#!/bin/bash
# Build bambu_extract_d, locate the official Bambu network plugin, and run the
# extractor against it.
#
# Plugin discovery (in order):
#   ~/.cache/bambu_extract_d/plugins/<version>/libbambu_networking.so  (downloaded)
#   ~/.config/BambuStudio/plugins/
#   ~/.var/app/com.bambulab.BambuStudio/config/BambuStudio/plugins/
#   ~/.config/BambuStudioBeta/plugins/
#   ~/.var/app/com.bambulab.BambuStudioBeta/config/BambuStudioBeta/plugins/
#
# If no local plugin is found and --allow-download is given, the official
# plugin is fetched from Bambu's CDN (see the legal note printed at that point).
set -e
cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this tool only runs on Linux" >&2
    exit 1
fi

# ABI prefix used for the download query (MM.mm.pp). The slicer key is the same
# across all plugin versions, so any supported version works. Override with the
# OBN_PLUGIN_ABI env var or --abi.
PLUGIN_ABI="${OBN_PLUGIN_ABI:-02.07.01}"
CACHE_ROOT="${HOME}/.cache/bambu_extract_d/plugins"
SO_NAME="libbambu_networking.so"

# ---- Parse run.sh-only flags; forward the rest to the binary --------------
ALLOW_DOWNLOAD=0
USER_PLUGIN=""
FWD_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-download) ALLOW_DOWNLOAD=1; shift ;;
        --abi)            PLUGIN_ABI="$2"; shift 2 ;;
        --plugin)         USER_PLUGIN="$2"; FWD_ARGS+=("$1" "$2"); shift 2 ;;
        *)                FWD_ARGS+=("$1"); shift ;;
    esac
done

# ---- Install build and runtime dependencies -------------------------------
if command -v apt-get >/dev/null 2>&1; then
    SUDO=""
    [[ $EUID -ne 0 ]] && SUDO="sudo"
    $SUDO apt-get install -y \
        build-essential cmake ninja-build xxd curl unzip \
        libssl-dev libcurl4-openssl-dev zlib1g-dev
else
    echo "warning: apt-get not found — ensure these are installed:" >&2
    echo "  build-essential cmake ninja-build xxd curl unzip" >&2
    echo "  libssl-dev libcurl4-openssl-dev zlib1g-dev" >&2
fi

make -j"$(nproc)"

# ---- Locate the plugin -----------------------------------------------------
find_plugin() {
    # Previously downloaded copies in the cache.
    local cached
    cached=$(ls -1 "${CACHE_ROOT}"/*/"${SO_NAME}" 2>/dev/null | head -1 || true)
    if [[ -n "$cached" ]]; then echo "$cached"; return 0; fi

    local dirs=(
        "${HOME}/.config/BambuStudio/plugins"
        "${HOME}/.var/app/com.bambulab.BambuStudio/config/BambuStudio/plugins"
        "${HOME}/.config/BambuStudioBeta/plugins"
        "${HOME}/.var/app/com.bambulab.BambuStudioBeta/config/BambuStudioBeta/plugins"
    )
    local d
    for d in "${dirs[@]}"; do
        if [[ -f "${d}/${SO_NAME}" ]]; then echo "${d}/${SO_NAME}"; return 0; fi
    done
    return 1
}

# Fetch the official plugin from Bambu's CDN into the cache. Echoes the path.
download_plugin() {
    cat >&2 <<'EOF'

================================ legal note =================================
About to download Bambu Lab's proprietary "bambu_networking" plugin from
Bambu's public CDN. This is third-party, closed-source software; you are
responsible for ensuring you are allowed to download and use it in your
jurisdiction. No extracted key material is distributed by this project.
============================================================================

EOF
    local api="https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=${PLUGIN_ABI}.00"
    local tmp_manifest tmp_zip url version dest_dir
    tmp_manifest="$(mktemp /tmp/bambu_manifest.XXXXXX.json)"
    tmp_zip="$(mktemp /tmp/bambu_plugin.XXXXXX.zip)"

    echo "[plugin-dl] fetching manifest for ABI ${PLUGIN_ABI} ..." >&2
    if ! curl --silent --location --max-time 60 \
            -H "X-BBL-OS-Type: linux" \
            -H "X-BBL-Client-Type: slicer" \
            -H "X-BBL-Client-Name: OpenBambooNetworking" \
            -o "$tmp_manifest" "$api"; then
        echo "[plugin-dl] manifest download failed" >&2
        rm -f "$tmp_manifest" "$tmp_zip"; return 1
    fi

    url=$(grep -oE '"url"[[:space:]]*:[[:space:]]*"[^"]+"' "$tmp_manifest" \
          | head -1 | sed -E 's/.*"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    version=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$tmp_manifest" \
          | head -1 | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/')
    [[ -z "$version" ]] && version="${PLUGIN_ABI}.00"
    if [[ -z "$url" ]]; then
        echo "[plugin-dl] no plugin url in manifest (ABI ${PLUGIN_ABI} not available?)" >&2
        rm -f "$tmp_manifest" "$tmp_zip"; return 1
    fi

    dest_dir="${CACHE_ROOT}/${version}"
    mkdir -p "$dest_dir"

    echo "[plugin-dl] downloading ${url}" >&2
    if ! curl --silent --location --max-time 180 \
            -H "X-BBL-OS-Type: linux" \
            -o "$tmp_zip" "$url"; then
        echo "[plugin-dl] plugin zip download failed" >&2
        rm -f "$tmp_manifest" "$tmp_zip"; return 1
    fi

    if ! unzip -j -o "$tmp_zip" "*${SO_NAME}" -d "$dest_dir" >/dev/null 2>&1; then
        echo "[plugin-dl] unzip failed (no ${SO_NAME} inside archive?)" >&2
        rm -f "$tmp_manifest" "$tmp_zip"; return 1
    fi
    rm -f "$tmp_manifest" "$tmp_zip"

    if [[ ! -f "${dest_dir}/${SO_NAME}" ]]; then
        echo "[plugin-dl] extracted ${SO_NAME} not found" >&2
        return 1
    fi
    chmod 0600 "${dest_dir}/${SO_NAME}" || true
    echo "[plugin-dl] cached: ${dest_dir}/${SO_NAME}" >&2
    echo "${dest_dir}/${SO_NAME}"
}

PLUGIN_PATH="$USER_PLUGIN"
if [[ -z "$PLUGIN_PATH" ]]; then
    if PLUGIN_PATH=$(find_plugin); then
        echo "found plugin: ${PLUGIN_PATH}"
    elif [[ "$ALLOW_DOWNLOAD" -eq 1 ]]; then
        PLUGIN_PATH=$(download_plugin) || {
            echo "error: plugin download failed" >&2; exit 1; }
    else
        cat >&2 <<EOF
error: official bambu_networking plugin not found in any known location:
  ~/.config/BambuStudio/plugins/
  ~/.var/app/com.bambulab.BambuStudio/config/BambuStudio/plugins/
  ~/.config/BambuStudioBeta/plugins/
  ~/.var/app/com.bambulab.BambuStudioBeta/config/BambuStudioBeta/plugins/

Install Bambu Studio (so it downloads the plugin), pass --plugin /path/to/${SO_NAME},
or re-run with --allow-download to fetch it from Bambu's CDN.
EOF
        exit 1
    fi
fi

echo ""
# If the user already passed --plugin, it is in FWD_ARGS; otherwise add ours.
if [[ -z "$USER_PLUGIN" ]]; then
    exec ./bambu_extract_d --plugin "$PLUGIN_PATH" "${FWD_ARGS[@]}"
else
    exec ./bambu_extract_d "${FWD_ARGS[@]}"
fi
