# bambu_extract_d

Extracts the RSA private key (`d`) from Bambu Lab's `libbambu_networking.so`
plugin so that `print.*` MQTT commands can be signed natively, without the
proprietary plugin being present at print time.

## How it works

The tool launches a minimal daemon binary in a sandboxed environment, injects an
LD_PRELOAD shim to defeat the watchdog timer, and redirects the daemon's printer
connection to a local fake TLS MQTT broker. When the daemon's signing thread
fires, the tool captures the RSA CRT intermediate values (`d_p`, `d_q`) via a
hardware breakpoint (DR0), reconstructs the full private key offline, and writes
it as a PKCS#1 PEM file.

No real printer is required. No network traffic leaves the machine. Feel free to
run it in a VM or container, particularly if you're worried about what Bambu's
network plugin might be doing to your computer.

Only Linux is supported for extraction, but using the key works on Windows. This
is one slicer key across all instances of BambuStudio. The key is not
distributed here due to uncertainty about the legality of doing so.

Since this is an adversarial environment, only the extraction method is
documented (the cheat answer at the end), not the full mechanism for
determining it. No need to give Bambu a test case to code against.

## Output

Output goes into the directory given by `--out-dir` (default: current
directory). `--format` selects what is written (default: `pem`):

| Format | Files (in `--out-dir`) | Permissions |
|---|---|---|
| `pem` | `slicer_key.pem` (PKCS#1 RSA-2048 private key) | 0600 |
|       | `slicer_pubkey.pem` (RSA public key, SubjectPublicKeyInfo) | 0644 |
|       | `slicer_cert_id.txt` (certificate ID string) | 0644 |
| `json` | `d_extracted.json` (raw factors / d / N) | 0600 |

For use with the slicer, write the PEM directly into the config directory:
- Linux/macOS: `~/.config/BambuStudio/` → `slicer_key.pem`
- Windows: `%APPDATA%\BambuStudio\` → `slicer_key.pem`

Or set `BBL_SLICER_KEY_PEM` / `BBL_SLICER_CERT_ID` environment variables.

## Quick start

```bash
# Build and run via the wrapper (locates the plugin automatically, ~15s).
tools/bambu_extract_d/run.sh --out-dir ~/.config/BambuStudio

# If no plugin is installed locally, allow fetching it from Bambu's CDN:
tools/bambu_extract_d/run.sh --allow-download --out-dir ~/.config/BambuStudio
```

`run.sh` searches these locations for the official `libbambu_networking.so`
(Orca Slicer is not searched):

- `~/.config/BambuStudio/plugins/`
- `~/.var/app/com.bambulab.BambuStudio/config/BambuStudio/plugins/`
- `~/.config/BambuStudioBeta/plugins/`
- `~/.var/app/com.bambulab.BambuStudioBeta/config/BambuStudioBeta/plugins/`

You can also point the extractor at a specific plugin and skip discovery
(the binary itself never searches the system):

```bash
make -C tools/bambu_extract_d
tools/bambu_extract_d/bambu_extract_d \
    --plugin /path/to/libbambu_networking.so --out-dir .
```

The extractor rejects the open-source "Open Bamboo Networking" replacement
plugin (its version ends in `.99`): extraction requires the official Bambu
plugin.

## Build prerequisites

```bash
apt install build-essential libssl-dev zlib1g-dev
```

The three embed headers (`daemon_embed.h`, `watchdog_defeat_embed.h`,
`slicer_cert_embed.h`) must be generated from pre-compiled binaries before
building `bambu_extract_d`. See comments inside each header for details.

## Security note

`slicer_key.pem` is the slicer's actual RSA-2048 private key — treat it like a
`.p12` certificate. Do not share it, commit it to git, or store it with
world-readable permissions.
