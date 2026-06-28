// main.cpp — Self-contained RSA-d extractor for libbambu_networking
// Phase 0: if _SELF_PRELOADED not set, write watchdog shim to memfd and re-exec with LD_PRELOAD.

// ---- Embedded assets ----
#include "watchdog_defeat_embed.h"   // watchdog_defeat_embed_so[] + _len

// ---- Phase 0: self-re-exec bootstrap ----
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char** environ;

static void bootstrap_if_needed(int argc, char** argv) {
    (void)argc;
    if (getenv("_SELF_PRELOADED")) return;

    int fd = memfd_create("bambu_wd", 0);
    if (fd < 0) { perror("memfd_create"); _exit(1); }

    size_t total = 0;
    while (total < watchdog_defeat_embed_so_len) {
        ssize_t n = write(fd,
            (const char*)watchdog_defeat_embed_so + total,
            watchdog_defeat_embed_so_len - total);
        if (n <= 0) { perror("write shim"); _exit(1); }
        total += (size_t)n;
    }

    char preload_path[64];
    snprintf(preload_path, sizeof(preload_path), "/proc/self/fd/%d", fd);
    setenv("LD_PRELOAD", preload_path, 1);
    setenv("_SELF_PRELOADED", "1", 1);

    execve("/proc/self/exe", argv, environ);
    perror("execve"); _exit(1);
}

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "vendored/Sha256Portable.hpp"
#include "vendored/BigIntModExp.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Declaration headers (no definitions).
#include "logging.h"
#include "version.h"
#include "bigint.h"
#include "envelope.h"
#include "capture.h"
#include "reconstruct.h"
#include "output.h"
#include "daemon.h"

// ===========================================================================
// Logging globals (definitions; declared extern in logging.h)
// ===========================================================================
double g_t0 = 0;
bool g_verbose = false;

// ===========================================================================
// CLI parsing
// ===========================================================================
struct Args {
    std::string plugin_path;
    std::string cert_path;
    std::string envelopes_path;
    std::string modulus_n_hex;
    std::string dev_id;
    std::string access_code;
    std::string out_dir       = ".";
    std::string format        = "pem";
    bool verbose              = false;
    int timeout_s             = 120;
    bool  no_envelopes        = true;
};

static void usage_simple(const char* prog) {
    std::fprintf(stderr,
        "usage: %s --plugin PATH [options]\n"
        "\n"
        "Required:\n"
        "  --plugin PATH       Path to the official libbambu_networking.so\n"
        "\n"
        "Options:\n"
        "  --out-dir DIR       Output directory (default: current directory)\n"
        "  --format FMT        Output format: pem (default) or json\n"
        "  --cert PATH         slicer_base64.cer path (auto-detected if omitted)\n"
        "  --timeout N         Seconds before giving up (default: 120)\n"
        "  --envelopes PATH    envelopes.json for validation (optional)\n"
        "  --out PATH          Deprecated: sets --out-dir/--format from PATH\n"
        "  --verbose           Log every HW BP trap\n"
        "  --help              Show this message\n"
        "\n"
        "Tip: run.sh locates the plugin automatically (and can download it with\n"
        "     --allow-download), then invokes this tool with --plugin.\n"
        "\n"
        "Example:\n"
        "  %s --plugin ~/.config/BambuStudio/plugins/libbambu_networking.so\n"
        "  %s --plugin ./libbambu_networking.so --out-dir ~/.config/BambuStudio --format pem\n",
        prog, prog, prog);
}

// True if `s` ends with `suffix`.
static bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// dlopen the plugin in a short-lived, timeout-guarded child process and read
// bambu_network_get_version(). Isolated in a child so the plugin's anti-debug
// / startup behaviour can't disturb the main process. Returns the version
// string, or empty if it could not be determined within `timeout_s`.
static std::string read_plugin_version(const std::string& plugin_path, int timeout_s) {
    int pfd[2];
    if (pipe(pfd) != 0) return {};

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return {}; }

    if (pid == 0) {
        close(pfd[0]);
        alarm((unsigned)(timeout_s > 0 ? timeout_s : 5));
        void* h = dlopen(plugin_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (h) {
            using fn_ver = std::string (*)();
            auto ver = reinterpret_cast<fn_ver>(dlsym(h, "bambu_network_get_version"));
            if (ver) {
                std::string v = ver();
                ssize_t wr = write(pfd[1], v.data(), v.size());
                (void)wr;
            }
        }
        close(pfd[1]);
        _exit(0);
    }

    close(pfd[1]);
    std::string out;
    struct pollfd pf = { pfd[0], POLLIN, 0 };
    double deadline = now_s() + (timeout_s > 0 ? timeout_s : 5);
    for (;;) {
        double remain = deadline - now_s();
        if (remain <= 0) break;
        int pr = poll(&pf, 1, (int)(remain * 1000));
        if (pr <= 0) break;
        char buf[256];
        ssize_t n = read(pfd[0], buf, sizeof(buf));
        if (n > 0) { out.append(buf, (size_t)n); continue; }
        break;  // EOF or error
    }
    close(pfd[0]);
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);

    while (!out.empty() &&
           (out.back() == '\n' || out.back() == '\r' ||
            out.back() == ' '  || out.back() == '\0')) {
        out.pop_back();
    }
    return out;
}

static void dump_daemon_log_tail(const std::string& daemon_log) {
    LOG_I("daemon log tail:");
    FILE* f = fopen(daemon_log.c_str(), "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    long off = std::max(0L, sz - 4096L);
    fseek(f, off, SEEK_SET);
    char buf[4097];
    size_t n = fread(buf, 1, 4096, f);
    buf[n] = 0;
    fclose(f);
    std::fprintf(stderr, "%s\n", buf);
}

// Global daemon PID for signal handler cleanup.
static int g_cleanup_pipe[2] = {-1, -1};
static pid_t g_daemon_pid_atomic = 0;

static void cleanup_signal_handler(int /*sig*/) {
    pid_t dpid = g_daemon_pid_atomic;
    if (dpid > 0) {
        kill(dpid, SIGKILL);
        kill(-dpid, SIGKILL);
    }
    _exit(1);
}

int main(int argc, char** argv) {
    // Phase 0: re-exec with LD_PRELOAD shim if not already done.
    bootstrap_if_needed(argc, argv);

    // Phase 1 from here.
    g_t0 = now_s();

    // Install signal handler to clean up on SIGTERM/SIGINT.
    {
        struct sigaction sa{};
        sa.sa_handler = cleanup_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT,  &sa, nullptr);
    }

    prctl(PR_SET_NAME, "bambustu_main", 0, 0, 0);

    {
        struct rlimit rl{0, 0};
        setrlimit(RLIMIT_CORE, &rl);
    }

    // ---- Parse simplified CLI ----
    Args args;

    bool show_help = false;
    bool bad_args  = false;

    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need = [&](std::string& slot) -> bool {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", s.c_str());
                return false;
            }
            slot = argv[++i];
            return true;
        };
        if      (s == "--plugin")      { if (!need(args.plugin_path)) return 2; }
        else if (s == "--cert")        { if (!need(args.cert_path)) return 2; }
        else if (s == "--out-dir")     { if (!need(args.out_dir)) return 2; }
        else if (s == "--format")      {
            std::string f; if (!need(f)) return 2;
            if (f != "pem" && f != "json") {
                std::fprintf(stderr, "invalid --format '%s' (expected pem or json)\n", f.c_str());
                return 2;
            }
            args.format = f;
        }
        else if (s == "--out")         {
            // Deprecated: derive output directory and format from the path.
            std::string p; if (!need(p)) return 2;
            auto sl = p.rfind('/');
            args.out_dir = (sl == std::string::npos) ? std::string(".")
                         : (sl == 0 ? std::string("/") : p.substr(0, sl));
            args.format  = ends_with(p, ".json") ? "json" : "pem";
            std::fprintf(stderr,
                "warning: --out is deprecated; use --out-dir and --format "
                "(interpreting as --out-dir %s --format %s)\n",
                args.out_dir.c_str(), args.format.c_str());
        }
        else if (s == "--envelopes")   {
            if (!need(args.envelopes_path)) return 2;
            args.no_envelopes = false;
        }
        else if (s == "--timeout")     {
            std::string t; if (!need(t)) return 2;
            int v = std::atoi(t.c_str());
            if (v <= 0) {
                std::fprintf(stderr, "invalid --timeout '%s' (expected positive integer)\n", t.c_str());
                return 2;
            }
            args.timeout_s = v;
        }
        else if (s == "--verbose")     { args.verbose = true; }
        else if (s == "--help" || s == "-h") { show_help = true; }
        else {
            std::fprintf(stderr, "unknown argument: %s\n", s.c_str());
            bad_args = true;
        }
    }

    // Synthetic identifiers — no real printer required.
    args.dev_id      = "01S00A2B3C4D5E6";
    args.access_code = "offline";
    std::string lan_ip = "127.0.0.1";

    if (show_help) {
        usage_simple(argv[0]);
        return 0;
    }
    if (bad_args) {
        usage_simple(argv[0]);
        return 2;
    }

    g_verbose = args.verbose;

    // The binary no longer searches for or downloads the plugin — run.sh
    // handles discovery and (opt-in) download, then passes --plugin here.
    if (args.plugin_path.empty()) {
        LOG_E("--plugin is required. Run via run.sh (it locates/downloads the "
              "plugin) or pass --plugin /path/to/libbambu_networking.so");
        return 2;
    }
    {
        struct stat pst{};
        if (stat(args.plugin_path.c_str(), &pst) != 0) {
            LOG_E("--plugin: %s: %s", args.plugin_path.c_str(), strerror(errno));
            return 2;
        }
    }
    g_plugin_path_for_home = args.plugin_path;

    // ---- Reject the Open Bamboo Networking replacement plugin ----
    // It installs as the same libbambu_networking.so in the same locations,
    // reports a version ending in ".99", and cannot be used to extract the
    // slicer key. Detect it via a guarded dlopen of get_version().
    {
        std::string pv = read_plugin_version(args.plugin_path, 5);
        if (!pv.empty()) {
            LOG_I("plugin reports version: %s", pv.c_str());
            if (ends_with(pv, ".99")) {
                LOG_E("Похоже, что вместо официального плагина установлен плагин "
                      "\"Open Bamboo Networking\".");
                LOG_E("Для извлечения ключа нужен официальный плагин bambu_networking "
                      "— установите его сначала (или укажите путь через --plugin).");
                return 2;
            }
        } else {
            LOG_W("could not determine plugin version (skipping .99 check)");
        }
    }

    // ---- Identify plugin version from file size ----
    const VersionProfile* ver = identify_version(args.plugin_path);
    double warmup_s = 4.0;
    if (ver) {
        warmup_s = ver->warmup_s;
    }

    LOG_I("bambu_extract_d");
    LOG_I("mode      : no-printer");
    LOG_I("plugin    : %s", args.plugin_path.c_str());
    LOG_I("out-dir   : %s", args.out_dir.c_str());
    LOG_I("format    : %s", args.format.c_str());
    LOG_I("timeout   : %ds", args.timeout_s);
    if (ver) {
        LOG_I("version   : %s (size=%lu)", ver->tag, (unsigned long)ver->so_size);
    } else {
        struct stat vst{};
        stat(args.plugin_path.c_str(), &vst);
        LOG_W("version   : UNKNOWN (size=%lu) — using default profile", (unsigned long)(uint64_t)vst.st_size);
    }

    // ---- Locate slicer cert and copy to tmpdir ----
    std::string cert_dir = write_cert_tmpdir(getpid(), args.plugin_path, args.cert_path);
    if (cert_dir.empty()) {
        LOG_E("failed to locate slicer cert — see above for details");
        return 3;
    }
    LOG_I("cert dir  : %s", cert_dir.c_str());

    // ---- Parse modulus N ----
    bn::BigInt N;
    {
        std::string nhex = args.modulus_n_hex.empty()
            ? std::string(version_02_05_03_63::N_HEX_DEFAULT)
            : args.modulus_n_hex;
        N = bn::from_hex(nhex);
        if (N.is_zero() || N.bit_length() < 2000) {
            LOG_E("modulus N parse failed (bits=%d)", N.bit_length());
            return 3;
        }
        LOG_I("N bits=%d", N.bit_length());
    }

    // ---- Load envelopes if given ----
    std::vector<Envelope> envs;
    if (!args.no_envelopes) {
        std::string body = slurp(args.envelopes_path);
        if (body.empty()) {
            LOG_E("envelopes file empty/missing: %s", args.envelopes_path.c_str());
            return 3;
        }
        if (!mini_json::parse_envelopes(body, envs)) {
            LOG_E("could not parse envelopes JSON");
            return 3;
        }
        LOG_I("envelopes: %zu", envs.size());
    } else {
        LOG_I("envelopes: none (validation skipped)");
    }

    // ---- Write daemon binary to memfd ----
    std::string daemon_exe = write_daemon_memfd();
    if (daemon_exe.empty()) {
        LOG_E("failed to write daemon binary to memfd");
        return 4;
    }
    LOG_I("daemon exe: %s", daemon_exe.c_str());

    // ---- Set up H2S home directory ----
    std::string h2s_home = setup_h2s_home(args.dev_id);
    if (h2s_home.empty()) {
        LOG_E("failed to set up H2S home directory");
        return 4;
    }

    // ---- Launch daemon ----
    double daemon_start_ts = now_s();
    std::string daemon_log = cert_dir + "/daemon.log";
    pid_t daemon_pid = launch_daemon(daemon_exe, h2s_home, args.plugin_path,
                                     args.dev_id, args.access_code, lan_ip,
                                     cert_dir, daemon_log);
    if (daemon_pid < 0) {
        LOG_E("failed to launch daemon");
        return 4;
    }
    g_daemon_pid_atomic = daemon_pid;
    LOG_I("daemon launched: PID %d", (int)daemon_pid);
    LOG_I("daemon log: %s", daemon_log.c_str());

    // ---- Read seccomp notif_fd from daemon constructor ----
    if (g_openat_notif_pipe_rd >= 0) {
        struct pollfd pf = { g_openat_notif_pipe_rd, POLLIN, 0 };
#ifdef USE_SECCOMP_UNOTIFY
        int pr = poll(&pf, 1, 3000);
#else
        int pr = poll(&pf, 1, 0);
#endif
        if (pr > 0 && (pf.revents & POLLIN)) {
            int daemon_notif_fd = -1;
            ssize_t nr = read(g_openat_notif_pipe_rd, &daemon_notif_fd, sizeof(int));
            if (nr == sizeof(int) && daemon_notif_fd >= 0) {
                LOG_I("openat: daemon notif_fd=%d (in daemon pid=%d)", daemon_notif_fd, daemon_pid);
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
                long pidfd = syscall(SYS_pidfd_open, (pid_t)daemon_pid, 0);
                if (pidfd < 0) {
                    LOG_W("pidfd_open(daemon=%d) failed: %s — openat supervisor disabled",
                          daemon_pid, strerror(errno));
                } else {
                    long local_fd = syscall(SYS_pidfd_getfd, (int)pidfd, daemon_notif_fd, 0);
                    close((int)pidfd);
                    if (local_fd < 0) {
                        LOG_W("pidfd_getfd(notif_fd=%d) failed: %s — openat supervisor disabled",
                              daemon_notif_fd, strerror(errno));
                    } else {
                        g_openat_notif_fd = (int)local_fd;
                        LOG_I("openat notif_fd=%d stolen via pidfd_getfd (daemon fd was %d)",
                              (int)local_fd, daemon_notif_fd);
                    }
                }
            } else {
                LOG_W("notif pipe read failed nr=%zd daemon_notif_fd=%d", nr, daemon_notif_fd);
            }
        } else if (pr == 0) {
            LOG_W("notif pipe timeout — openat supervisor disabled");
        } else {
            LOG_W("notif pipe poll failed: %s — openat supervisor disabled", strerror(errno));
        }
        close(g_openat_notif_pipe_rd);
        g_openat_notif_pipe_rd = -1;
    }

    // ---- Start openat supervisor thread ----
    if (g_openat_notif_fd >= 0) {
        LOG_I("starting openat supervisor thread (notif_fd=%d)", g_openat_notif_fd);
        g_notif_stop_flag.store(false, std::memory_order_relaxed);
        int nfd = g_openat_notif_fd;
        g_notif_thread = std::thread([nfd]() {
            openat_supervisor_thread(nfd, &g_notif_stop_flag);
        });
    } else {
        LOG_I("openat supervisor not started (no notif_fd)");
    }

    // ---- Wait for plugin to be loaded ----
    LOG_I("waiting for libbambu_networking to map (max 90s)...");
    pid_t target_pid = wait_for_libbambu(daemon_pid, args.plugin_path, 90);
    if (target_pid == 0) {
        LOG_E("libbambu_networking never mapped in daemon — bailing");
        dump_daemon_log_tail(daemon_log);
        kill(daemon_pid, SIGKILL);
        waitpid(daemon_pid, nullptr, 0);
        return 5;
    }
    LOG_I("libbambu mapped in PID %d", (int)target_pid);

    // ---- VMP warm-up ----
    {
        const char* env_delay = std::getenv("BBL_SEIZE_DELAY");
        if (env_delay) {
            double extra_delay = std::atof(env_delay);
            if (extra_delay > 0) {
                LOG_I("BBL_SEIZE_DELAY=%.1fs: letting VMP run untraced (self-test window)...", extra_delay);
                double deadline = now_s() + extra_delay;
                while (now_s() < deadline) {
                    usleep(500 * 1000);
                    if (kill(daemon_pid, 0) != 0) {
                        LOG_E("daemon died during seize delay");
                        return 7;
                    }
                }
                LOG_I("BBL_SEIZE_DELAY elapsed — attaching now");
            }
        } else {
            double elapsed = now_s() - daemon_start_ts;
            if (elapsed < warmup_s) {
                double wait_s = warmup_s - elapsed;
                LOG_I("VMP warm-up: waiting %.1fs (until %.0fs from daemon start)", wait_s, warmup_s);
                while (wait_s > 0.0) {
                    double slice = std::min(wait_s, 2.0);
                    usleep((useconds_t)(slice * 1e6));
                    wait_s -= slice;
                    if (kill(daemon_pid, 0) != 0) {
                        LOG_E("daemon died during warm-up wait");
                        return 7;
                    }
                }
                LOG_I("VMP warm-up complete");
            }
        }
    }

    // ---- Arm DR0 and capture ----
    LOG_I("attaching to PID %d for d-capture (timeout=%ds)...",
          (int)target_pid, args.timeout_s);

    bool require_bytes = true;
    CaptureResult cap = drive_capture_attach(target_pid, args.plugin_path,
                                             args.timeout_s, require_bytes, ver);

    // Shut down daemon.
    LOG_I("shutting down daemon...");
    kill(daemon_pid, SIGTERM);
    {
        int st = 0;
        for (int i = 0; i < 20; ++i) {
            pid_t r = waitpid(daemon_pid, &st, WNOHANG);
            if (r == daemon_pid || r < 0) break;
            usleep(100 * 1000);
        }
        kill(daemon_pid, SIGKILL);
        waitpid(daemon_pid, nullptr, 0);
    }

    if (!cap.ok) {
        LOG_E("capture failed: only %zu bytes (need %d)",
              cap.stream.size(), version_02_05_03_63::TOTAL_BYTES);
        if (cap.total_traps > 0)
            LOG_W("trap count = %d (expected multiples of 256)", cap.total_traps);
        dump_daemon_log_tail(daemon_log);
        LOG_E("FAILED — capture incomplete");
        return 5;
    }
    LOG_I("byte stream complete (%zu bytes), traps=%d sign_cycles=%d",
          cap.stream.size(), cap.total_traps, cap.sign_cycles);

    // ---- Reconstruct ----
    int min_matches = args.no_envelopes ? 0 : 3;
    std::vector<Envelope> head_envs;
    if (!args.no_envelopes) {
        size_t head_n = std::min<size_t>(envs.size(), 10);
        head_envs.assign(envs.begin(), envs.begin() + head_n);
    }

    DRecon R = reconstruct(cap.stream, N, version_02_05_03_63::E_PUB,
                           version_02_05_03_63::MAX_K, head_envs, min_matches);
    if (!R.ok) {
        LOG_E("reconstruction failed (factor recovery produced no valid mode)");
        std::string hex;
        char buf[3];
        for (size_t i = 0; i < std::min<size_t>(64, cap.stream.size()); ++i) {
            snprintf(buf, 3, "%02x", cap.stream[i]);
            hex += buf;
        }
        LOG_W("stream[0..63]: %s", hex.c_str());
        return 6;
    }
    LOG_I("factor recovery: k=%d mode=%s", R.k_found, R.mode.c_str());

    // ---- Envelope validation ----
    int env_pass = 0;
    if (!args.no_envelopes) {
        env_pass = validate_envelopes(R.d, N, envs);
        LOG_I("envelope validation: %d/%zu", env_pass, envs.size());
        if (env_pass < min_matches) {
            LOG_E("only %d envelopes matched (need >= %d)", env_pass, min_matches);
            return 7;
        }
    } else {
        LOG_I("envelope validation: skipped");
    }

    // ---- Print d to stdout ----
    std::string d_hex = bn::to_hex_str(R.d, false);
    std::printf("d=%s\n", d_hex.c_str());
    std::fflush(stdout);

    // ---- Write output ----
    if (!write_output(args.out_dir, args.format, R, N, env_pass, (int)envs.size())) {
        return 8;
    }
    LOG_I("output written to %s (format=%s)", args.out_dir.c_str(), args.format.c_str());

    // Dump daemon log for diagnostics.
    dump_daemon_log_tail(daemon_log);

    // Cleanup.
    {
        char cert_path[300];
        snprintf(cert_path, sizeof(cert_path), "%s/slicer_base64.cer", cert_dir.c_str());
        unlink(cert_path);
        char dlog_path[300];
        snprintf(dlog_path, sizeof(dlog_path), "%s/daemon.log", cert_dir.c_str());
        unlink(dlog_path);
        rmdir(cert_dir.c_str());
    }

    (void)g_cleanup_pipe;  // suppress unused warning

    LOG_I("SUCCESS — wall time: %.2f s", now_s() - g_t0);
    return 0;
}
