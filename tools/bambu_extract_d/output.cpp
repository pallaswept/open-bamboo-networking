#include "output.h"
#include "logging.h"
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>

std::string slurp(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

namespace {

BIGNUM* bn_from_bigint(const bn::BigInt& x) {
    BIGNUM* b = nullptr;
    std::string h = bn::to_hex_str(x, false);
    BN_hex2bn(&b, h.c_str());
    return b;
}

// Build an RSA private key (with CRT parameters) as an EVP_PKEY from the
// recovered factors. Uses the OpenSSL 3.0 provider API so nothing is
// deprecated. Returns nullptr on failure.
EVP_PKEY* build_rsa_pkey(const DRecon& R, const bn::BigInt& N) {
    BIGNUM* n   = bn_from_bigint(N);
    BIGNUM* e   = BN_new();
    BIGNUM* d   = bn_from_bigint(R.d);
    BIGNUM* p   = bn_from_bigint(R.p);
    BIGNUM* q   = bn_from_bigint(R.q);
    BIGNUM* dp  = bn_from_bigint(R.dp);
    BIGNUM* dq  = bn_from_bigint(R.dq);
    BIGNUM* qi  = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM*     params = nullptr;
    EVP_PKEY_CTX*   pctx   = nullptr;
    EVP_PKEY*       pkey   = nullptr;

    if (!n || !e || !d || !p || !q || !dp || !dq || !qi || !ctx || !bld) {
        LOG_E("OpenSSL allocation failed");
        goto cleanup;
    }
    if (!BN_set_word(e, 65537)) {
        LOG_E("BN_set_word(e) failed");
        goto cleanup;
    }
    // iqmp = q^-1 mod p (CRT coefficient).
    if (!BN_mod_inverse(qi, q, p, ctx)) {
        LOG_E("BN_mod_inverse failed");
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi)) {
        LOG_E("OSSL_PARAM_BLD_push_BN failed");
        goto cleanup;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        LOG_E("OSSL_PARAM_BLD_to_param failed");
        goto cleanup;
    }
    pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!pctx || EVP_PKEY_fromdata_init(pctx) <= 0) {
        LOG_E("EVP_PKEY_fromdata_init failed");
        goto cleanup;
    }
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        LOG_E("EVP_PKEY_fromdata failed");
        pkey = nullptr;
    }

cleanup:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(pctx);
    BN_CTX_free(ctx);
    // These hold private key material — clear before freeing.
    BN_clear_free(n);  BN_clear_free(e);  BN_clear_free(d);
    BN_clear_free(p);  BN_clear_free(q);  BN_clear_free(dp);
    BN_clear_free(dq); BN_clear_free(qi);
    return pkey;
}

bool encode_pkey_pem(EVP_PKEY* pkey, const std::string& path,
                     int selection, const char* structure, mode_t mode) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        return false;
    }
    BIO* bio = BIO_new_fd(fd, BIO_CLOSE);
    if (!bio) {
        close(fd);
        LOG_E("BIO_new_fd(%s) failed", path.c_str());
        return false;
    }
    OSSL_ENCODER_CTX* ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", structure, nullptr);
    bool ok = ectx && OSSL_ENCODER_to_bio(ectx, bio);
    if (!ok) LOG_E("OSSL_ENCODER_to_bio(%s) failed", path.c_str());
    OSSL_ENCODER_CTX_free(ectx);
    BIO_free(bio);  // closes fd
    return ok;
}

bool write_cert_id(const std::string& path) {
    // NOTE: this is a fixed fallback cert-id string and may not match the
    // certificate the recovered key was actually issued under. It is kept
    // for backward compatibility with downstream tooling that expects the
    // file to exist; treat it as a placeholder.
    static const char kFallbackCertId[] =
        "a4e8faaa1a38e3650a0ea590d192383f"
        "CN=GLOF3813734089.bambulab.com";
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG_W("could not write slicer_cert_id.txt: %s", strerror(errno));
        return false;
    }
    std::string line = std::string(kFallbackCertId) + "\n";
    bool ok = write(fd, line.data(), line.size()) == (ssize_t)line.size();
    close(fd);
    if (ok) LOG_I("slicer_cert_id.txt written: %s", path.c_str());
    else    LOG_W("short write to slicer_cert_id.txt");
    return ok;
}

bool write_pem_output(const std::string& out_dir,
                      const DRecon& R, const bn::BigInt& N) {
    EVP_PKEY* pkey = build_rsa_pkey(R, N);
    if (!pkey) return false;

    std::string key_path    = out_dir + "/slicer_key.pem";
    std::string pubkey_path = out_dir + "/slicer_pubkey.pem";
    std::string cert_id_path = out_dir + "/slicer_cert_id.txt";

    bool ok = encode_pkey_pem(pkey, key_path, EVP_PKEY_KEYPAIR,
                              "type-specific", 0600);
    if (ok) LOG_I("slicer_key.pem written: %s", key_path.c_str());

    if (ok && !encode_pkey_pem(pkey, pubkey_path, EVP_PKEY_PUBLIC_KEY,
                               "SubjectPublicKeyInfo", 0644)) {
        LOG_W("could not write slicer_pubkey.pem");
    } else if (ok) {
        LOG_I("slicer_pubkey.pem written: %s", pubkey_path.c_str());
    }

    if (ok) write_cert_id(cert_id_path);

    EVP_PKEY_free(pkey);
    return ok;
}

bool write_json_output(const std::string& path,
                       const DRecon& R, const bn::BigInt& N,
                       int env_pass, int env_total) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_E("open(%s): %s", path.c_str(), strerror(errno));
        return false;
    }
    std::string body;
    body += "{\n";
    body += "  \"p_hex\":  \"" + bn::to_hex_str(R.p)  + "\",\n";
    body += "  \"q_hex\":  \"" + bn::to_hex_str(R.q)  + "\",\n";
    body += "  \"dp_hex\": \"" + bn::to_hex_str(R.dp) + "\",\n";
    body += "  \"dq_hex\": \"" + bn::to_hex_str(R.dq) + "\",\n";
    body += "  \"d_hex\":  \"" + bn::to_hex_str(R.d)  + "\",\n";
    body += "  \"N_hex\":  \"" + bn::to_hex_str(N)    + "\",\n";
    body += "  \"E\": 65537,\n";
    body += "  \"mode\": \"" + R.mode + "\",\n";
    body += "  \"k_factor\": " + std::to_string(R.k_found) + ",\n";
    body += "  \"envelope_pass_count\": " + std::to_string(env_pass) + ",\n";
    body += "  \"envelope_total\": " + std::to_string(env_total) + ",\n";
    body += "  \"_security\": \"SECRET: slicer RSA-2048 d. Mode 0600.\"\n";
    body += "}\n";
    ssize_t w = write(fd, body.data(), body.size());
    close(fd);
    if (w != (ssize_t)body.size()) {
        LOG_E("short write to %s", path.c_str());
        return false;
    }
    return true;
}

}  // namespace

bool write_output(const std::string& out_dir, const std::string& format,
                  const DRecon& R, const bn::BigInt& N,
                  int env_pass, int env_total) {
    if (mkdir(out_dir.c_str(), 0700) < 0 && errno != EEXIST) {
        LOG_E("mkdir(%s): %s", out_dir.c_str(), strerror(errno));
        return false;
    }

    if (format == "json")
        return write_json_output(out_dir + "/d_extracted.json", R, N,
                                 env_pass, env_total);

    return write_pem_output(out_dir, R, N);
}
