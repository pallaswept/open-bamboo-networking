#pragma once
#include <string>
#include "bigint.h"
#include "reconstruct.h"

// ===========================================================================
// I/O helpers
// ===========================================================================
std::string slurp(const std::string& path);

// Write the recovered key material into out_dir using the requested format:
//   "pem"  -> slicer_key.pem (0600) + slicer_pubkey.pem + slicer_cert_id.txt
//   "json" -> d_extracted.json (0600)
// out_dir is created if missing. Returns false on any failure.
bool write_output(const std::string& out_dir, const std::string& format,
                  const DRecon& R, const bn::BigInt& N,
                  int env_pass, int env_total);
