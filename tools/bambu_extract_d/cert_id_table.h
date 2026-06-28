#pragma once
// Known key→cert_id lookup table.
// Key: MD5 hex of private key in DER encoding.
// Value: cert_id string as used in the signed MQTT envelope header.
//
// To add a new entry:
//   openssl pkey -in slicer_key.pem -outform DER | md5sum
// Then pair it with the cert_id captured from a real signed MQTT message.

struct CertIdEntry {
    const char* key_md5;
    const char* cert_id;
};

static const CertIdEntry kCertIdTable[] = {
    {"53fcd26903b891cb73d347abc5a5ca03",
     "a4e8faaa1a38e3650a0ea590d192383fCN=GLOF3813734089.bambulab.com"},
};
