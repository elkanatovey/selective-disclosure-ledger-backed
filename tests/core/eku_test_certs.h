// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

// TEST-ONLY key material, freshly generated for this repository and used
// nowhere else. It exists because the CCF certificate helpers cannot add an
// Extended Key Usage extension, and the SCITT X.509 profile pins
// id-kp-codeSigning (1.3.6.1.5.5.7.3.3) through its did:x509 EKU policy: this
// chain is what lets the positive EKU path be tested. The certificates are
// P-256 and valid for 100 years from generation, so the tests do not need to
// disable certificate-time checks.
//
// Regenerate with:
//   openssl ecparam -name prime256v1 -genkey -noout -out root.key
//   openssl req -x509 -new -key root.key -sha256 -days 36500 \
//     -subj "/CN=SCITT Selective Disclosure Test Root CA" \
//     -addext "basicConstraints=critical,CA:TRUE" \
//     -addext "keyUsage=critical,keyCertSign,cRLSign" -out root.pem
//   openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
//   openssl req -new -key leaf.key -out leaf.csr \
//     -subj "/CN=SCITT Selective Disclosure Test Issuer"
//   openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key \
//     -CAcreateserial -days 36500 -sha256 -extfile leaf.ext -out leaf.pem
//   openssl pkcs8 -topk8 -nocrypt -in leaf.key -out leaf.pk8.pem
// with leaf.ext containing:
//   basicConstraints=critical,CA:FALSE
//   keyUsage=critical,digitalSignature
//   extendedKeyUsage=codeSigning
//   subjectKeyIdentifier=hash
//   authorityKeyIdentifier=keyid

namespace scitt_sd::testing
{
  // Self-signed root CA, the separately trusted anchor in the EKU tests.
  inline constexpr const char* EKU_ROOT_CA_PEM =
    R"pem(-----BEGIN CERTIFICATE-----
MIIByzCCAXGgAwIBAgIUW57O3bAVzAKvMabdZUd8qGQf1o4wCgYIKoZIzj0EAwIw
MjEwMC4GA1UEAwwnU0NJVFQgU2VsZWN0aXZlIERpc2Nsb3N1cmUgVGVzdCBSb290
IENBMCAXDTI2MDgxNzE5MTYzMVoYDzIxMjYwNzI0MTkxNjMxWjAyMTAwLgYDVQQD
DCdTQ0lUVCBTZWxlY3RpdmUgRGlzY2xvc3VyZSBUZXN0IFJvb3QgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQZ/yta+4xDNCHrFih6FSvDb1kbSNtTz25Z3dhf
M+ZgQPoPksfX8UyQScjFM4Wp3eh6ghCPeJ2iZXZ5ovCXEAFlo2MwYTAdBgNVHQ4E
FgQUsATead8MCzpnmuF+sEf3uyrkxk0wHwYDVR0jBBgwFoAUsATead8MCzpnmuF+
sEf3uyrkxk0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI
zj0EAwIDSAAwRQIgLAcusYwk5mh67wRvQLlws2POnWIreEwArpiQmxrCorICIQC7
7fhXIl9+Q/EctXOLgpktX+q9GvW1O3++zkTf1tsV1A==
-----END CERTIFICATE-----
)pem";

  // Leaf endorsed by that root, carrying extendedKeyUsage=codeSigning.
  inline constexpr const char* EKU_LEAF_CERT_PEM =
    R"pem(-----BEGIN CERTIFICATE-----
MIIB3TCCAYKgAwIBAgIURnYlcLaEUQSqkqEZdTJk/7XJnBwwCgYIKoZIzj0EAwIw
MjEwMC4GA1UEAwwnU0NJVFQgU2VsZWN0aXZlIERpc2Nsb3N1cmUgVGVzdCBSb290
IENBMCAXDTI2MDgxNzE5MTYzMVoYDzIxMjYwNzI0MTkxNjMxWjAxMS8wLQYDVQQD
DCZTQ0lUVCBTZWxlY3RpdmUgRGlzY2xvc3VyZSBUZXN0IElzc3VlcjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABPs7LMcPxO9eYyR71NB8ybZGOgTDI6IXZ97jivYp
52BNDfPvFbERVTPgzRPkM+z0kDjzF6pll3XNLirTGos+rHijdTBzMAwGA1UdEwEB
/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1Ud
DgQWBBS/bErl47mg+bGurn4Ezqk9FDNLYzAfBgNVHSMEGDAWgBSwBN5p3wwLOmea
4X6wR/e7KuTGTTAKBggqhkjOPQQDAgNJADBGAiEAwG3c2PhEP0/32hO+0HM2owgY
gl6pqOG7yjtEs4d2T2ECIQD/+RSbOudfJQUHDAT7m4EjTZTnOeMHIsVRbrj6++sQ
mQ==
-----END CERTIFICATE-----
)pem";

  // The leaf's private key: TEST-ONLY, never used outside these tests.
  inline constexpr const char* EKU_LEAF_KEY_PEM =
    R"pem(-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDgsnkhcNKs8PBzti1E
wmC3/RHBcN9l4qikUsvSu+ptSA==
-----END PRIVATE KEY-----
)pem";
}
