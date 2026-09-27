//! Independent OpenSSH / OpenSSL fixtures for the RSA and ECDSA P-256 tests.
//! Nothing here is generated at test time.
//!
//! Provenance (OpenSSH_10.2p1, OpenSSL 3.5.8), generated solely as test
//! fixtures and never used as host keys:
//!
//! ```text
//! ssh-keygen -t rsa -b 2048 -N '' -C tatami-rsa -f rsa2048
//! ssh-keygen -t ecdsa -b 256 -N '' -C tatami-ecdsa -f p256
//! ssh-keygen -t rsa -b 1024 -N '' -C tatami-rsa1024 -f rsa1024
//! ssh-keygen -t ecdsa -b 384 -N '' -C tatami-p384 -f p384
//! ssh-keygen -lf KEY.pub                    # *_FP
//! ssh-keygen -r fixture.example -f KEY.pub  # *_SSHFP
//! ssh-keygen -e -m PKCS8 -f KEY.pub         # *_SPKI (base64 body)
//! cp KEY KEY.pem; ssh-keygen -p -m PEM -N '' -P '' -f KEY.pem
//!                                           # *_PKCS1 / *_SEC1: OpenSSL's
//!                                           # own CRT values and SEC1 layout
//! ```

#![allow(dead_code)]

/// `rsa2048.pub` blob (base64).
pub const RSA_2048_PUB: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/pUSpK/bpDncU75uYgJ+xQtxuqITHzTd9IUzFgNNlp1atsMgG+plKggA93jMaPuSc/PKrn0ShISco1UWZajKeNXyO2jdcsWtwiRXLQRLWFgT308pyunpMmewS03xJg7nBhneWSPbLjvr3PxALsDZSplTTCl15Iyuwvcoq14Jp+oPJ27Jz73sRRYqcwXoyrMqfgOOb5kTeS+EG206df1zfwVkLNmzTh+N3c5krdc49eQjg3JKGszQjpIotfyJSOwtDTHrexFcrYJgXNPjaytgO3OJ5UnAvXuQCl2YeDu3pwJUuil5rGFfLNloa5pmSD0a34c/8IxUl7LZVCbSWGGtd";
/// `ssh-keygen -lf rsa2048.pub`.
pub const RSA_2048_FP: &str = "SHA256:xo85+YH/IOJ/kQz2hVqUbirzalxWNzzNn3z5MbwJkWA";
/// `ssh-keygen -r` type-2 record for `rsa2048.pub`.
pub const RSA_2048_SSHFP: &str =
    "1 2 c68f39f981ff20e27f910cf6855a946e2af36a5c56373ccd9f7cf931bc099160";
/// `ssh-keygen -r` SHA-1 record, which Tatami must never produce or parse.
pub const RSA_2048_SSHFP_SHA1: &str = "1 1 27ffbf4ea3ee0aecca3220177658b32af1439817";
/// `ssh-keygen -e -m PKCS8 -f rsa2048.pub` body.
pub const RSA_2048_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6VEqSv26Q53FO+bmICfsULcbqiEx803fSFMxYDTZadWrbDIBvqZSoIAPd4zGj7knPzyq59EoSEnKNVFmWoynjV8jto3XLFrcIkVy0ES1hYE99PKcrp6TJnsEtN8SYO5wYZ3lkj2y4769z8QC7A2UqZU0wpdeSMrsL3KKteCafqDyduyc+97EUWKnMF6MqzKn4Djm+ZE3kvhBttOnX9c38FZCzZs04fjd3OZK3XOPXkI4NyShrM0I6SKLX8iUjsLQ0x63sRXK2CYFzT42srYDtzieVJwL17kApdmHg7t6cCVLopeaxhXyzZaGuaZkg9Gt+HP/CMVJey2VQm0lhhrXQIDAQAB";
/// `rsa2048` (unencrypted `openssh-key-v1`).
pub const RSA_2048_OPENSSH: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAv6VEqSv26Q53FO+bmICfsULcbqiEx803fSFMxYDTZadWrbDIBvqZ
SoIAPd4zGj7knPzyq59EoSEnKNVFmWoynjV8jto3XLFrcIkVy0ES1hYE99PKcrp6TJnsEt
N8SYO5wYZ3lkj2y4769z8QC7A2UqZU0wpdeSMrsL3KKteCafqDyduyc+97EUWKnMF6MqzK
n4Djm+ZE3kvhBttOnX9c38FZCzZs04fjd3OZK3XOPXkI4NyShrM0I6SKLX8iUjsLQ0x63s
RXK2CYFzT42srYDtzieVJwL17kApdmHg7t6cCVLopeaxhXyzZaGuaZkg9Gt+HP/CMVJey2
VQm0lhhrXQAAA8BZJzc9WSc3PQAAAAdzc2gtcnNhAAABAQC/pUSpK/bpDncU75uYgJ+xQt
xuqITHzTd9IUzFgNNlp1atsMgG+plKggA93jMaPuSc/PKrn0ShISco1UWZajKeNXyO2jdc
sWtwiRXLQRLWFgT308pyunpMmewS03xJg7nBhneWSPbLjvr3PxALsDZSplTTCl15Iyuwvc
oq14Jp+oPJ27Jz73sRRYqcwXoyrMqfgOOb5kTeS+EG206df1zfwVkLNmzTh+N3c5krdc49
eQjg3JKGszQjpIotfyJSOwtDTHrexFcrYJgXNPjaytgO3OJ5UnAvXuQCl2YeDu3pwJUuil
5rGFfLNloa5pmSD0a34c/8IxUl7LZVCbSWGGtdAAAAAwEAAQAAAQAIZQ4mpesdJtnPBDbp
3XqBSoc63q1gTiw30jlZbmz0JzocBiIg8iG8Woj1rNHKvMYJXWgo3eNk9n2PY5Y2o+j/Nq
MT49moeQoWhh67BkjzsUe67l9QGryINfbaFUL8umUs5b2/ysbqwELciTnj9S5P/QK6stnI
2GJNzeZ47XNEPpZWoc/BxdpJEZibBBfsvliPnvBmjuUBE3E5z2xBOyehVhVYUrsA3eZ/TF
oqOXlEFGvQ84YyB1wLO5TaXFlZzfbsqQ1tR3CphgDavlGpPIB+vxpQle5pRdTIJNzo6rTh
L8Yn8iajuGw+dazLQ1qL94lCtUysZ2gJ+m8lGMKtxpOBAAAAgGikq7jdQhCU02mfOpzK0z
L0JqJ+6o+AYCU/0vpYS3b2b9Ee4MvEDcle5sX68gzC22CzTJNhBkrTd4ZAhjCjRw14brQh
ux6j/YxBLmzGVGne+zumwJ3QN2+snLbQOaif8uREIOtPw83evsCNbHPUR7voPlq/imkNjy
zhQ71BiGtpAAAAgQDgfGY3zXykfR1J2Kg3KoVnP+RBPhDfF8QI54pJbg7DZe1V4vrvkrmE
Mj0oHvIc3TIPBUeU/KzWlXrGoU1V/YoY6RvuQ7wI5QxkRggPWSNpwocPp5iFDCaKOn/NHN
KquGe/AB+d2QSLKmOMT7FYrXxeDQTzVmKq9kGwLYAKhRl/3QAAAIEA2oymBcz8Hk4TdajF
YB4W0an76ogqYEWFYyV6horrYkyqBFMkKcEMfq/bgiQzTVx4ekJe6i7zHpEpYJF1zDpbOp
K6lbdsohpOX1AIvN6JsUqQt+TPY0LEPVY/OzZIyZbna3Dvy04v5ImlJVMqNnP7jt5PwKaM
DTsyRQrmDDNZoYEAAAAKdGF0YW1pLXJzYQE=
-----END OPENSSH PRIVATE KEY-----
";
/// OpenSSL's PKCS#1 `RSAPrivateKey` for `rsa2048` (base64 DER), including
/// the CRT values it computed itself.
pub const RSA_2048_PKCS1: &str = "MIIEogIBAAKCAQEAv6VEqSv26Q53FO+bmICfsULcbqiEx803fSFMxYDTZadWrbDIBvqZSoIAPd4zGj7knPzyq59EoSEnKNVFmWoynjV8jto3XLFrcIkVy0ES1hYE99PKcrp6TJnsEtN8SYO5wYZ3lkj2y4769z8QC7A2UqZU0wpdeSMrsL3KKteCafqDyduyc+97EUWKnMF6MqzKn4Djm+ZE3kvhBttOnX9c38FZCzZs04fjd3OZK3XOPXkI4NyShrM0I6SKLX8iUjsLQ0x63sRXK2CYFzT42srYDtzieVJwL17kApdmHg7t6cCVLopeaxhXyzZaGuaZkg9Gt+HP/CMVJey2VQm0lhhrXQIDAQABAoIBAAhlDial6x0m2c8ENundeoFKhzrerWBOLDfSOVlubPQnOhwGIiDyIbxaiPWs0cq8xgldaCjd42T2fY9jljaj6P82oxPj2ah5ChaGHrsGSPOxR7ruX1AavIg19toVQvy6ZSzlvb/KxurAQtyJOeP1Lk/9Arqy2cjYYk3N5njtc0Q+llahz8HF2kkRmJsEF+y+WI+e8GaO5QETcTnPbEE7J6FWFVhSuwDd5n9MWio5eUQUa9DzhjIHXAs7lNpcWVnN9uypDW1HcKmGANq+Uak8gH6/GlCV7mlF1Mgk3OjqtOEvxifyJqO4bD51rMtDWov3iUK1TKxnaAn6byUYwq3Gk4ECgYEA4HxmN818pH0dSdioNyqFZz/kQT4Q3xfECOeKSW4Ow2XtVeL675K5hDI9KB7yHN0yDwVHlPys1pV6xqFNVf2KGOkb7kO8COUMZEYID1kjacKHD6eYhQwmijp/zRzSqrhnvwAfndkEiypjjE+xWK18Xg0E81ZiqvZBsC2ACoUZf90CgYEA2oymBcz8Hk4TdajFYB4W0an76ogqYEWFYyV6horrYkyqBFMkKcEMfq/bgiQzTVx4ekJe6i7zHpEpYJF1zDpbOpK6lbdsohpOX1AIvN6JsUqQt+TPY0LEPVY/OzZIyZbna3Dvy04v5ImlJVMqNnP7jt5PwKaMDTsyRQrmDDNZoYECgYA9gHd0xFxoqEp05+G2M3UXA38ijMGMjXNMyTquwXNT/0HVrPj41+bxm937dvb4B3XmfZjN7afgplVbw+dvLqY+Cud3EKGcgjwx4KnmopI8MGpWVKFJmjmY10waQtJIqXrq7jq7QTCoe/WIBHFfDTCsh76aeElR82Otw9l3iF2jFQKBgAynxllhpFvQ45mVm1BUjbe4YykSl3mZrP6vxeeSlczMaa/0bIyqbCHN5yUjGYFqUGOsAjkHXPaxKzc3VR3tZyj+JCXVSEoewdkNFmRxcoG8sqKjckrqK9jtbJ3uJ8rcnSwAjzIzpdxTCCggJ7qdfryoLPAX9NYzTlbnKakdNByBAoGAaKSruN1CEJTTaZ86nMrTMvQmon7qj4BgJT/S+lhLdvZv0R7gy8QNyV7mxfryDMLbYLNMk2EGStN3hkCGMKNHDXhutCG7HqP9jEEubMZUad77O6bAndA3b6ycttA5qJ/y5EQg60/Dzd6+wI1sc9RHu+g+Wr+KaQ2PLOFDvUGIa2k=";

/// `p256.pub` blob (base64).
pub const P256_PUB: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPefqcX04ziwNySvMXeLEfDe8F0XSC8g003NOymUwN0vb5UpZ3nIXNJJQafT41xQzPXH9DJRby8NLEtRLgS20No=";
/// `ssh-keygen -lf p256.pub`.
pub const P256_FP: &str = "SHA256:SsEpc4vJWMyCyhf6jvzGGY6gWGY4opN5/12I08W43B4";
/// `ssh-keygen -r` type-2 record for `p256.pub`.
pub const P256_SSHFP: &str = "3 2 4ac129738bc958cc82ca17fa8efcc6198ea0586638a29379ff5d88d3c5b8dc1e";
/// `ssh-keygen -e -m PKCS8 -f p256.pub` body.
pub const P256_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE95+pxfTjOLA3JK8xd4sR8N7wXRdILyDTTc07KZTA3S9vlSlnechc0klBp9PjXFDM9cf0MlFvLw0sS1EuBLbQ2g==";
/// `p256` (unencrypted `openssh-key-v1`).
pub const P256_OPENSSH: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT3n6nF9OM4sDckrzF3ixHw3vBdF0gv
INNNzTsplMDdL2+VKWd5yFzSSUGn0+NcUMz1x/QyUW8vDSxLUS4EttDaAAAAqNGjKcbRoy
nGAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPefqcX04ziwNySv
MXeLEfDe8F0XSC8g003NOymUwN0vb5UpZ3nIXNJJQafT41xQzPXH9DJRby8NLEtRLgS20N
oAAAAhALYUyJJ3H2634hSVlQKFu2gLJEWfBiDyCpd43t+LnLJOAAAADHRhdGFtaS1lY2Rz
YQECAw==
-----END OPENSSH PRIVATE KEY-----
";
/// OpenSSL's SEC1 `ECPrivateKey` for `p256` (base64 DER).
pub const P256_SEC1: &str = "MHcCAQEEILYUyJJ3H2634hSVlQKFu2gLJEWfBiDyCpd43t+LnLJOoAoGCCqGSM49AwEHoUQDQgAE95+pxfTjOLA3JK8xd4sR8N7wXRdILyDTTc07KZTA3S9vlSlnechc0klBp9PjXFDM9cf0MlFvLw0sS1EuBLbQ2g==";

/// `rsa1024.pub` blob: well formed, below the RSA policy.
pub const RSA_1024_PUB: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDaHk8Oo0PJIFbw0drZloysH85GmOfyoDgcqK0Hpn95IWPYh2QVc1O43DwNQ0+ZoCQnTC7IxjTpDv/flXnjf0gHBsLojhDOvBTpdKE5Y/fwRM/XiKpOMFpqS+UHwKN5v8HuCK37uPNdhJ24cn2kZSLLvZ8rheglnS7lDbS88aAxTw==";
/// `rsa1024` private key.
pub const RSA_1024_OPENSSH: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA2h5PDqNDySBW8NHa2ZaMrB/ORpjn8qA4HKitB6Z/eSFj2IdkFXNT
uNw8DUNPmaAkJ0wuyMY06Q7/35V5439IBwbC6I4QzrwU6XShOWP38ETP14iqTjBaakvlB8
Cjeb/B7git+7jzXYSduHJ9pGUiy72fK4XoJZ0u5Q20vPGgMU8AAAIIFeOZSRXjmUkAAAAH
c3NoLXJzYQAAAIEA2h5PDqNDySBW8NHa2ZaMrB/ORpjn8qA4HKitB6Z/eSFj2IdkFXNTuN
w8DUNPmaAkJ0wuyMY06Q7/35V5439IBwbC6I4QzrwU6XShOWP38ETP14iqTjBaakvlB8Cj
eb/B7git+7jzXYSduHJ9pGUiy72fK4XoJZ0u5Q20vPGgMU8AAAADAQABAAAAgQCy4fCMXL
GXHYKv9iu6D5JHB76wf26auXPLbTqa753TxeKRDliyjua20UgeyHlb0M5VvFESMBvsl3SZ
9YkFXrm+JVUzgZXLnlhA8CbG8J7+iOSn+9e+x53gUey8kOW+T1wCHJMHE8dF9udGsou5Sd
DM6b4DDBFGCMADZenfLEFOAQAAAEB0xUwkmyvA/u4wgtiBeV0/UDUNtKfAFXFsO6fxgBkk
CEGgUqiopD4MxRBvR9inFn7iPWvWiQcFALnSGR3rEEfCAAAAQQD5Lvyk3BhjDeq5UN7OMq
aJ276JPyAfcf+gYVVcf35SbqHeYk6yKDhhuTA3BZ2lTT518gzJrHQn9naM63wav1qPAAAA
QQDgFcZsM0v2ITHdb+h3mjJaq1C42hGCpPktzh7iQMEVwH7viMICIjkN32FqOstgWvWJ7L
sCBMaTp9PGDX3tuB1BAAAADnRhdGFtaS1yc2ExMDI0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
";
/// `p384.pub` blob: a supported format family, unsupported curve.
pub const P384_PUB: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBKqprDlpH5PJza5LqOywKj4kPqgYqzUu74/arpip9M8thIz4kEg1sz43R+79LRAqIoI1XoP7BrK4dn6N8ttmtM0lbHn3N3tWoA2muMsU6mEPAiQNam91O4+130w52slIGg==";
/// `p384` private key.
pub const P384_OPENSSH: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSqqaw5aR+Tyc2uS6jssCo+JD6oGKs1
Lu+P2q6YqfTPLYSM+JBINbM+N0fu/S0QKiKCNV6D+wayuHZ+jfLbZrTNJWx59zd7VqANpr
jLFOphDwIkDWpvdTuPtd9MOdrJSBoAAADYqSZytKkmcrQAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEEqqmsOWkfk8nNrkuo7LAqPiQ+qBirNS7vj9qumKn0zy
2EjPiQSDWzPjdH7v0tECoigjVeg/sGsrh2fo3y22a0zSVsefc3e1agDaa4yxTqYQ8CJA1q
b3U7j7XfTDnayUgaAAAAMQDuPxa7MlBDOcHjScIMd6Kbes/Jh+dyOwdgSQgXpW/C7kqvlU
tIY3VHtPfvcSMu6VsAAAALdGF0YW1pLXAzODQBAgME
-----END OPENSSH PRIVATE KEY-----
";

/// Decodes a base64 fixture.
pub fn b64(text: &str) -> alloc::vec::Vec<u8> {
    use base64ct::{Base64, Encoding as _};
    Base64::decode_vec(text).expect("fixture is valid base64")
}
