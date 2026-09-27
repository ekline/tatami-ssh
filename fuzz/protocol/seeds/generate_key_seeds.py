#!/usr/bin/env python3
"""Regenerates the committed seeds for the round-5 host-identity targets
(`spki_conversion`, `known_hosts`, `openssh_private_key`).

Run from anywhere: `python3 fuzz/protocol/seeds/generate_key_seeds.py`.
Deterministic; re-running must not change any file.

Provenance:
- SPKI fixtures are written by hand from RFC 8410 §4 / §10.1 (the valid
  example key is the RFC's own); each malformed seed changes one field.
- `known_hosts` seeds are *descriptions* in the layout documented at the top
  of `fuzz_targets/known_hosts.rs`; keys are derived at run time.
- `openssh_private_key` raw seeds are the `ssh-keygen` (OpenSSH_10.2p1)
  TEST fixtures already committed in `crates/tatami_ssh_keys/src/openssh_key.rs`
  (never host keys); structured seeds are descriptions (seed bytes, tamper
  kind), with key material derived at run time.
"""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def write(target, name, data):
    d = HERE / target
    d.mkdir(exist_ok=True)
    (d / name).write_bytes(bytes(data))


# ---- spki_conversion ------------------------------------------------------
# sel even = raw bytes; sel odd = 32-byte Ed25519 seed (derived key).
PREFIX = bytes.fromhex("302a300506032b6570032100")
RFC8410_KEY = bytes.fromhex(
    "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
)


def spki(oid=bytes.fromhex("2b6570"), params=b"", unused=0, key=RFC8410_KEY):
    alg = bytes([0x06, len(oid)]) + oid + params
    alg = bytes([0x30, len(alg)]) + alg
    bits = bytes([unused]) + key
    bits = bytes([0x03, len(bits)]) + bits
    body = alg + bits
    return bytes([0x30, len(body)]) + body


assert spki() == PREFIX + RFC8410_KEY
raw = {
    "raw_rfc8410_example": spki(),
    "raw_oid_ed448": spki(oid=bytes.fromhex("2b6571")),
    "raw_oid_x25519": spki(oid=bytes.fromhex("2b656e")),
    "raw_oid_rsa": spki(oid=bytes.fromhex("2a864886f70d010101")),
    "raw_params_null": spki(params=b"\x05\x00"),
    "raw_unused_bits_1": spki(unused=1),
    "raw_key_31_bytes": spki(key=RFC8410_KEY[:31]),
    "raw_key_33_bytes": spki(key=RFC8410_KEY + b"\x00"),
    "raw_long_form_length": b"\x30\x81\x2a" + spki()[2:],
    "raw_indefinite_length": b"\x30\x80" + spki()[2:] + b"\x00\x00",
    "raw_trailing_byte": spki() + b"\x00",
    "raw_truncated": spki()[:30],
    "raw_ssh_blob": b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + RFC8410_KEY,
    "raw_bare_key": RFC8410_KEY,
    "raw_empty": b"",
}
for name, data in raw.items():
    write("spki_conversion", name, b"\x00" + data)
write("spki_conversion", "derived_seed_zero", b"\x01" + bytes(32))
write("spki_conversion", "derived_seed_counting", b"\x01" + bytes(range(32)))

# ---- known_hosts ----------------------------------------------------------
# flags: bits 0-1 lookup (0 host.example:22, 1 HOST.Example:22,
# 2 host.example:2222, 3 other.example:22); bits 2-3 offered key; bit 4
# malformed line; bits 5-7 malformed kind. Then n-1, bad_at, lines of
# (mark, key, h, p1, p2, p3). Vocabulary indices (see the target):
V = {
    "host.example": 0,
    "HOST.EXAMPLE": 1,
    "*": 2,
    "*.example": 3,
    "h?st.example": 4,
    "[host.example]:2222": 5,
    "[*.example]:2222": 6,
    "other.example": 7,
    "[host.example]:*": 8,
    "*:2222": 9,
}
NEG = 0x80
NONE, REVOKED, CA = 0, 1, 2
K0, K1, K2, RSA = 0, 1, 2, 3


def pat(mark, key, *patterns):
    ps = list(patterns) + [0] * (3 - len(patterns))
    return [mark, key, len(patterns) - 1] + ps


def hashed(mark, key, lookup):
    return [mark, key, 0x80 | (lookup << 3), 0, 0, 0]


def kh(name, lines, lookup=0, offered=0, bad=None, bad_at=0, glob=b""):
    flags = lookup | (offered << 2)
    if bad is not None:
        flags |= 0x10 | (bad << 5)
    data = [flags, len(lines) - 1, bad_at]
    for l in lines:
        data += l
    write("known_hosts", name, bytes(data) + glob)


kh("trusted_plain", [pat(NONE, K0, V["host.example"])])
kh("trusted_uppercase_pattern", [pat(NONE, K0, V["HOST.EXAMPLE"])], lookup=1)
kh("trusted_wildcard", [pat(NONE, K0, V["*.example"])])
kh("trusted_question_mark", [pat(NONE, K0, V["h?st.example"])])
kh("trusted_port_2222", [pat(NONE, K0, V["[host.example]:2222"])], lookup=2)
kh("trusted_port_wildcard", [pat(NONE, K0, V["[*.example]:2222"])], lookup=2)
kh("port22_entry_not_2222", [pat(NONE, K0, V["host.example"])], lookup=2)
kh("negated", [pat(NONE, K0, V["*"], NEG | V["host.example"])])
kh("negation_only", [pat(NONE, K0, NEG | V["other.example"])])
kh("hashed_port22", [hashed(NONE, K0, 0)])
kh("hashed_port2222", [hashed(NONE, K0, 2)], lookup=2)
kh("hashed_other_name", [hashed(NONE, K0, 3)])
kh(
    "revoked_before_positive",
    [pat(REVOKED, K0, V["*"]), pat(NONE, K0, V["host.example"])],
)
kh(
    "revoked_after_positive",
    [pat(NONE, K0, V["host.example"]), pat(REVOKED, K0, V["host.example"])],
)
kh(
    "revoked_other_host",
    [pat(REVOKED, K0, V["other.example"]), pat(NONE, K0, V["host.example"])],
)
kh(
    "rotation",
    [pat(NONE, K1, V["host.example"]), pat(NONE, K0, V["host.example"])],
)
kh(
    "duplicates",
    [pat(NONE, K0, V["host.example"]), pat(NONE, K0, V["host.example"])],
)
kh("key_changed", [pat(NONE, K1, V["host.example"])])
kh("ca_only_same_key", [pat(CA, K0, V["*"])])
kh("other_algorithm_only", [pat(NONE, RSA, V["host.example"])])
kh("unknown_host", [pat(NONE, K0, V["other.example"])])
kh(
    "mixed_eight_lines",
    [
        pat(CA, K2, V["*"]),
        pat(NONE, RSA, V["host.example"]),
        hashed(NONE, K1, 0),
        pat(NONE, K2, V["*.example"], NEG | V["other.example"]),
        pat(REVOKED, K1, V["*"]),
        pat(NONE, K0, V["[host.example]:*"], V["host.example"]),
        pat(NONE, K1, V["*:2222"]),
        hashed(REVOKED, K2, 2),
    ],
    glob=b"*a?b.ab*ba",
)
for kind, name in enumerate(
    ["unknown_marker", "revoked_bad_base64", "key_type_mismatch", "missing_key", "empty_pattern"]
):
    kh(
        f"malformed_{name}",
        [pat(NONE, K0, V["host.example"]), pat(NONE, K1, V["*"])],
        bad=kind,
        bad_at=1,
    )

# ---- openssh_private_key --------------------------------------------------
src = (ROOT / "crates/tatami_ssh_keys/src/openssh_key.rs").read_text()


def fixture(const):
    m = re.search(const + r': &str = "\\\n(.*?)";', src, re.S)
    assert m, const
    return m.group(1).encode()


for const, name in [
    ("SSH_KEYGEN_ED25519", "raw_ssh_keygen_ed25519"),
    ("SSH_KEYGEN_ED25519_ENCRYPTED", "raw_ssh_keygen_encrypted"),
    ("SSH_KEYGEN_ECDSA", "raw_ssh_keygen_ecdsa"),
]:
    write("openssh_private_key", name, b"\x00" + fixture(const))
write(
    "openssh_private_key",
    "raw_pkcs8_pem",
    b"\x00-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    b"-----END PRIVATE KEY-----\n",
)
KINDS = [
    "valid",
    "public_not_derived",
    "outer_public_mismatch",
    "embedded_public_mismatch",
    "checkint_mismatch",
    "two_keys",
    "kdf_on_unencrypted",
    "bad_padding",
    "trailing_bytes",
    "truncated",
    "encrypted_aes256_ctr_bcrypt",
]
for kind, name in enumerate(KINDS):
    seed = bytes((kind * 37 + i * 11) & 0xFF for i in range(32))
    write("openssh_private_key", f"structured_{name}", b"\x01" + seed + bytes([kind, 0x30]))
