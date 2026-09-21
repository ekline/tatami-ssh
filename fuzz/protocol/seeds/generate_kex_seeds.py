#!/usr/bin/env python3
"""Regenerates the committed seeds for the key-exchange protocol targets
(`key_blobs`, `tcp_negotiation`, `tcp_gcm_packets`, `tcp_handshake`,
`handshake_report_json`) and the standard-strict-marker seeds of
`tcp_probe` / `tcp_observer`.

Run from anywhere: `python3 fuzz/protocol/seeds/generate_kex_seeds.py`.
Every seed is a *description* in the layout documented at the top of the
target file; the harness derives all key material at run time, so no key,
signature or ciphertext is stored here. Deterministic; re-running must not
change any file.
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent


def u8(v):
    return bytes([v & 0xFF])


def u16be(v):
    return v.to_bytes(2, "big")


def u32be(v):
    return v.to_bytes(4, "big")


def string(b):
    return u32be(len(b)) + b


def name_list(names):
    return string(b",".join(names))


def lcg_bytes(n, seed):
    out = bytearray()
    x = seed & 0xFFFFFFFF
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def write(target, name, data):
    d = HERE / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


# ---------------------------------------------------------------------------
# key_blobs: sel:u8 then raw bytes (sel < 0x80) or a structured description
# (seed 32, flip_sig u8, flip_msg u8, flip_pin u8, msg_len u8, message).
# ---------------------------------------------------------------------------

RAW = b"\x00"
STRUCT = b"\x80"
# RFC 8032 §7.1 TEST 1 public key (a public value, not a secret).
TEST1_PK = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
TEST1_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
ED_BLOB = string(b"ssh-ed25519") + string(TEST1_PK)
SIG_BLOB = string(b"ssh-ed25519") + string(TEST1_SIG)
TEST1_FP = b"SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"

KEY_BLOBS = {
    "raw_empty": RAW,
    "raw_ed25519_test1_blob": RAW + ED_BLOB,
    "raw_ed25519_blob_trailing": RAW + ED_BLOB + b"\x00",
    "raw_ed25519_key_len_31": RAW + string(b"ssh-ed25519") + string(TEST1_PK[:31]),
    "raw_ed25519_invalid_point_y2": RAW + string(b"ssh-ed25519") + string(b"\x02" + b"\x00" * 31),
    "raw_rsa_blob": RAW + string(b"ssh-rsa") + string(b"\x01\x00\x01") + string(b"\xc3" * 32),
    "raw_algorithm_length_overflow": RAW + u32be(11) + b"s",
    "raw_signature_blob_test1": RAW + SIG_BLOB,
    "raw_signature_blob_trailing": RAW + SIG_BLOB + b"\x00",
    "raw_signature_blob_rsa_sha2_256": RAW + string(b"rsa-sha2-256") + string(b"xy"),
    "raw_signature_blob_len_63": RAW + string(b"ssh-ed25519") + string(TEST1_SIG[:63]),
    "raw_fingerprint_text_test1": RAW + TEST1_FP,
    "raw_fingerprint_padded": RAW + TEST1_FP + b"=",
    "raw_fingerprint_lowercase_prefix": RAW + b"sha256:" + TEST1_FP[7:],
    "raw_fingerprint_urlsafe": RAW + TEST1_FP[:-2] + b"_8",
    "raw_fingerprint_noncanonical_tail": RAW + TEST1_FP[:-1] + b"9",
    "structured_empty_message": STRUCT + lcg_bytes(32, 1) + u8(3) + u8(0) + u8(9) + u8(0),
    "structured_short_message": STRUCT + lcg_bytes(32, 2) + u8(63) + u8(7) + u8(31) + u8(5) + b"hello",
    "structured_long_message": STRUCT + lcg_bytes(32, 3) + u8(0) + u8(0) + u8(0) + u8(128) + lcg_bytes(128, 4),
}
for name, data in KEY_BLOBS.items():
    write("key_blobs", name, data)

# ---------------------------------------------------------------------------
# tcp_negotiation: flags u8; lists per kex_support::lists::gen_lists:
# cookie 16, then ten lists of (count u8 mod 5, index bytes), flags u8
# (bit0 first_kex_packet_follows, bit1 reserved u32 follows).
# Index bytes: kex pool 0-5, markers 6-11 (ext-info-c, ext-info-s,
# kex-strict-c-v00, kex-strict-s-v00, kex-strict-c, kex-strict-s);
# host keys 0-5; ciphers 0-5; macs 0-5; compressions 0-3; languages 0-2;
# larger indices are fuzz names.
# ---------------------------------------------------------------------------


def lst(*idx):
    return u8(len(idx)) + bytes(idx)


def lists(cookie_seed, kex, hk, ec, es, mc, ms, cc, cs, lc=(), ls=(), flags=0, reserved=None):
    out = lcg_bytes(16, cookie_seed)
    for l in (kex, hk, ec, es, mc, ms, cc, cs, lc, ls):
        out += lst(*l)
    out += u8(flags)
    if reserved is not None:
        out += u32be(reserved)
    return out


AEAD_SERVER = dict(hk=(0,), ec=(0,), es=(0,), mc=(0,), ms=(0,), cc=(0,), cs=(0,))

NEGOTIATION = {
    # Our proposal (ext-info-c, strict) vs a matching strict server (pre-standard).
    "proposal_vs_strict_prestandard_server": u8(0x07) + lcg_bytes(16, 10) + lists(11, (0, 7, 9), **AEAD_SERVER),
    # Our proposal vs a server offering only the standard strict name.
    "proposal_vs_standard_strict_server": u8(0x07) + lcg_bytes(16, 12) + lists(13, (0, 11), **AEAD_SERVER),
    # Mixed spellings never pair: client both, server standard only, no ext-info.
    "proposal_no_ext_info_vs_mixed": u8(0x05) + lcg_bytes(16, 14) + lists(15, (0, 9, 11), **AEAD_SERVER),
    # Proposal without strict vs server with both strict spellings.
    "proposal_no_strict_vs_both": u8(0x03) + lcg_bytes(16, 16) + lists(17, (0, 9, 11, 7), **AEAD_SERVER),
    # Server guess wrong: first method differs, flag set.
    "proposal_vs_guess_wrong": u8(0x07) + lcg_bytes(16, 18) + lists(19, (3, 0, 7, 9), flags=1, **AEAD_SERVER),
    # Server guess right: same first method and host key, flag set.
    "proposal_vs_guess_right": u8(0x07) + lcg_bytes(16, 20) + lists(21, (0, 3), flags=1, **AEAD_SERVER),
    # No common kex: markers only on the server side.
    "proposal_vs_markers_only": u8(0x07) + lcg_bytes(16, 22) + lists(23, (7, 9, 11), **AEAD_SERVER),
    # Non-AEAD cipher selected: NoMacImplemented.
    "pair_non_aead_cipher": u8(0x00)
    + lists(24, (0,), (0,), (2,), (2,), (0,), (0,), (0,), (0,))
    + lists(25, (0,), (0,), (2,), (2,), (0,), (0,), (0,), (0,)),
    # Fuzz pair: every list empty on one side.
    "pair_empty_server_lists": u8(0x00) + lists(26, (0, 6, 8), (0,), (0,), (0,), (0,), (0,), (0,), (0,)) + lists(27, (), (), (), (), (), (), (), ()),
    # Fuzz pair with all six markers on both sides and unknown names.
    "pair_all_markers_and_unknown": u8(0x00)
    + lists(28, (6, 7, 8, 9, 10, 11, 5, 0), (5, 0), (5, 0), (0, 5), (5,), (5,), (3, 0), (0, 3), (0,), (1,), flags=3, reserved=0xDEADBEEF)
    + lists(29, (11, 10, 9, 8, 7, 6, 0, 5), (0, 5), (0, 5), (5, 0), (5,), (5,), (0, 3), (3, 0), (2,), (0,)),
    # Mixed strict spellings never enable strict KEX: client standard only vs
    # server pre-standard only, and the reverse.
    "pair_mixed_strict_standard_vs_prestandard": u8(0x00)
    + lists(40, (0, 10), (0,), (0,), (0,), (0,), (0,), (0,), (0,))
    + lists(41, (0, 9), (0,), (0,), (0,), (0,), (0,), (0,), (0,)),
    "pair_mixed_strict_prestandard_vs_standard": u8(0x00)
    + lists(42, (0, 8, 6), (0,), (0,), (0,), (0,), (0,), (0,), (0,))
    + lists(43, (0, 11, 7), (0,), (0,), (0,), (0,), (0,), (0,), (0,)),
    # Same spelling on both sides, standard only: strict.
    "pair_standard_strict_both": u8(0x00)
    + lists(44, (0, 10), (0,), (0,), (0,), (0,), (0,), (0,), (0,))
    + lists(45, (0, 11), (0,), (0,), (0,), (0,), (0,), (0,), (0,)),
    # Compression mismatch in one direction.
    "pair_compression_s2c_mismatch": u8(0x00)
    + lists(30, (0,), (0,), (0,), (0,), (0,), (0,), (0,), (1,))
    + lists(31, (0,), (0,), (0,), (0,), (0,), (0,), (0,), (0,)),
    # Raw KEXINIT tail: the wire-format server proposal with standard strict marker.
    "raw_tail_standard_strict": u8(0x0F)
    + lcg_bytes(16, 32)
    + lists(33, (0, 11, 7), **AEAD_SERVER)
    + u8(20)
    + lcg_bytes(16, 34)
    + name_list([b"curve25519-sha256", b"kex-strict-s", b"ext-info-s"])
    + name_list([b"ssh-ed25519"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"none"])
    + name_list([b"none"])
    + name_list([])
    + name_list([])
    + u8(0)
    + u32be(0),
}
for name, data in NEGOTIATION.items():
    write("tcp_negotiation", name, data)

# ---------------------------------------------------------------------------
# tcp_gcm_packets: flags u8, key 16, iv 12, pad seed u8, [limit u16],
# n payloads u8, per payload len u16 + bytes, n_sched u8 + sizes,
# mutation idx u8, xor u8, fuzz length 4, boundary k u8, forged padding u8.
# ---------------------------------------------------------------------------


def gcm_seed(flags, key_seed, payloads, limit=None, sched=b"", mut_idx=0, xor=1, fuzz_len=b"\x00\x00\x00\x20", k=1, forged=4):
    out = u8(flags) + lcg_bytes(16, key_seed) + lcg_bytes(12, key_seed + 1) + u8(key_seed & 0xFF)
    if limit is not None:
        out += u16be(limit)
    out += u8(len(payloads))
    for p in payloads:
        out += u16be(len(p)) + p
    out += u8(len(sched)) + sched
    out += u8(mut_idx) + u8(xor) + fuzz_len + u8(k) + u8(forged)
    return out


EXT_INFO_PAYLOAD = u8(7) + u32be(1) + string(b"server-sig-algs") + string(b"ssh-ed25519")
SERVICE_ACCEPT_PAYLOAD = u8(6) + string(b"ssh-userauth")

GCM = {
    "round_trip_two_packets_default_limit": gcm_seed(0x00, 40, [EXT_INFO_PAYLOAD, SERVICE_ACCEPT_PAYLOAD]),
    "round_trip_byte_sizes_1_15_16_17": gcm_seed(0x10, 41, [b"\x15", lcg_bytes(15, 1), lcg_bytes(16, 2), lcg_bytes(17, 3)]),
    "cap_boundary_64kib_packet": gcm_seed(0x08, 42, [SERVICE_ACCEPT_PAYLOAD]),
    "cap_boundary_rejected_by_limit_1024": gcm_seed(0x09, 43, [SERVICE_ACCEPT_PAYLOAD]),
    "counter_boundary_k0": gcm_seed(0x04, 44, [b"\x02\x00\x00\x00\x00"], k=0),
    "counter_boundary_k3": gcm_seed(0x04, 45, [b"\x02\x00\x00\x00\x00"], k=3),
    "mutation_length_field_byte3": gcm_seed(0x40, 46, [EXT_INFO_PAYLOAD], mut_idx=3, xor=0x10),
    "mutation_body_and_forged_padding_3": gcm_seed(0x40, 47, [EXT_INFO_PAYLOAD], mut_idx=9, xor=0x01, forged=3),
    "mutation_tag_and_forged_padding_eats_body": gcm_seed(0x40, 48, [SERVICE_ACCEPT_PAYLOAD], mut_idx=51, xor=0x80, forged=32),
    "limit_16_too_large": gcm_seed(0x02, 49, [SERVICE_ACCEPT_PAYLOAD], fuzz_len=b"\x00\x00\x00\x10"),
    "fuzz_limit_0_and_raw_stream": gcm_seed(0xC3, 50, [], limit=0) + b"\x00\x00\x00\x10" + lcg_bytes(32, 51),
    "chunked_list_schedule": gcm_seed(0x00, 52, [lcg_bytes(100, 5), lcg_bytes(3, 6), lcg_bytes(300, 7)], sched=b"\x01\x05\x07\x40"),
}
for name, data in GCM.items():
    write("tcp_gcm_packets", name, data)

# ---------------------------------------------------------------------------
# tcp_handshake: rng seed 8, server secret 32, host seed 32, flags u8,
# ident u8 (0-4 v2.0, 5 v1.99, 6 LF-only, 7 v1.5), software u8,
# n_prelude u8 (mod 3) + indices, n_pre u8 (mod 3) + msgs, server lists,
# guess u8, n_before_reply u8 + msgs, reply u8 (mod 24), n_before_newkeys
# u8 + msgs, send_newkeys u8 (0 = no), n_protected u8 (mod 5) + prots,
# tamper u8 (+ idx, off, xor), trust u8 (mod 6: 0/1 untrusted), n_sched.
#
# flags: bit0 ext-info-c, bit1 CLEAR = offer strict, bits 4-5 chunk mode,
# bit6 do not prepend curve25519, bit7 raw fuzz server lists; low nibble
# 0x8 = tiny pre-KEX budget (3 packets), 0xC = entropy/overflow checks.
# msg: kind u8 mod 11 (0/1 ignore len+bytes, 2 debug, 3 unimplemented u32,
# 4 disconnect code+desc, 5 other number, 6 kexinit again, 7 newkeys/reply,
# 8 malformed idx (ignore, debug, unimplemented, disconnect, newkeys,
# kexinit), 9 empty payload, 10 bad frame).
# prot: kind u8 mod 13 (0/1 ext_info n pairs, 2 too many, 3-5 service
# accept idx (0 = ssh-userauth), 6 disconnect, 7 kexinit, 8 skip, 9 other,
# 10 empty, 11 malformed idx (ignore, debug, disconnect, ext_info,
# service_accept), 12 bad clear length).
# ---------------------------------------------------------------------------


def hs_seed(flags, ident=0, software=1, prelude=(), pre=b"\x00", server=None, guess=0, before_reply=b"\x00",
            reply=b"\x00", before_newkeys=b"\x00", newkeys=1, prot=b"\x00", tamper=b"\x00", trust=5, sched=b"", seed=1):
    out = lcg_bytes(8, seed) + lcg_bytes(32, seed + 100) + lcg_bytes(32, seed + 200)
    out += u8(flags) + u8(ident) + u8(software)
    out += u8(len(prelude)) + bytes(prelude)
    out += pre
    if server is None:
        server = lists(seed + 300, (7, 9), (0,), (0,), (0,), (0,), (0,), (0,), (0,))
    out += server
    out += u8(guess) + before_reply + reply + before_newkeys + u8(newkeys) + prot + tamper + u8(trust)
    out += u8(len(sched)) + sched
    return out


IGNORE = u8(0) + u8(3) + b"abc"
DEBUG = u8(2) + u8(1) + u8(2) + b"hi"
UNIMPL = u8(3) + u32be(7)
DISCONNECT_2 = u8(4) + u8(2) + u8(1)
OTHER_50 = u8(5) + u8(1)  # OTHER_NUMBERS[1] == 50
KEXINIT_AGAIN = u8(6)
MAL_IGNORE = u8(8) + u8(0)
MAL_DISCONNECT = u8(8) + u8(3)
MAL_NEWKEYS = u8(8) + u8(4)
EMPTY_MSG = u8(9)
BAD_FRAME = u8(10)
PROT_MAL_EXT_INFO = u8(11) + u8(3)
PROT_MAL_SERVICE_ACCEPT = u8(11) + u8(4)
PROT_BAD_LENGTH = u8(12)
EXT_INFO_SIG_ALGS = u8(0) + u8(1) + u8(0) + u8(0)  # one pair: server-sig-algs = ssh-ed25519
EXT_INFO_BAD_SIG_ALGS = u8(0) + u8(1) + u8(0) + u8(2)  # server-sig-algs = a,,b
SERVICE_USERAUTH = u8(3) + u8(0)
SERVICE_CONNECTION = u8(3) + u8(1)
PROT_KEXINIT = u8(7)
PROT_DISCONNECT = u8(6) + u8(11) + u8(1)

STRICT_SERVER = lists(1, (7, 9), **AEAD_SERVER)  # ext-info-s, kex-strict-s-v00 (+ curve25519 prepended)
STANDARD_STRICT_SERVER = lists(2, (11,), **AEAD_SERVER)  # kex-strict-s
PLAIN_SERVER = lists(3, (), **AEAD_SERVER)
# dh-group14 first, curve25519 second, flag set; used with flag bit6 so the
# harness does not prepend curve25519 (guess wrong).
GUESS_SERVER = lists(4, (3, 0, 7, 9), flags=1, **AEAD_SERVER)

HANDSHAKE = {
    "completed_strict_ext_info": hs_seed(0x01, server=STRICT_SERVER, prot=u8(2) + EXT_INFO_SIG_ALGS + SERVICE_USERAUTH, seed=1),
    "completed_standard_strict": hs_seed(0x01, server=STANDARD_STRICT_SERVER, prot=u8(1) + SERVICE_USERAUTH, seed=2),
    "completed_non_strict_lf_only_1_99": hs_seed(0x00, ident=5, server=PLAIN_SERVER, pre=u8(1) + IGNORE, prot=u8(1) + SERVICE_USERAUTH, seed=3),
    "wrong_pin_no_newkeys": hs_seed(0x01, server=STRICT_SERVER, trust=0, seed=4),
    "no_policy_untrusted": hs_seed(0x01, server=PLAIN_SERVER, trust=1, seed=5),
    "bad_signature_bit_flip": hs_seed(0x01, server=STRICT_SERVER, reply=u8(12) + u8(0x25), seed=6),
    "signature_over_wrong_hash": hs_seed(0x01, server=STRICT_SERVER, reply=u8(13), seed=7),
    "signature_alg_rsa": hs_seed(0x01, server=PLAIN_SERVER, reply=u8(14), seed=8),
    "signature_trailing_byte": hs_seed(0x01, server=PLAIN_SERVER, reply=u8(15), seed=31),
    "host_key_rsa": hs_seed(0x01, server=PLAIN_SERVER, reply=u8(17), seed=9),
    "host_key_31_bytes": hs_seed(0x01, server=PLAIN_SERVER, reply=u8(18), seed=32),
    "all_zero_qs": hs_seed(0x01, server=STRICT_SERVER, reply=u8(20), seed=10),
    "qs_31_bytes": hs_seed(0x01, server=STRICT_SERVER, reply=u8(21), seed=11),
    "reply_trailing_byte": hs_seed(0x01, server=STRICT_SERVER, reply=u8(22), seed=33),
    "guess_wrong_discard": hs_seed(0x41, server=GUESS_SERVER, guess=0x03, prot=u8(1) + SERVICE_USERAUTH, seed=12),
    "guess_wrong_no_guess_packet": hs_seed(0x41, server=GUESS_SERVER, guess=0x00, seed=13),
    "guess_wrong_non_strict_discard_32": hs_seed(0x43, server=lists(6, (3, 0), flags=1, **AEAD_SERVER), guess=0x05, prot=u8(1) + SERVICE_USERAUTH, seed=34),
    "ignore_before_kexinit_strict": hs_seed(0x01, server=STRICT_SERVER, pre=u8(1) + IGNORE, seed=14),
    "debug_during_kex_strict": hs_seed(0x01, server=STRICT_SERVER, before_reply=u8(1) + DEBUG, seed=15),
    "unimplemented_before_newkeys_non_strict": hs_seed(0x00, server=PLAIN_SERVER, before_newkeys=u8(1) + UNIMPL, prot=u8(1) + SERVICE_USERAUTH, seed=16),
    "disconnect_before_kexinit": hs_seed(0x01, server=PLAIN_SERVER, pre=u8(1) + DISCONNECT_2, seed=17),
    "second_kexinit_during_kex": hs_seed(0x01, server=STRICT_SERVER, before_reply=u8(1) + KEXINIT_AGAIN, seed=18),
    "rekey_after_newkeys": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + PROT_KEXINIT, seed=19),
    "wrong_service_name": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + SERVICE_CONNECTION, seed=20),
    "tampered_protected_byte": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + SERVICE_USERAUTH, tamper=u8(1) + u8(0) + u8(5) + u8(0x40), seed=21),
    "protected_disconnect": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + PROT_DISCONNECT, seed=22),
    "ext_info_invalid_server_sig_algs": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + EXT_INFO_BAD_SIG_ALGS, seed=23),
    "ext_info_too_many": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + u8(2), seed=24),
    "eof_awaiting_newkeys": hs_seed(0x01, server=STRICT_SERVER, newkeys=0, seed=25),
    "negotiation_failed_no_kex": hs_seed(0x41, server=lists(5, (3, 7), **AEAD_SERVER), seed=26),
    "unsupported_version_1_5": hs_seed(0x01, ident=7, server=PLAIN_SERVER, seed=27),
    "entropy_failure": hs_seed(0x0C, server=PLAIN_SERVER, seed=28),
    "chunked_list_completed": hs_seed(0x01, server=STRICT_SERVER, prot=u8(2) + EXT_INFO_SIG_ALGS + SERVICE_USERAUTH, sched=b"\x01\x03\x07\x0b\x40", seed=29),
    "prelude_two_lines_unexpected_50_before_kexinit": hs_seed(0x01, prelude=(0, 1), server=PLAIN_SERVER, pre=u8(1) + OTHER_50, seed=30),
    "malformed_ignore_non_strict": hs_seed(0x02, server=PLAIN_SERVER, before_reply=u8(1) + MAL_IGNORE, seed=35),
    "malformed_disconnect_strict_decodes_first": hs_seed(0x01, server=STRICT_SERVER, before_reply=u8(1) + MAL_DISCONNECT, seed=36),
    "malformed_newkeys_after_trust": hs_seed(0x01, server=STRICT_SERVER, before_newkeys=u8(1) + MAL_NEWKEYS, seed=37),
    "empty_unprotected_payload": hs_seed(0x01, server=PLAIN_SERVER, pre=u8(1) + EMPTY_MSG, seed=38),
    "bad_frame_before_reply": hs_seed(0x01, server=STRICT_SERVER, before_reply=u8(1) + BAD_FRAME, seed=39),
    "tiny_budget_completes_in_three": hs_seed(0x08, server=PLAIN_SERVER, prot=u8(1) + SERVICE_USERAUTH, seed=40),
    "tiny_budget_fourth_packet_refused": hs_seed(0x08, server=PLAIN_SERVER, before_reply=u8(1) + IGNORE, seed=41),
    "protected_malformed_ext_info": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + PROT_MAL_EXT_INFO, seed=42),
    "protected_malformed_service_accept": hs_seed(0x01, server=STRICT_SERVER, prot=u8(1) + PROT_MAL_SERVICE_ACCEPT, seed=43),
    "protected_misaligned_length": hs_seed(0x01, server=STRICT_SERVER, prot=u8(2) + EXT_INFO_SIG_ALGS + PROT_BAD_LENGTH, seed=44),
}
for name, data in HANDSHAKE.items():
    write("tcp_handshake", name, data)

# ---------------------------------------------------------------------------
# handshake_report_json: sel u8, flags u8, port u16, pin 32, host len + host,
# rest = server bytes for the attached HandshakeReport.
# ---------------------------------------------------------------------------


def rj_seed(sel, flags, port, host, server=b"", pin_seed=60):
    return u8(sel) + u8(flags) + u16be(port) + lcg_bytes(32, pin_seed) + u8(len(host)) + host + server


SERVER_IDENT = b"SSH-2.0-OpenSSH_9.6 Ubuntu\r\n"
SERVER_KEXINIT = (
    u8(20)
    + lcg_bytes(16, 70)
    + name_list([b"curve25519-sha256", b"ext-info-s", b"kex-strict-s"])
    + name_list([b"ssh-ed25519"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"none"])
    + name_list([b"none"])
    + name_list([])
    + name_list([])
    + u8(0)
    + u32be(0)
)


def frame(payload):
    base = 5 + len(payload)
    pad = 8 - (base % 8)
    if pad < 4:
        pad += 8
    return u32be(1 + len(payload) + pad) + u8(pad) + payload + b"\x5a" * pad


REPORT_JSON = {
    "complete_no_handshake": rj_seed(0, 0x06, 22, b"example.org"),
    "connect_failed_ipv6_host": rj_seed(15, 0x00, 2222, b"::1"),
    "not_started_with_elapsed": rj_seed(16, 0x04, 22, b"h"),
    "eof_after_ident_with_report": rj_seed(10, 0x0B, 22, b"srv", SERVER_IDENT),
    # sel 37: 37 % 17 == 3 (NegotiationFailed), (37 >> 5) % 6 == 1 (NoCommonHostKey).
    "negotiation_failed_report": rj_seed(37, 0x03, 22, b"srv", SERVER_IDENT + frame(SERVER_KEXINIT)),
    "unexpected_message_report": rj_seed(8, 0x0F, 8022, b"a.b.c", b"banner\r\n" + SERVER_IDENT + frame(u8(2) + string(b"x")) + frame(u8(50) + b"\x00")),
    "io_error_timed_out": rj_seed(14, 0x07, 22, b"host-1"),
    "strict_violation_prelude_report": rj_seed(4, 0x0B, 22, b"x", b"line one\r\n" + SERVER_IDENT + frame(u8(2) + string(b"")) + frame(SERVER_KEXINIT)),
    # sel 23: 23 % 17 == 6 (ServerDisconnected, reason 23 % 20 == 3).
    "server_disconnected_reason_3": rj_seed(23, 0x03, 22, b"s", SERVER_IDENT + frame(u8(1) + u32be(3) + string(b"bye") + string(b""))),
    "junk_server_bytes": rj_seed(11, 0x0B, 22, b"s", lcg_bytes(200, 71)),
}
for name, data in REPORT_JSON.items():
    write("handshake_report_json", name, data)

# ---------------------------------------------------------------------------
# tcp_probe / tcp_observer raw seeds with the standard strict marker names.
# Layout: byte0 (0x40: EOF, raw), n_sched u8 + sizes, k u16, raw stream.
# ---------------------------------------------------------------------------

PROBE_KEXINIT = (
    u8(20)
    + bytes(range(16))
    + name_list([b"curve25519-sha256", b"kex-strict-s", b"ext-info-s", b"kex-strict-s-v00@openssh.com"])
    + name_list([b"ssh-ed25519"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"none"])
    + name_list([b"none"])
    + name_list([])
    + name_list([])
    + u8(0)
    + u32be(0)
)
write(
    "tcp_probe",
    "raw_standard_strict_marker",
    u8(0x40) + u8(2) + b"\x03\x11" + u16be(5) + b"SSH-2.0-Fixture_2\r\n" + frame(PROBE_KEXINIT),
)
OBSERVER_KEXINIT = (
    u8(20)
    + bytes(range(16))
    + name_list([b"curve25519-sha256", b"ext-info-c", b"kex-strict-c-v00@openssh.com", b"kex-strict-c"])
    + name_list([b"ssh-ed25519"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"aes128-gcm@openssh.com"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"hmac-sha2-256"])
    + name_list([b"none"])
    + name_list([b"none"])
    + name_list([])
    + name_list([])
    + u8(0)
    + u32be(0)
)
write(
    "tcp_observer",
    "raw_client_both_strict_spellings",
    u8(0x40) + u8(2) + b"\x03\x11" + u16be(5) + b"SSH-2.0-tatami_0.1.0\r\n" + frame(OBSERVER_KEXINIT),
)

print("seeds written under", HERE)
