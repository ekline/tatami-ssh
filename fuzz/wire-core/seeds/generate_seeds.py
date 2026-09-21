#!/usr/bin/env python3
"""Regenerates the committed seed corpora for the wire-core fuzz targets.

Run from anywhere: `python3 fuzz/wire-core/seeds/generate_seeds.py`.
Each seed is written as raw bytes in exactly the layout the target's
`fuzz_target!` input expects (documented at the top of each target file).
The script is deterministic; re-running it must not change any file.
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent


def u8(v):
    return bytes([v & 0xFF])


def u16be(v):
    return v.to_bytes(2, "big")


def u32be(v):
    return v.to_bytes(4, "big")


def u32le(v):
    return v.to_bytes(4, "little")


def u64le(v):
    return v.to_bytes(8, "little")


def string(b):
    return u32be(len(b)) + b


def name_list(names):
    return string(b",".join(names))


def lcg_bytes(n, seed):
    """Deterministic filler for structured-path seeds."""
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
# identification_content: raw identification content, no terminator.
# ---------------------------------------------------------------------------

IDENT = {
    "openssh": b"SSH-2.0-OpenSSH_9.6",
    "compat": b"SSH-1.99-Compat c",
    "openssh_ident_comments": b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
    "tatami": b"SSH-2.0-tatami_0.1.0",
    "comments_empty": b"SSH-2.0-x ",
    "comments_with_dash_and_spaces": b"SSH-2.0-tatami_0.1.0 hello-world  two spaces",
    "ssh1_version": b"SSH-1.5-OpenSSH_3.9p1",
    "future_version": b"SSH-3.0-future",
    "missing_prefix_lowercase": b"ssh-2.0-x",
    "missing_separator": b"SSH-2.0x",
    "empty_proto": b"SSH--x",
    "empty_software": b"SSH-2.0-",
    "empty_software_with_comments": b"SSH-2.0- comments",
    "bad_software_dash": b"SSH-2.0-open-ssh",
    "bad_proto_space": b"SSH-2 0-x",
    "control_cr": b"SSH-2.0-x\r",
    "control_lf_in_comments": b"SSH-2.0-x a\nb",
    "nul_in_comments": b"SSH-2.0-x a\x00b",
    "high_bytes_comments": b"SSH-2.0-x \xff\xfe\x80",
    "high_byte_in_software": b"SSH-2.0-\xc3\xa9",
    "prefix_only": b"SSH-",
    "short": b"SS",
}
for name, data in IDENT.items():
    write("identification_content", name, data)

# ---------------------------------------------------------------------------
# identification_encode:
#   mode:u8, plen:u16be, proto, slen:u16be, software, clen:u16be, comments,
#   cap:u16be, fill:u8
# mode bits: 0 sanitize proto, 1 sanitize software, 2 comments present,
# 3 strip CR/LF/NUL from comments; bits 4-5: capacity 0 arbitrary,
# 1 exact, 2 needed-1, 3 needed+7.
# ---------------------------------------------------------------------------


def enc_seed(mode, proto, software, comments, cap, fill=0xA5):
    return (
        u8(mode)
        + u16be(len(proto))
        + proto
        + u16be(len(software))
        + software
        + u16be(len(comments))
        + comments
        + u16be(cap)
        + u8(fill)
    )


ENCODE = {
    "tatami_exact_capacity": enc_seed(0x10, b"2.0", b"tatami_0.1.0", b"", 0),
    "openssh_comments_exact": enc_seed(0x14, b"2.0", b"OpenSSH_9.6", b"Debian-4", 0),
    "openssh_comments_short_by_one": enc_seed(0x24, b"2.0", b"OpenSSH_9.6", b"Debian-4", 0),
    "openssh_comments_roomy": enc_seed(0x34, b"2.0", b"OpenSSH_9.6", b"Debian-4", 0),
    "empty_comments_present": enc_seed(0x04, b"2.0", b"x", b"", 20),
    "no_comments_arbitrary_cap": enc_seed(0x00, b"1.99", b"Compat", b"ignored", 64),
    "bad_proto_dash": enc_seed(0x00, b"2-0", b"x", b"", 50),
    "bad_proto_empty": enc_seed(0x00, b"", b"x", b"", 50),
    "bad_software_space": enc_seed(0x00, b"2.0", b"a b", b"", 50),
    "comments_with_lf": enc_seed(0x04, b"2.0", b"x", b"a\nb", 50),
    "comments_with_nul_stripped": enc_seed(0x0C, b"2.0", b"x", b"a\x00b", 50),
    "zero_capacity": enc_seed(0x00, b"2.0", b"x", b"", 0),
    "sanitized_junk_tokens": enc_seed(0x17, lcg_bytes(40, 1), lcg_bytes(60, 2), lcg_bytes(30, 3), 0),
    "long_fields_600": enc_seed(0x03, lcg_bytes(300, 4), lcg_bytes(300, 5), b"", 600),
}
for name, data in ENCODE.items():
    write("identification_encode", name, data)

# ---------------------------------------------------------------------------
# wire_primitives: ilen:u16be, input, cap:u16be, ops...
# ---------------------------------------------------------------------------

R_U8, R_BOOL, R_U32, R_U64, R_STRING, R_NAMELIST, R_BYTES, FINISH = range(8)
W_U8, W_BOOL, W_U32, W_U64, W_STRING, W_NAMELIST, W_BYTES = range(8, 15)


def prim_seed(inp, cap, ops):
    return u16be(len(inp)) + inp + u16be(cap) + b"".join(ops)


def op(code, *args):
    return u8(code) + b"".join(args)


def op_names(mask, names):
    out = u8(W_NAMELIST) + u8(len(names)) + u8(mask)
    for n in names:
        out += u8(len(n)) + n
    return out


PRIMS = {
    "read_all_fixed": prim_seed(
        b"\x01" + u32be(1) + bytes(range(2, 10)) + string(b"abc"),
        0,
        [op(R_U8), op(R_U32), op(R_U64), op(R_STRING), op(FINISH)],
    ),
    "name_list_ok_and_iterate": prim_seed(
        name_list([b"zlib", b"none", b"a"]), 0, [op(R_NAMELIST), op(FINISH)]
    ),
    "name_list_markers": prim_seed(
        name_list([b"ext-info-s", b"kex-strict-s-v00@openssh.com", b"made-up"]),
        0,
        [op(R_NAMELIST), op(FINISH)],
    ),
    "name_list_standard_strict_markers": prim_seed(
        name_list([b"curve25519-sha256", b"kex-strict-c", b"kex-strict-s", b"ext-info-c"]),
        0,
        [op(R_NAMELIST), op(FINISH)],
    ),
    "name_list_empty": prim_seed(u32be(0), 0, [op(R_NAMELIST), op(FINISH)]),
    "name_list_double_comma": prim_seed(
        string(b"a,,b"), 0, [op(R_NAMELIST), op(R_STRING), op(FINISH)]
    ),
    "name_list_trailing_comma": prim_seed(string(b"a,"), 0, [op(R_NAMELIST)]),
    "name_list_leading_comma": prim_seed(string(b",a"), 0, [op(R_NAMELIST)]),
    "name_list_space": prim_seed(string(b"a b"), 0, [op(R_NAMELIST)]),
    "name_list_utf8": prim_seed(string(b"ab\xc3\xa9"), 0, [op(R_NAMELIST)]),
    "string_length_overflow": prim_seed(
        u32be(9) + b"ab", 0, [op(R_STRING), op(R_U32), op(R_BYTES, u16be(2)), op(FINISH)]
    ),
    "string_huge_length": prim_seed(b"\xff\xff\xff\xff", 0, [op(R_STRING), op(R_NAMELIST)]),
    "string_truncated_prefix": prim_seed(b"\x00\x00\x00", 0, [op(R_STRING), op(R_NAMELIST)]),
    "truncated_u32_then_bytes": prim_seed(
        b"\x01\x02\x03", 0, [op(R_U32), op(R_U8), op(R_U8), op(R_U8), op(R_U32), op(FINISH)]
    ),
    "read_bytes_too_many": prim_seed(
        b"\x00\x01\x02\x03", 0, [op(R_BYTES, u16be(1024)), op(R_BYTES, u16be(4)), op(FINISH)]
    ),
    "bool_noncanonical": prim_seed(
        b"\xff\x00\x02", 0, [op(R_BOOL), op(R_BOOL), op(R_BOOL), op(FINISH), op(R_BOOL)]
    ),
    "writer_sequence": prim_seed(
        b"",
        16,
        [
            op(W_U8, u8(7)),
            op(W_BOOL, u8(1)),
            op(W_BOOL, u8(0)),
            op(W_U32, u32le(0x01020304)),
            op(W_STRING, u16be(2), b"hi"),
            op(W_U32, u32le(1)),
        ],
    ),
    "writer_name_list": prim_seed(
        b"",
        32,
        [
            op_names(0, [b"a", b"bc"]),
            op_names(0, []),
            op_names(0, [b"ok", b"bad,name"]),
            op_names(0, [b""]),
        ],
    ),
    "writer_name_list_sanitized": prim_seed(
        b"", 64, [op_names(0x07, [lcg_bytes(5, 7), lcg_bytes(9, 8), lcg_bytes(3, 9)])]
    ),
    "writer_name_list_second_invalid": prim_seed(
        b"", 64, [op_names(0x05, [b"fine", b"not ok", b"also bad"])]
    ),
    "writer_overflow_string": prim_seed(b"", 5, [op(W_STRING, u16be(3), b"abc")]),
    "writer_u64_then_full": prim_seed(
        b"", 8, [op(W_U64, u64le(0x0102030405060708)), op(W_U8, u8(1)), op(W_BYTES, u16be(0))]
    ),
    "writer_bytes_exact_fit": prim_seed(b"", 4, [op(W_BYTES, u16be(4), b"\xde\xad\xbe\xef")]),
    "mixed_read_write": prim_seed(
        string(b"none") + u32be(5),
        16,
        [op(R_NAMELIST), op(W_STRING, u16be(4), b"none"), op(R_U32), op(W_U32, u32le(5)), op(FINISH)],
    ),
}
for name, data in PRIMS.items():
    write("wire_primitives", name, data)

# ---------------------------------------------------------------------------
# wire_messages: sel:u8 then payload (sel < 0x80: raw payload to all
# decoders; sel >= 0x80: structured generation for message sel % 8).
# ---------------------------------------------------------------------------

RAW = b"\x00"
COOKIE = bytes(range(16))


def kexinit(lists, first=0, reserved=0, cookie=COOKIE):
    out = u8(20) + cookie
    for names in lists:
        out += name_list(names)
    return out + u8(first) + u32be(reserved)


CLIENT_LISTS = [
    [b"curve25519-sha256", b"ext-info-c", b"kex-strict-c-v00@openssh.com"],
    [b"ssh-ed25519", b"rsa-sha2-256"],
    [b"aes128-ctr", b"aes256-gcm@openssh.com"],
    [b"chacha20-poly1305@openssh.com"],
    [b"hmac-sha2-256"],
    [b"hmac-sha2-512-etm@openssh.com"],
    [b"none"],
    [b"zlib@openssh.com", b"none"],
    [],
    [],
]
# Both strict-KEX spellings on each side (draft-ietf-sshm-strict-kex-02 §3.1
# recommends offering both).
CLIENT_LISTS_STANDARD = [
    [b"curve25519-sha256", b"ext-info-c", b"kex-strict-c-v00@openssh.com", b"kex-strict-c"]
] + CLIENT_LISTS[1:]
SERVER_LISTS_STANDARD_ONLY = [
    [b"curve25519-sha256", b"kex-strict-s", b"ext-info-s"],
    [b"ssh-ed25519"],
    [b"aes128-gcm@openssh.com"],
    [b"aes128-gcm@openssh.com"],
    [b"hmac-sha2-256"],
    [b"hmac-sha2-256"],
    [b"none"],
    [b"none"],
    [],
    [],
]
SERVER_LISTS = [
    [b"curve25519-sha256", b"ext-info-s", b"kex-strict-s-v00@openssh.com"],
    [b"ssh-ed25519"],
    [b"aes256-gcm@openssh.com"],
    [b"aes128-ctr", b"aes256-ctr"],
    [b"hmac-sha2-512"],
    [b"hmac-sha2-256"],
    [b"none", b"zlib@openssh.com"],
    [b"none"],
    [b"en-US"],
    [],
]
EMPTY_REQUIRED = [
    [b"curve25519-sha256"],
    [b"ssh-ed25519"],
    [],
    [],
    [b"hmac-sha2-256"],
    [b"hmac-sha2-256"],
    [b"none"],
    [b"none"],
    [],
    [],
]
BAD_LIST = [[b"a,,b"]] + CLIENT_LISTS[1:]

server = kexinit(SERVER_LISTS, first=1)
open_session = (
    u8(90) + string(b"session") + u32be(0) + u32be(0x200000) + u32be(0x8000)
)
open_unknown = (
    u8(90) + string(b"x@example") + u32be(5) + u32be(1) + u32be(2) + b"\xaa\xbb\xcc\xdd\xee"
)
confirmation = u8(91) + u32be(3) + u32be(9) + u32be(0x100) + u32be(0x40) + b"\x01\x02"
failure_200 = u8(92) + u32be(7) + u32be(200) + string(b"no") + string(b"")

MESSAGES = {
    "empty_payload": RAW,
    "kexinit_client_markers": RAW + kexinit(CLIENT_LISTS),
    "kexinit_server_markers": RAW + server,
    "kexinit_client_both_strict_spellings": RAW + kexinit(CLIENT_LISTS_STANDARD),
    "kexinit_server_standard_strict_only": RAW + kexinit(SERVER_LISTS_STANDARD_ONLY),
    # Near misses must stay methods: prefix, wrong version, wrong domain.
    "kexinit_strict_near_misses": RAW
    + kexinit(
        [[b"kex-strict", b"kex-strict-c-v01@openssh.com", b"kex-strict-c@openssh.com", b"kex-strict-cs"]]
        + CLIENT_LISTS[1:]
    ),
    "kexinit_truncated_reserved": RAW + server[:-4],
    "kexinit_truncated_mid_reserved": RAW + server[:-2],
    "kexinit_truncated_cookie": RAW + u8(20) + COOKIE[:7],
    "kexinit_nonzero_reserved": RAW + kexinit(SERVER_LISTS, reserved=0xDEADBEEF),
    "kexinit_noncanonical_first": RAW + kexinit(CLIENT_LISTS, first=0x7F),
    "kexinit_bad_name_list": RAW + kexinit(BAD_LIST),
    "kexinit_empty_required_lists": RAW + kexinit(EMPTY_REQUIRED),
    "kexinit_trailing_byte": RAW + server + b"\x00",
    "kexinit_wrong_number": RAW + u8(21) + server[1:],
    "disconnect_protocol_error": RAW + u8(1) + u32be(2) + string(b"bye") + string(b""),
    "disconnect_by_application_lang": RAW + u8(1) + u32be(11) + string(b"closing") + string(b"en"),
    "disconnect_unknown_code_trailing": RAW + u8(1) + u32be(999) + string(b"x") + string(b"en") + b"\xff",
    "disconnect_truncated_description": RAW + u8(1) + u32be(2) + u32be(9) + b"b",
    "ignore_data": RAW + u8(2) + string(b"\xde\xad"),
    "ignore_trailing": RAW + u8(2) + string(b"\xde\xad") + b"\x00",
    "unimplemented_42": RAW + u8(3) + u32be(42),
    "unimplemented_short": RAW + u8(3) + b"\x00\x00",
    "debug_noncanonical_bool": RAW + u8(4) + u8(5) + string(b"x") + string(b"en"),
    "debug_false_empty": RAW + u8(4) + u8(0) + string(b"") + string(b""),
    "open_session": RAW + open_session,
    "open_unknown_type_tail5": RAW + open_unknown,
    "open_truncated_window": RAW + u8(90) + string(b"s") + u32be(1) + b"\x00\x00",
    "open_type_length_overflow": RAW + u8(90) + u32be(9) + b"a",
    "open_confirmation_tail": RAW + confirmation,
    "open_confirmation_truncated": RAW + confirmation[:16],
    "open_failure_code200": RAW + failure_200,
    "open_failure_trailing": RAW + failure_200 + b"\x00",
    "open_failure_known_code": RAW + u8(92) + u32be(1) + u32be(3) + string(b"unknown type") + string(b"en"),
    "unknown_message_number": RAW + u8(50) + b"\x00" * 8,
}
for kind in range(8):
    MESSAGES[f"structured_{kind}"] = u8(0x80 + kind) + lcg_bytes(240, 100 + kind)
    MESSAGES[f"structured_{kind}_short"] = u8(0x88 + kind) + lcg_bytes(24, 200 + kind)
# Structured KEXINIT (kind 0): 16 cookie bytes then the marker bit mask; bits
# 4 and 5 add the standard strict names, 0x3F adds all six markers.
MESSAGES["structured_0_all_six_markers"] = u8(0x80) + lcg_bytes(16, 300) + u8(0x3F) + lcg_bytes(200, 301)
MESSAGES["structured_0_standard_strict_markers"] = u8(0x80) + lcg_bytes(16, 302) + u8(0x30) + lcg_bytes(200, 303)
for name, data in MESSAGES.items():
    write("wire_messages", name, data)

# ---------------------------------------------------------------------------
# wire_kex_codecs: sel:u8 then payload (sel < 0x80: raw payload to all six
# decoders and read_mpint; sel >= 0x80: structured case sel & 7).
# ---------------------------------------------------------------------------

ED25519_BLOB = string(b"ssh-ed25519") + string(bytes(range(32)))
SIG_BLOB = string(b"ssh-ed25519") + string(bytes(range(64)))
Q = bytes(range(0x40, 0x60))
ecdh_reply = u8(31) + string(ED25519_BLOB) + string(Q) + string(SIG_BLOB)


def ext_info(pairs):
    out = u8(7) + u32be(len(pairs))
    for n, v in pairs:
        out += string(n) + string(v)
    return out


KEX = {
    "empty_payload": RAW,
    # RFC 4251 §5 mpint examples as raw strings (also fed to the decoders).
    "mpint_rfc4251_zero": RAW + u32be(0),
    "mpint_rfc4251_positive": RAW + u32be(8) + bytes.fromhex("09a378f9b2e332a7"),
    "mpint_rfc4251_0x80": RAW + u32be(2) + bytes.fromhex("0080"),
    "mpint_rfc4251_neg_1234": RAW + u32be(2) + bytes.fromhex("edcc"),
    "mpint_rfc4251_neg_deadbeef": RAW + u32be(5) + bytes.fromhex("ff21524111"),
    "mpint_noncanonical_zero_byte": RAW + u32be(1) + b"\x00",
    "mpint_noncanonical_leading_zero": RAW + u32be(3) + bytes.fromhex("0009a3"),
    "mpint_noncanonical_leading_ff": RAW + u32be(3) + bytes.fromhex("ffedcc"),
    "mpint_minus_one": RAW + u32be(1) + b"\xff",
    "mpint_x25519_high_bit": RAW + u32be(33) + b"\x00\x80" + b"\x11" * 31,
    "mpint_length_overflow": RAW + u32be(3) + b"\x01",
    "ecdh_init_x25519": RAW + u8(30) + string(Q),
    "ecdh_init_empty_qc": RAW + u8(30) + u32be(0),
    "ecdh_init_trailing": RAW + u8(30) + string(Q) + b"\x00",
    "ecdh_init_truncated_prefix": RAW + u8(30) + b"\x00\x00",
    "ecdh_reply_ed25519": RAW + ecdh_reply,
    "ecdh_reply_truncated_ks": RAW + ecdh_reply[:5],
    "ecdh_reply_truncated_qs": RAW + ecdh_reply[: 5 + len(ED25519_BLOB) + 2],
    "ecdh_reply_truncated_signature": RAW + ecdh_reply[:-1],
    "ecdh_reply_trailing": RAW + ecdh_reply + b"\x00",
    "newkeys": RAW + u8(21),
    "newkeys_trailing": RAW + u8(21) + u8(0),
    "service_request_userauth": RAW + u8(5) + string(b"ssh-userauth"),
    "service_accept_userauth": RAW + u8(6) + string(b"ssh-userauth"),
    "service_accept_connection_trailing": RAW + u8(6) + string(b"ssh-connection") + b"\x00",
    "service_request_length_overflow": RAW + u8(5) + u32be(20) + b"ssh",
    "ext_info_server_sig_algs": RAW + ext_info([(b"server-sig-algs", b"ssh-ed25519,rsa-sha2-512")]),
    "ext_info_zero": RAW + ext_info([]),
    "ext_info_rfc8308_delay_compression": RAW
    + ext_info([(b"delay-compression", string(b"zlib,none") + string(b"zlib,none"))]),
    "ext_info_three_incl_unknown_binary": RAW
    + ext_info(
        [
            (b"publickey-hostbound@openssh.com", b"0"),
            (b"server-sig-algs", b"ssh-ed25519"),
            (b"ping@openssh.com", b"\x00\x01"),
        ]
    ),
    "ext_info_claims_two_has_one": RAW + u8(7) + u32be(2) + string(b"server-sig-algs") + string(b"") + b"\x00" * 8,
    "ext_info_count_mismatch": RAW + u8(7) + u32be(2) + string(b"elevation") + string(b"y"),
    "ext_info_huge_count_12_bytes": RAW + u8(7) + u32be(0xFFFFFFFF) + b"\x00" * 7,
    "ext_info_invalid_server_sig_algs": RAW + ext_info([(b"server-sig-algs", b"a,,b")]),
    "ext_info_truncated_value": RAW + u8(7) + u32be(1) + string(b"no-flow-control") + u32be(5) + b"p",
    "ext_info_trailing": RAW + ext_info([(b"elevation", b"d")]) + b"\x00",
    "unknown_number_50": RAW + u8(50) + b"\x00" * 8,
}
for kind in range(8):
    KEX[f"structured_{kind}"] = u8(0x80 + kind) + lcg_bytes(200, 400 + kind)
    KEX[f"structured_{kind}_short"] = u8(0x88 + kind) + lcg_bytes(20, 500 + kind)
for name, data in KEX.items():
    write("wire_kex_codecs", name, data)

print("seeds written under", HERE)
