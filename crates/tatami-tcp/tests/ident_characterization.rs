//! Characterization fixtures for TCP identification handling.
//!
//! Written before the identification syntax was moved into `tatami-wire`.
//! Each case records behaviour the round-one/round-two code exhibited so the
//! refactor can be checked against it. Expected values were derived by hand
//! from RFC 4253 §4.2 and the documented compatibility policy, not by
//! running the code.

use tatami_tcp::ident::{
    IdentAnomaly, IdentError, IdentLimits, IdentStep, IdentificationReader, InvalidIdentification,
    InvalidLocalIdentification, LineTerminator, VersionSupport, build_identification,
    is_version_token,
};

fn reader() -> IdentificationReader {
    IdentificationReader::new(IdentLimits::default())
}

struct Accepted {
    input: &'static [u8],
    line: &'static [u8],
    terminator: LineTerminator,
    protocol: &'static [u8],
    software: &'static [u8],
    comments: Option<&'static [u8]>,
    support: VersionSupport,
    anomalies: &'static [IdentAnomaly],
}

const ACCEPTED: &[Accepted] = &[
    Accepted {
        input: b"SSH-2.0-OpenSSH_9.6\r\n",
        line: b"SSH-2.0-OpenSSH_9.6",
        terminator: LineTerminator::CrLf,
        protocol: b"2.0",
        software: b"OpenSSH_9.6",
        comments: None,
        support: VersionSupport::Ssh2,
        anomalies: &[],
    },
    Accepted {
        input: b"SSH-2.0-x y z\r\n",
        line: b"SSH-2.0-x y z",
        terminator: LineTerminator::CrLf,
        protocol: b"2.0",
        software: b"x",
        comments: Some(b"y z"),
        support: VersionSupport::Ssh2,
        anomalies: &[],
    },
    // Present-but-empty comment (trailing space) stays distinguishable.
    Accepted {
        input: b"SSH-2.0-x \r\n",
        line: b"SSH-2.0-x ",
        terminator: LineTerminator::CrLf,
        protocol: b"2.0",
        software: b"x",
        comments: Some(b""),
        support: VersionSupport::Ssh2,
        anomalies: &[],
    },
    // Comments are raw bytes: high bytes and tabs are preserved, not
    // rejected, not lossily decoded.
    Accepted {
        input: b"SSH-2.0-x \xc3\xa9\t\xff\r\n",
        line: b"SSH-2.0-x \xc3\xa9\t\xff",
        terminator: LineTerminator::CrLf,
        protocol: b"2.0",
        software: b"x",
        comments: Some(b"\xc3\xa9\t\xff"),
        support: VersionSupport::Ssh2,
        anomalies: &[],
    },
    // Software version may contain any printable ASCII except space and '-'.
    Accepted {
        input: b"SSH-2.0-a.b_c/d@e:f!\r\n",
        line: b"SSH-2.0-a.b_c/d@e:f!",
        terminator: LineTerminator::CrLf,
        protocol: b"2.0",
        software: b"a.b_c/d@e:f!",
        comments: None,
        support: VersionSupport::Ssh2,
        anomalies: &[],
    },
    Accepted {
        input: b"SSH-1.99-Compat\n",
        line: b"SSH-1.99-Compat",
        terminator: LineTerminator::Lf,
        protocol: b"1.99",
        software: b"Compat",
        comments: None,
        support: VersionSupport::Ssh2Compatibility,
        anomalies: &[
            IdentAnomaly::LfOnlyTerminator,
            IdentAnomaly::CompatibilityVersion,
        ],
    },
];

#[test]
fn accepted_identifications() {
    for case in ACCEPTED {
        let mut r = reader();
        match r.feed(case.input) {
            Ok(IdentStep::Identification { ident, consumed }) => {
                assert_eq!(consumed, case.input.len(), "{:?}", case.input);
                assert_eq!(ident.line, case.line);
                assert_eq!(ident.terminator, case.terminator);
                assert_eq!(ident.protocol_version, case.protocol);
                assert_eq!(ident.software_version, case.software);
                assert_eq!(ident.comments, case.comments, "{:?}", case.input);
                assert_eq!(ident.support, case.support);
                let a: Vec<IdentAnomaly> = ident.anomalies().collect();
                assert_eq!(a, case.anomalies);
            }
            other => panic!("{:?}: {other:?}", case.input),
        }
    }
}

const REJECTED: &[(&[u8], IdentError)] = &[
    (b"SSH-1.5-old\r\n", IdentError::UnsupportedVersion),
    (b"SSH-1.0-older\r\n", IdentError::UnsupportedVersion),
    (b"SSH-3.0-future\r\n", IdentError::UnsupportedVersion),
    (b"SSH-2.1-almost\r\n", IdentError::UnsupportedVersion),
    (
        b"SSH-2.0\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::MissingSeparator),
    ),
    (
        b"SSH--x\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadProtocolVersion),
    ),
    (
        b"SSH-2 0-x\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadProtocolVersion),
    ),
    (
        b"SSH-2.0-\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadSoftwareVersion),
    ),
    (
        b"SSH-2.0- comment\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadSoftwareVersion),
    ),
    (
        b"SSH-2.0-a\tb\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadSoftwareVersion),
    ),
    (
        b"SSH-2.0-a\xffb\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::BadSoftwareVersion),
    ),
    (
        b"SSH-2.0-a\rb\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::ControlCharacter),
    ),
    (
        b"SSH-2.0-a\x00b\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::ControlCharacter),
    ),
    (
        b"SSH-2.0-a b\rc\r\n",
        IdentError::InvalidIdentification(InvalidIdentification::ControlCharacter),
    ),
];

#[test]
fn rejected_identifications() {
    for (input, expected) in REJECTED {
        let mut r = reader();
        assert_eq!(r.feed(input), Err(*expected), "{input:?}");
    }
}

#[test]
fn version_policy_is_checked_after_syntax() {
    // A bad software version with an unsupported protocol version reports the
    // syntax error, not the policy error.
    let mut r = reader();
    assert_eq!(
        r.feed(b"SSH-1.5-\r\n"),
        Err(IdentError::InvalidIdentification(
            InvalidIdentification::BadSoftwareVersion
        ))
    );
}

#[test]
fn length_boundaries_include_the_observed_terminator() {
    // 253 content + CRLF = 255: accepted.
    let mut line = vec![b'x'; 255];
    line[..8].copy_from_slice(b"SSH-2.0-");
    line[253] = b'\r';
    line[254] = b'\n';
    assert!(matches!(
        reader().feed(&line),
        Ok(IdentStep::Identification { consumed: 255, .. })
    ));

    // 254 content + LF = 255: accepted (LF-only compatibility).
    let mut lf = vec![b'x'; 255];
    lf[..8].copy_from_slice(b"SSH-2.0-");
    lf[254] = b'\n';
    match reader().feed(&lf) {
        Ok(IdentStep::Identification { ident, consumed }) => {
            assert_eq!(consumed, 255);
            assert_eq!(ident.line.len(), 254);
            assert_eq!(ident.terminator, LineTerminator::Lf);
        }
        other => panic!("{other:?}"),
    }

    // 254 content + CRLF = 256: rejected.
    let mut long = vec![b'x'; 256];
    long[..8].copy_from_slice(b"SSH-2.0-");
    long[254] = b'\r';
    long[255] = b'\n';
    assert_eq!(reader().feed(&long), Err(IdentError::IdentificationTooLong));

    // 255 bytes without a terminator: rejected without waiting.
    assert_eq!(
        reader().feed(&long[..255]),
        Err(IdentError::IdentificationTooLong)
    );
    // 254 bytes without a terminator: still waiting (an LF could complete it).
    assert_eq!(reader().feed(&long[..254]), Ok(IdentStep::NeedMore));
}

#[test]
fn prelude_and_suffix_handling() {
    let mut r = reader();
    let mut buf: &[u8] = b"Banner\r\n\nSSH-2.0-s\r\n\x00\x00\x00\x0c";
    match r.feed(buf).unwrap() {
        IdentStep::Prelude {
            line,
            terminator: LineTerminator::CrLf,
            consumed: 8,
        } => {
            assert_eq!(line, b"Banner");
            buf = &buf[8..];
        }
        other => panic!("{other:?}"),
    }
    // An empty prelude line (bare LF) is a valid prelude line.
    match r.feed(buf).unwrap() {
        IdentStep::Prelude {
            line,
            terminator: LineTerminator::Lf,
            consumed: 1,
        } => {
            assert_eq!(line, b"");
            buf = &buf[1..];
        }
        other => panic!("{other:?}"),
    }
    match r.feed(buf).unwrap() {
        IdentStep::Identification { consumed, .. } => buf = &buf[consumed..],
        other => panic!("{other:?}"),
    }
    assert_eq!(buf, b"\x00\x00\x00\x0c");
    assert_eq!(r.prelude_lines(), 2);
}

#[test]
fn outgoing_identification_contract() {
    assert_eq!(
        build_identification("tatami_0.1.0").unwrap(),
        b"SSH-2.0-tatami_0.1.0\r\n"
    );
    assert_eq!(
        build_identification("tatami_observer_0.1.0").unwrap(),
        b"SSH-2.0-tatami_observer_0.1.0\r\n"
    );
    for bad in ["", "a b", "a-b", "a\tb", "é", "a\r"] {
        assert_eq!(
            build_identification(bad),
            Err(InvalidLocalIdentification::BadSoftwareVersion),
            "{bad:?}"
        );
    }
    let ok = "x".repeat(245);
    assert_eq!(build_identification(&ok).unwrap().len(), 255);
    assert_eq!(
        build_identification(&"x".repeat(246)),
        Err(InvalidLocalIdentification::TooLong { len: 256 })
    );
}

#[test]
fn token_rules() {
    for ok in [
        "2.0",
        "1.99",
        "OpenSSH_9.6p1",
        "a",
        "!\"#$%&'()*+,./:;<=>?@[\\]^_`{|}~",
    ] {
        assert!(is_version_token(ok.as_bytes()), "{ok:?}");
    }
    for bad in ["", "-", "a-b", " ", "a b", "\t", "\x7f", "é"] {
        assert!(!is_version_token(bad.as_bytes()), "{bad:?}");
    }
}
