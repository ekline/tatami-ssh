//! `SSH_MSG_KEXINIT` payload codec (RFC 4253 §7.1).
//!
//! [`KexInit::decode`] is purely syntactic: it checks the message number and
//! every field boundary and borrows each name list from the payload. It
//! attaches no meaning to any name and preserves unknown names verbatim.
//! Recognition of extension markers that are *not* key-exchange methods
//! lives separately in [`classify_kex_name`].
//!
//! # Validation policy
//!
//! - The `reserved` field is decoded and exposed, not required to be zero.
//!   RFC 4253 says it "MUST be sent as zero"; a consumer decides whether a
//!   nonzero value is an anomaly worth reporting.
//! - Bytes after the reserved field are rejected with
//!   [`MessageError::TrailingBytes`].
//! - Empty name lists are accepted for every field at this layer. RFC 4253
//!   requires non-empty algorithm lists but permits empty language lists;
//!   [`KexInit::empty_algorithm_lists`] reports which required lists are
//!   empty so callers can decide.

use crate::EncodeError;
use crate::error::MessageError;
use crate::message::{expect_message, field, finish};
use crate::msg;
use crate::namelist::NameList;
use crate::primitives::{Reader, Writer};

/// Length of the KEXINIT cookie in bytes.
pub const COOKIE_LEN: usize = 16;

/// Borrowed view of a decoded KEXINIT payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KexInit<'a> {
    /// The 16 random cookie bytes.
    pub cookie: &'a [u8; COOKIE_LEN],
    /// `kex_algorithms`, in the sender's preference order. May include
    /// extension markers; see [`classify_kex_name`].
    pub kex_algorithms: NameList<'a>,
    /// `server_host_key_algorithms`.
    pub server_host_key_algorithms: NameList<'a>,
    /// `encryption_algorithms_client_to_server`.
    pub encryption_client_to_server: NameList<'a>,
    /// `encryption_algorithms_server_to_client`.
    pub encryption_server_to_client: NameList<'a>,
    /// `mac_algorithms_client_to_server`.
    pub mac_client_to_server: NameList<'a>,
    /// `mac_algorithms_server_to_client`.
    pub mac_server_to_client: NameList<'a>,
    /// `compression_algorithms_client_to_server`.
    pub compression_client_to_server: NameList<'a>,
    /// `compression_algorithms_server_to_client`.
    pub compression_server_to_client: NameList<'a>,
    /// `languages_client_to_server`. May be empty.
    pub languages_client_to_server: NameList<'a>,
    /// `languages_server_to_client`. May be empty.
    pub languages_server_to_client: NameList<'a>,
    /// `first_kex_packet_follows`.
    pub first_kex_packet_follows: bool,
    /// The trailing `uint32` reserved field, as sent.
    pub reserved: u32,
}

/// Names of the eight algorithm name lists that RFC 4253 requires to be
/// non-empty, in wire order. Used by [`KexInit::empty_algorithm_lists`].
pub const ALGORITHM_LIST_NAMES: [&str; 8] = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
];

impl<'a> KexInit<'a> {
    /// Decodes a complete, already delimited KEXINIT payload starting at the
    /// message number byte.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::KEXINIT)?;
        let cookie = field(&mut r, "cookie", |r| r.read_bytes(COOKIE_LEN))?;
        let cookie: &[u8; COOKIE_LEN] = cookie
            .try_into()
            .expect("read_bytes returned exactly COOKIE_LEN bytes");
        let kex_algorithms = field(&mut r, "kex_algorithms", Reader::read_name_list)?;
        let server_host_key_algorithms =
            field(&mut r, "server_host_key_algorithms", Reader::read_name_list)?;
        let encryption_client_to_server = field(
            &mut r,
            "encryption_algorithms_client_to_server",
            Reader::read_name_list,
        )?;
        let encryption_server_to_client = field(
            &mut r,
            "encryption_algorithms_server_to_client",
            Reader::read_name_list,
        )?;
        let mac_client_to_server = field(
            &mut r,
            "mac_algorithms_client_to_server",
            Reader::read_name_list,
        )?;
        let mac_server_to_client = field(
            &mut r,
            "mac_algorithms_server_to_client",
            Reader::read_name_list,
        )?;
        let compression_client_to_server = field(
            &mut r,
            "compression_algorithms_client_to_server",
            Reader::read_name_list,
        )?;
        let compression_server_to_client = field(
            &mut r,
            "compression_algorithms_server_to_client",
            Reader::read_name_list,
        )?;
        let languages_client_to_server =
            field(&mut r, "languages_client_to_server", Reader::read_name_list)?;
        let languages_server_to_client =
            field(&mut r, "languages_server_to_client", Reader::read_name_list)?;
        let first_kex_packet_follows =
            field(&mut r, "first_kex_packet_follows", Reader::read_bool)?;
        let reserved = field(&mut r, "reserved", Reader::read_u32)?;
        finish(&r)?;
        Ok(KexInit {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_client_to_server,
            encryption_server_to_client,
            mac_client_to_server,
            mac_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            reserved,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    ///
    /// Exists so tests and future senders can build payloads with the same
    /// field order as the decoder. It performs no semantic validation.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::KEXINIT)?;
        w.write_bytes(self.cookie)?;
        for list in self.name_lists() {
            w.write_name_list(list)?;
        }
        w.write_bool(self.first_kex_packet_follows)?;
        w.write_u32(self.reserved)?;
        Ok(w.position())
    }

    /// The ten name lists in wire order.
    #[must_use]
    pub fn name_lists(&self) -> [NameList<'a>; 10] {
        [
            self.kex_algorithms,
            self.server_host_key_algorithms,
            self.encryption_client_to_server,
            self.encryption_server_to_client,
            self.mac_client_to_server,
            self.mac_server_to_client,
            self.compression_client_to_server,
            self.compression_server_to_client,
            self.languages_client_to_server,
            self.languages_server_to_client,
        ]
    }

    /// Names (from [`ALGORITHM_LIST_NAMES`]) of required algorithm lists
    /// that are empty. Language lists are never reported.
    pub fn empty_algorithm_lists(&self) -> impl Iterator<Item = &'static str> + '_ {
        let lists = self.name_lists();
        ALGORITHM_LIST_NAMES
            .into_iter()
            .enumerate()
            .filter(move |(i, _)| lists[*i].is_empty())
            .map(|(_, name)| name)
    }
}

/// Semantic annotation for an entry of `kex_algorithms`.
///
/// This is a recognition aid for reports. It does not authorise negotiation,
/// and an unrecognised name is simply [`KexName::Method`] with no claim about
/// whether it is a real method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexName {
    /// Presumed key-exchange method name (including any the workspace does
    /// not recognise).
    Method,
    /// `ext-info-c`: client signals RFC 8308 extension negotiation support.
    /// Not a key-exchange method (RFC 8308 §2.1).
    ExtInfoClient,
    /// `ext-info-s`: server signals RFC 8308 extension negotiation support.
    /// Not a key-exchange method (RFC 8308 §2.1).
    ExtInfoServer,
    /// `kex-strict-c-v00@openssh.com`: client signals OpenSSH strict key
    /// exchange (OpenSSH `PROTOCOL` §1.10). Not a key-exchange method.
    StrictKexClient,
    /// `kex-strict-s-v00@openssh.com`: server signals OpenSSH strict key
    /// exchange (OpenSSH `PROTOCOL` §1.10). Not a key-exchange method.
    StrictKexServer,
}

impl KexName {
    /// Returns `true` for markers that must never be selected as the
    /// key-exchange method.
    #[must_use]
    pub const fn is_marker(self) -> bool {
        !matches!(self, KexName::Method)
    }
}

/// Classifies one entry of a `kex_algorithms` list.
#[must_use]
pub fn classify_kex_name(name: &[u8]) -> KexName {
    match name {
        b"ext-info-c" => KexName::ExtInfoClient,
        b"ext-info-s" => KexName::ExtInfoServer,
        b"kex-strict-c-v00@openssh.com" => KexName::StrictKexClient,
        b"kex-strict-s-v00@openssh.com" => KexName::StrictKexServer,
        _ => KexName::Method,
    }
}

#[cfg(feature = "alloc")]
pub use owned::OwnedKexInit;

#[cfg(feature = "alloc")]
mod owned {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{COOKIE_LEN, KexInit};
    use crate::namelist::NameList;

    /// Owned copy of a decoded [`KexInit`], for reports that outlive the
    /// payload buffer. Name lists are copied into `Vec<String>` (names are
    /// guaranteed US-ASCII by the decoder) in their original order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct OwnedKexInit {
        /// See [`KexInit::cookie`].
        pub cookie: [u8; COOKIE_LEN],
        /// See [`KexInit::kex_algorithms`].
        pub kex_algorithms: Vec<String>,
        /// See [`KexInit::server_host_key_algorithms`].
        pub server_host_key_algorithms: Vec<String>,
        /// See [`KexInit::encryption_client_to_server`].
        pub encryption_client_to_server: Vec<String>,
        /// See [`KexInit::encryption_server_to_client`].
        pub encryption_server_to_client: Vec<String>,
        /// See [`KexInit::mac_client_to_server`].
        pub mac_client_to_server: Vec<String>,
        /// See [`KexInit::mac_server_to_client`].
        pub mac_server_to_client: Vec<String>,
        /// See [`KexInit::compression_client_to_server`].
        pub compression_client_to_server: Vec<String>,
        /// See [`KexInit::compression_server_to_client`].
        pub compression_server_to_client: Vec<String>,
        /// See [`KexInit::languages_client_to_server`].
        pub languages_client_to_server: Vec<String>,
        /// See [`KexInit::languages_server_to_client`].
        pub languages_server_to_client: Vec<String>,
        /// See [`KexInit::first_kex_packet_follows`].
        pub first_kex_packet_follows: bool,
        /// See [`KexInit::reserved`].
        pub reserved: u32,
    }

    fn own(list: NameList<'_>) -> Vec<String> {
        list.iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect()
    }

    impl KexInit<'_> {
        /// Copies every field into an [`OwnedKexInit`].
        #[must_use]
        pub fn to_owned(&self) -> OwnedKexInit {
            OwnedKexInit {
                cookie: *self.cookie,
                kex_algorithms: own(self.kex_algorithms),
                server_host_key_algorithms: own(self.server_host_key_algorithms),
                encryption_client_to_server: own(self.encryption_client_to_server),
                encryption_server_to_client: own(self.encryption_server_to_client),
                mac_client_to_server: own(self.mac_client_to_server),
                mac_server_to_client: own(self.mac_server_to_client),
                compression_client_to_server: own(self.compression_client_to_server),
                compression_server_to_client: own(self.compression_server_to_client),
                languages_client_to_server: own(self.languages_client_to_server),
                languages_server_to_client: own(self.languages_server_to_client),
                first_kex_packet_follows: self.first_kex_packet_follows,
                reserved: self.reserved,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{DecodeError, InvalidEncoding};

    /// Hand-assembled KEXINIT with distinct lists in every direction.
    fn fixture() -> [u8; 192] {
        let mut buf = [0u8; 192];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0xA5; 16]).unwrap();
        w.write_string(b"curve25519-sha256,ext-info-s").unwrap(); // kex
        w.write_string(b"ssh-ed25519").unwrap(); // host key
        w.write_string(b"aes128-ctr").unwrap(); // enc c2s
        w.write_string(b"aes256-ctr").unwrap(); // enc s2c
        w.write_string(b"hmac-sha2-256").unwrap(); // mac c2s
        w.write_string(b"hmac-sha2-512").unwrap(); // mac s2c
        w.write_string(b"none").unwrap(); // comp c2s
        w.write_string(b"zlib").unwrap(); // comp s2c
        w.write_string(b"").unwrap(); // lang c2s
        w.write_string(b"en").unwrap(); // lang s2c
        w.write_bool(false).unwrap();
        w.write_u32(0).unwrap();
        let n = w.position();
        // Store the length in the last byte so tests can slice.
        buf[191] = n as u8;
        buf
    }

    fn fixture_slice(buf: &[u8; 192]) -> &[u8] {
        &buf[..buf[191] as usize]
    }

    #[test]
    fn decodes_distinct_directional_lists() {
        let buf = fixture();
        let k = KexInit::decode(fixture_slice(&buf)).unwrap();
        assert_eq!(k.cookie, &[0xA5; 16]);
        assert_eq!(k.kex_algorithms.as_str(), "curve25519-sha256,ext-info-s");
        assert_eq!(k.server_host_key_algorithms.as_str(), "ssh-ed25519");
        assert_eq!(k.encryption_client_to_server.as_str(), "aes128-ctr");
        assert_eq!(k.encryption_server_to_client.as_str(), "aes256-ctr");
        assert_eq!(k.mac_client_to_server.as_str(), "hmac-sha2-256");
        assert_eq!(k.mac_server_to_client.as_str(), "hmac-sha2-512");
        assert_eq!(k.compression_client_to_server.as_str(), "none");
        assert_eq!(k.compression_server_to_client.as_str(), "zlib");
        assert!(k.languages_client_to_server.is_empty());
        assert_eq!(k.languages_server_to_client.as_str(), "en");
        assert!(!k.first_kex_packet_follows);
        assert_eq!(k.reserved, 0);
        assert_eq!(k.empty_algorithm_lists().count(), 0);
    }

    #[test]
    fn encode_round_trips_through_decode() {
        let buf = fixture();
        let k = KexInit::decode(fixture_slice(&buf)).unwrap();
        let mut out = [0u8; 192];
        let n = k.encode(&mut out).unwrap();
        assert_eq!(&out[..n], fixture_slice(&buf));
    }

    #[test]
    fn wrong_message_number() {
        let mut buf = fixture();
        buf[0] = 21;
        assert_eq!(
            KexInit::decode(fixture_slice(&buf)),
            Err(MessageError::UnexpectedMessage {
                expected: 20,
                found: 21
            })
        );
        assert_eq!(KexInit::decode(&[]), Err(MessageError::Empty));
    }

    #[test]
    fn truncation_at_every_boundary_names_the_field() {
        let buf = fixture();
        let full = fixture_slice(&buf);
        // Every proper prefix must fail; check a few named boundaries.
        for n in 0..full.len() {
            assert!(KexInit::decode(&full[..n]).is_err(), "prefix {n} accepted");
        }
        match KexInit::decode(&full[..10]) {
            Err(MessageError::Field {
                field: "cookie",
                offset: 1,
                ..
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
        match KexInit::decode(&full[..full.len() - 2]) {
            Err(MessageError::Field {
                field: "reserved",
                error:
                    DecodeError::Truncated {
                        needed: 4,
                        available: 2,
                    },
                ..
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let buf = fixture();
        let full = fixture_slice(&buf);
        let mut extended = [0u8; 193];
        extended[..full.len()].copy_from_slice(full);
        assert_eq!(
            KexInit::decode(&extended[..full.len() + 1]),
            Err(MessageError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn nonzero_reserved_is_preserved_not_rejected() {
        let buf = fixture();
        let full = fixture_slice(&buf);
        let mut copy = [0u8; 192];
        copy[..full.len()].copy_from_slice(full);
        copy[full.len() - 1] = 7;
        let k = KexInit::decode(&copy[..full.len()]).unwrap();
        assert_eq!(k.reserved, 7);
    }

    #[test]
    fn noncanonical_first_kex_packet_follows() {
        let buf = fixture();
        let full = fixture_slice(&buf);
        let mut copy = [0u8; 192];
        copy[..full.len()].copy_from_slice(full);
        copy[full.len() - 5] = 0x80;
        assert!(
            KexInit::decode(&copy[..full.len()])
                .unwrap()
                .first_kex_packet_follows
        );
    }

    #[test]
    fn malformed_name_list_names_the_field() {
        let mut buf = [0u8; 192];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0; 16]).unwrap();
        w.write_string(b"a").unwrap();
        w.write_string(b"bad name").unwrap();
        let n = w.position();
        match KexInit::decode(&buf[..n]) {
            Err(MessageError::Field {
                field: "server_host_key_algorithms",
                offset: 22,
                error: DecodeError::InvalidEncoding(InvalidEncoding::NameListNonAscii { offset: 3 }),
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn empty_required_lists_are_reported_not_rejected() {
        let mut buf = [0u8; 192];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0; 16]).unwrap();
        for _ in 0..10 {
            w.write_string(b"").unwrap();
        }
        w.write_bool(false).unwrap();
        w.write_u32(0).unwrap();
        let n = w.position();
        let k = KexInit::decode(&buf[..n]).unwrap();
        let empties: [&str; 8] = {
            let mut arr = [""; 8];
            for (slot, name) in arr.iter_mut().zip(k.empty_algorithm_lists()) {
                *slot = name;
            }
            arr
        };
        assert_eq!(empties, ALGORITHM_LIST_NAMES);
    }

    #[test]
    fn markers_are_recognised_and_unknown_names_kept() {
        assert_eq!(classify_kex_name(b"ext-info-s"), KexName::ExtInfoServer);
        assert_eq!(classify_kex_name(b"ext-info-c"), KexName::ExtInfoClient);
        assert_eq!(
            classify_kex_name(b"kex-strict-s-v00@openssh.com"),
            KexName::StrictKexServer
        );
        assert_eq!(
            classify_kex_name(b"kex-strict-c-v00@openssh.com"),
            KexName::StrictKexClient
        );
        assert_eq!(classify_kex_name(b"curve25519-sha256"), KexName::Method);
        assert_eq!(classify_kex_name(b"totally-unknown"), KexName::Method);
        assert!(KexName::ExtInfoServer.is_marker());
        assert!(!KexName::Method.is_marker());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_copy_preserves_order() {
        let buf = fixture();
        let owned = KexInit::decode(fixture_slice(&buf)).unwrap().to_owned();
        assert_eq!(owned.kex_algorithms, ["curve25519-sha256", "ext-info-s"]);
        assert_eq!(owned.compression_server_to_client, ["zlib"]);
        assert!(owned.languages_client_to_server.is_empty());
        assert_eq!(owned.cookie, [0xA5; 16]);
    }
}
