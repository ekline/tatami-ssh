//! Algorithm negotiation (RFC 4253 §7.1) for the first interoperability
//! profile, plus the client's own `KEXINIT` proposal.
//!
//! # Rules applied
//!
//! - **Key exchange**: the first algorithm in the client's list that the
//!   server also lists. Marker pseudo-algorithms (`ext-info-*`,
//!   `kex-strict-*`; see [`classify_kex_name`]) are excluded on *both* sides
//!   before the comparison and can never be selected (RFC 8308 §2.2,
//!   draft-ietf-sshm-strict-kex-02 §3.1).
//! - **Host key**: the first algorithm in the client's list that the server
//!   also lists. RFC 4253 additionally requires the chosen algorithm to be
//!   capable of what the key-exchange method needs; `curve25519-sha256`
//!   needs only a signature-capable key, which every host-key algorithm is.
//! - **Encryption** (per direction): the first algorithm in the client's
//!   list that the server also lists.
//! - **MAC** (per direction): when the selected cipher is an AEAD, MAC
//!   negotiation is skipped and the MAC lists are not consulted
//!   ([`Mac::ImplicitAead`]; draft-miller-sshm-aes-gcm-01 §2, OpenSSH
//!   `PROTOCOL` §1.6). Otherwise negotiation fails with
//!   [`NegotiationError::NoMacImplemented`]: Tatami implements no HMAC, so
//!   there is no MAC it could honestly select. See the MAC-list policy below.
//! - **Compression** (per direction): the first algorithm in the client's
//!   list that the server also lists; only `none` is implemented, and the
//!   client offers only `none`.
//! - **Strict KEX**: enabled when the client offered a client-role marker
//!   and the server offered the server-role marker of the *same spelling*
//!   (both pre-standard or both standard), never across spellings.
//! - **`first_kex_packet_follows`**: if the server set it, its guess is right
//!   only when both sides' first key-exchange *method* and first host-key
//!   algorithm agree; otherwise the client must ignore the server's first
//!   key-exchange packet ([`Negotiated::server_guess_wrong`]). Markers are
//!   skipped when locating the first method because they are not methods and
//!   cannot be guessed; OpenSSH compares raw first tokens, which agrees
//!   whenever markers are listed after the real methods, as they always are
//!   in practice.
//!
//! # MAC-list policy
//!
//! Tatami advertises only `aes128-gcm@openssh.com` as a cipher, so the peer
//! can never select a non-AEAD cipher from our proposal and MAC negotiation
//! is always skipped. RFC 4253 §7.1 still requires `mac_algorithms_*` to be
//! non-empty name-lists, so the proposal carries `hmac-sha2-256` in both
//! directions purely to satisfy that syntax. No HMAC is implemented, and
//! [`negotiate`] refuses to proceed in the (impossible from our proposal)
//! case that the selected cipher is not an AEAD. This is recorded as W-30 in
//! `docs/crypto-provider-audit.md`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use tatami_wire::EncodeError;
use tatami_wire::algorithms;
use tatami_wire::kexinit::{
    COOKIE_LEN, KexInit, KexName, StrictKexRole, StrictKexSpelling, classify_kex_name,
    classify_strict_kex_name,
};
use tatami_wire::namelist::NameList;

/// The client's `KEXINIT` proposal: the fixed first-profile algorithm lists
/// plus the two optional markers and an injected cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientProposal {
    /// Sixteen random bytes supplied by the caller's entropy source.
    pub cookie: [u8; COOKIE_LEN],
    /// Offer `ext-info-c` (RFC 8308 §2.1).
    pub advertise_ext_info: bool,
    /// Offer both strict-KEX client markers (draft-ietf-sshm-strict-kex-02
    /// §3.1 recommends offering both spellings).
    pub offer_strict_kex: bool,
}

impl ClientProposal {
    /// `kex_algorithms` in the order sent: the real method first, then the
    /// markers.
    #[must_use]
    pub fn kex_algorithms(&self) -> Vec<&'static [u8]> {
        let mut names = alloc::vec![algorithms::CURVE25519_SHA256];
        if self.advertise_ext_info {
            names.push(algorithms::EXT_INFO_C);
        }
        if self.offer_strict_kex {
            names.push(algorithms::KEX_STRICT_C_OPENSSH);
            names.push(algorithms::KEX_STRICT_C);
        }
        names
    }

    /// Encodes the complete `KEXINIT` payload (`I_C`: message number
    /// included, packet framing excluded).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let kex = self.kex_algorithms();
        let mut out = alloc::vec![0u8; 512];
        let mut w = tatami_wire::Writer::new(&mut out);
        w.write_u8(tatami_wire::msg::KEXINIT)?;
        w.write_bytes(&self.cookie)?;
        w.write_name_list(kex.iter())?;
        w.write_name_list([algorithms::SSH_ED25519])?;
        w.write_name_list([algorithms::AES128_GCM_OPENSSH])?;
        w.write_name_list([algorithms::AES128_GCM_OPENSSH])?;
        // See the MAC-list policy in the module documentation.
        w.write_name_list([algorithms::HMAC_SHA2_256])?;
        w.write_name_list([algorithms::HMAC_SHA2_256])?;
        w.write_name_list([algorithms::NONE])?;
        w.write_name_list([algorithms::NONE])?;
        w.write_name_list::<[&[u8]; 0], &[u8]>([])?;
        w.write_name_list::<[&[u8]; 0], &[u8]>([])?;
        w.write_bool(false)?;
        w.write_u32(0)?;
        let len = w.position();
        out.truncate(len);
        Ok(out)
    }
}

/// How packet integrity is provided in one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mac {
    /// The selected cipher is an AEAD; integrity is part of the cipher and
    /// the MAC lists were not consulted.
    ImplicitAead,
}

impl Mac {
    /// Stable text for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Mac::ImplicitAead => "implicit (AEAD)",
        }
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strict key exchange markers seen in the two initial `KEXINIT`s and the
/// resulting decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictKex {
    /// The client offered `kex-strict-c-v00@openssh.com`.
    pub offered_pre_standard: bool,
    /// The client offered `kex-strict-c`.
    pub offered_standard: bool,
    /// The server offered `kex-strict-s-v00@openssh.com`.
    pub server_pre_standard: bool,
    /// The server offered `kex-strict-s`.
    pub server_standard: bool,
    /// Strict KEX is in effect: a matching pair of the same spelling.
    pub negotiated: bool,
}

impl StrictKex {
    /// Evaluates the markers of both initial proposals.
    #[must_use]
    pub fn evaluate(client: &KexInit<'_>, server: &KexInit<'_>) -> Self {
        let offered = |list: NameList<'_>, role: StrictKexRole, spelling: StrictKexSpelling| {
            list.iter().any(|name| {
                classify_strict_kex_name(name)
                    .is_some_and(|m| m.role == role && m.spelling == spelling)
            })
        };
        let offered_pre_standard = offered(
            client.kex_algorithms,
            StrictKexRole::Client,
            StrictKexSpelling::OpenSshV00,
        );
        let offered_standard = offered(
            client.kex_algorithms,
            StrictKexRole::Client,
            StrictKexSpelling::Standard,
        );
        let server_pre_standard = offered(
            server.kex_algorithms,
            StrictKexRole::Server,
            StrictKexSpelling::OpenSshV00,
        );
        let server_standard = offered(
            server.kex_algorithms,
            StrictKexRole::Server,
            StrictKexSpelling::Standard,
        );
        StrictKex {
            offered_pre_standard,
            offered_standard,
            server_pre_standard,
            server_standard,
            negotiated: (offered_pre_standard && server_pre_standard)
                || (offered_standard && server_standard),
        }
    }

    /// The client side of the record, before the server's proposal is known.
    #[must_use]
    pub fn offered(client: &KexInit<'_>) -> Self {
        let has = |name: &[u8]| client.kex_algorithms.contains(name);
        StrictKex {
            offered_pre_standard: has(algorithms::KEX_STRICT_C_OPENSSH),
            offered_standard: has(algorithms::KEX_STRICT_C),
            ..StrictKex::default()
        }
    }
}

/// Outcome of a successful negotiation. Names are the exact wire names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// Key-exchange method.
    pub kex: String,
    /// Server host-key algorithm.
    pub host_key: String,
    /// Cipher, client to server.
    pub encryption_client_to_server: String,
    /// Cipher, server to client.
    pub encryption_server_to_client: String,
    /// Integrity, client to server.
    pub mac_client_to_server: Mac,
    /// Integrity, server to client.
    pub mac_server_to_client: Mac,
    /// Compression, client to server.
    pub compression_client_to_server: String,
    /// Compression, server to client.
    pub compression_server_to_client: String,
    /// Strict-KEX markers and decision.
    pub strict_kex: StrictKex,
    /// The server offered `ext-info-s` (RFC 8308 §2.1).
    pub ext_info: bool,
    /// The server set `first_kex_packet_follows` and guessed wrong: the
    /// client must discard the server's first key-exchange-specific message
    /// (RFC 4253 §7.1).
    pub server_guess_wrong: bool,
}

impl Negotiated {
    /// Fails unless every selected algorithm is one this crate implements
    /// (the first interoperability profile). [`negotiate`] is a pure
    /// RFC 4253 §7.1 function over arbitrary proposals; the handshake calls
    /// this afterwards so an unexpected selection is reported, not assumed.
    pub fn check_profile(&self) -> Result<(), NegotiationError> {
        let unsupported = |field: &'static str, name: &str| {
            Err(NegotiationError::UnsupportedSelection {
                field,
                name: String::from(name),
            })
        };
        if self.kex.as_bytes() != algorithms::CURVE25519_SHA256 {
            return unsupported("kex_algorithms", &self.kex);
        }
        if self.host_key.as_bytes() != algorithms::SSH_ED25519 {
            return unsupported("server_host_key_algorithms", &self.host_key);
        }
        if !is_aead(self.encryption_client_to_server.as_bytes()) {
            return unsupported(
                "encryption_algorithms_client_to_server",
                &self.encryption_client_to_server,
            );
        }
        if !is_aead(self.encryption_server_to_client.as_bytes()) {
            return unsupported(
                "encryption_algorithms_server_to_client",
                &self.encryption_server_to_client,
            );
        }
        if self.compression_client_to_server.as_bytes() != algorithms::NONE {
            return unsupported(
                "compression_algorithms_client_to_server",
                &self.compression_client_to_server,
            );
        }
        if self.compression_server_to_client.as_bytes() != algorithms::NONE {
            return unsupported(
                "compression_algorithms_server_to_client",
                &self.compression_server_to_client,
            );
        }
        Ok(())
    }
}

/// Which direction a per-direction failure refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client to server.
    ClientToServer,
    /// Server to client.
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Direction::ClientToServer => "client-to-server",
            Direction::ServerToClient => "server-to-client",
        })
    }
}

/// Why negotiation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationError {
    /// No key-exchange method (markers excluded) is common to both lists.
    NoCommonKex,
    /// No host-key algorithm is common to both lists.
    NoCommonHostKey,
    /// No cipher is common to both lists in this direction.
    NoCommonCipher(Direction),
    /// The selected cipher is not an AEAD and this crate implements no MAC.
    NoMacImplemented(Direction),
    /// No compression algorithm is common to both lists in this direction.
    NoCommonCompression(Direction),
    /// Negotiation succeeded but selected something outside the implemented
    /// profile (only possible with a proposal other than
    /// [`ClientProposal`]).
    UnsupportedSelection {
        /// The `KEXINIT` field.
        field: &'static str,
        /// The selected name.
        name: String,
    },
}

impl NegotiationError {
    /// Stable, machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            NegotiationError::NoCommonKex => "no_common_kex",
            NegotiationError::NoCommonHostKey => "no_common_host_key",
            NegotiationError::NoCommonCipher(_) => "no_common_cipher",
            NegotiationError::NoMacImplemented(_) => "no_mac_implemented",
            NegotiationError::NoCommonCompression(_) => "no_common_compression",
            NegotiationError::UnsupportedSelection { .. } => "unsupported_selection",
        }
    }
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NegotiationError::NoCommonKex => f.write_str("no common key-exchange method"),
            NegotiationError::NoCommonHostKey => f.write_str("no common host-key algorithm"),
            NegotiationError::NoCommonCipher(d) => write!(f, "no common {d} cipher"),
            NegotiationError::NoMacImplemented(d) => write!(
                f,
                "selected {d} cipher is not an AEAD and no MAC is implemented"
            ),
            NegotiationError::NoCommonCompression(d) => {
                write!(f, "no common {d} compression algorithm")
            }
            NegotiationError::UnsupportedSelection { field, name } => {
                write!(f, "selected `{name}` in {field} is not implemented")
            }
        }
    }
}

impl core::error::Error for NegotiationError {}

/// `true` for cipher names whose integrity is built in (RFC 5647 family).
#[must_use]
pub fn is_aead(cipher: &[u8]) -> bool {
    cipher == algorithms::AES128_GCM_OPENSSH
}

fn is_method(name: &[u8]) -> bool {
    classify_kex_name(name) == KexName::Method
}

/// First real key-exchange method in a proposal, skipping markers.
fn first_method<'a>(k: &KexInit<'a>) -> Option<&'a [u8]> {
    k.kex_algorithms.iter().find(|n| is_method(n))
}

/// First entry of `client` that also appears in `server`.
fn first_common<'a>(client: NameList<'a>, server: NameList<'_>) -> Option<&'a [u8]> {
    client.iter().find(|name| server.contains(name))
}

fn owned(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// Applies RFC 4253 §7.1 to two initial proposals. See the module
/// documentation for the exact rules.
pub fn negotiate(
    client: &KexInit<'_>,
    server: &KexInit<'_>,
) -> Result<Negotiated, NegotiationError> {
    let server_methods: Vec<&[u8]> = server
        .kex_algorithms
        .iter()
        .filter(|name| is_method(name))
        .collect();
    let kex = client
        .kex_algorithms
        .iter()
        .filter(|name| is_method(name))
        .find(|name| server_methods.contains(name))
        .ok_or(NegotiationError::NoCommonKex)?;

    let host_key = first_common(
        client.server_host_key_algorithms,
        server.server_host_key_algorithms,
    )
    .ok_or(NegotiationError::NoCommonHostKey)?;

    let enc_c2s = first_common(
        client.encryption_client_to_server,
        server.encryption_client_to_server,
    )
    .ok_or(NegotiationError::NoCommonCipher(Direction::ClientToServer))?;
    let enc_s2c = first_common(
        client.encryption_server_to_client,
        server.encryption_server_to_client,
    )
    .ok_or(NegotiationError::NoCommonCipher(Direction::ServerToClient))?;

    // AEAD rule: the MAC lists are not consulted for an AEAD cipher. No
    // other cipher is implemented, so any other selection has no usable MAC.
    let mac = |cipher: &[u8], direction| {
        if is_aead(cipher) {
            Ok(Mac::ImplicitAead)
        } else {
            Err(NegotiationError::NoMacImplemented(direction))
        }
    };
    let mac_c2s = mac(enc_c2s, Direction::ClientToServer)?;
    let mac_s2c = mac(enc_s2c, Direction::ServerToClient)?;

    let comp_c2s = first_common(
        client.compression_client_to_server,
        server.compression_client_to_server,
    )
    .ok_or(NegotiationError::NoCommonCompression(
        Direction::ClientToServer,
    ))?;
    let comp_s2c = first_common(
        client.compression_server_to_client,
        server.compression_server_to_client,
    )
    .ok_or(NegotiationError::NoCommonCompression(
        Direction::ServerToClient,
    ))?;

    let strict_kex = StrictKex::evaluate(client, server);
    let ext_info = server.kex_algorithms.contains(algorithms::EXT_INFO_S);

    let server_guess_wrong = server.first_kex_packet_follows && {
        let same_kex = first_method(client) == first_method(server);
        let same_host_key = client.server_host_key_algorithms.iter().next()
            == server.server_host_key_algorithms.iter().next();
        !(same_kex && same_host_key)
    };

    Ok(Negotiated {
        kex: owned(kex),
        host_key: owned(host_key),
        encryption_client_to_server: owned(enc_c2s),
        encryption_server_to_client: owned(enc_s2c),
        mac_client_to_server: mac_c2s,
        mac_server_to_client: mac_s2c,
        compression_client_to_server: owned(comp_c2s),
        compression_server_to_client: owned(comp_s2c),
        strict_kex,
        ext_info,
        server_guess_wrong,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tatami_wire::Writer;

    /// Hand-built `KEXINIT` payload with one string per list. Independent of
    /// `ClientProposal::encode`.
    struct Lists {
        kex: &'static str,
        host_key: &'static str,
        enc_c2s: &'static str,
        enc_s2c: &'static str,
        mac: &'static str,
        comp_c2s: &'static str,
        comp_s2c: &'static str,
        first_kex_packet_follows: bool,
    }

    impl Default for Lists {
        fn default() -> Self {
            Lists {
                kex: "curve25519-sha256",
                host_key: "ssh-ed25519",
                enc_c2s: "aes128-gcm@openssh.com",
                enc_s2c: "aes128-gcm@openssh.com",
                mac: "hmac-sha2-256",
                comp_c2s: "none",
                comp_s2c: "none",
                first_kex_packet_follows: false,
            }
        }
    }

    fn payload(l: &Lists) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0x11; 16]).unwrap();
        for s in [
            l.kex, l.host_key, l.enc_c2s, l.enc_s2c, l.mac, l.mac, l.comp_c2s, l.comp_s2c, "", "",
        ] {
            w.write_string(s.as_bytes()).unwrap();
        }
        w.write_bool(l.first_kex_packet_follows).unwrap();
        w.write_u32(0).unwrap();
        w.written().to_vec()
    }

    fn client_lists() -> Lists {
        Lists {
            kex: "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com,kex-strict-c",
            ..Lists::default()
        }
    }

    fn run(client: &Lists, server: &Lists) -> Result<Negotiated, NegotiationError> {
        let c = payload(client);
        let s = payload(server);
        negotiate(&KexInit::decode(&c).unwrap(), &KexInit::decode(&s).unwrap())
    }

    #[test]
    fn proposal_encodes_expected_lists_and_marker_order() {
        let p = ClientProposal {
            cookie: [7; 16],
            advertise_ext_info: true,
            offer_strict_kex: true,
        };
        let bytes = p.encode().unwrap();
        let k = KexInit::decode(&bytes).unwrap();
        assert_eq!(k.cookie, &[7; 16]);
        assert_eq!(
            k.kex_algorithms.as_str(),
            "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com,kex-strict-c"
        );
        assert_eq!(k.server_host_key_algorithms.as_str(), "ssh-ed25519");
        assert_eq!(
            k.encryption_client_to_server.as_str(),
            "aes128-gcm@openssh.com"
        );
        assert_eq!(
            k.encryption_server_to_client.as_str(),
            "aes128-gcm@openssh.com"
        );
        assert_eq!(k.mac_client_to_server.as_str(), "hmac-sha2-256");
        assert_eq!(k.mac_server_to_client.as_str(), "hmac-sha2-256");
        assert_eq!(k.compression_client_to_server.as_str(), "none");
        assert_eq!(k.compression_server_to_client.as_str(), "none");
        assert!(k.languages_client_to_server.is_empty());
        assert!(k.languages_server_to_client.is_empty());
        assert!(!k.first_kex_packet_follows);
        assert_eq!(k.reserved, 0);
        assert_eq!(k.empty_algorithm_lists().count(), 0);

        let minimal = ClientProposal {
            cookie: [0; 16],
            advertise_ext_info: false,
            offer_strict_kex: false,
        };
        let bytes = minimal.encode().unwrap();
        let k = KexInit::decode(&bytes).unwrap();
        assert_eq!(k.kex_algorithms.as_str(), "curve25519-sha256");
        let only_ext = ClientProposal {
            advertise_ext_info: true,
            ..minimal
        };
        let bytes = only_ext.encode().unwrap();
        assert_eq!(
            KexInit::decode(&bytes).unwrap().kex_algorithms.as_str(),
            "curve25519-sha256,ext-info-c"
        );
    }

    #[test]
    fn full_profile_match_selects_everything() {
        let server = Lists {
            kex: "mlkem768x25519-sha256,curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
            host_key: "rsa-sha2-512,ssh-ed25519",
            enc_c2s: "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com",
            enc_s2c: "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            mac: "umac-64-etm@openssh.com,hmac-sha2-512",
            comp_c2s: "none,zlib@openssh.com",
            comp_s2c: "zlib@openssh.com,none",
            first_kex_packet_follows: false,
        };
        let n = run(&client_lists(), &server).unwrap();
        assert_eq!(n.kex, "curve25519-sha256");
        assert_eq!(n.host_key, "ssh-ed25519");
        assert_eq!(n.encryption_client_to_server, "aes128-gcm@openssh.com");
        assert_eq!(n.encryption_server_to_client, "aes128-gcm@openssh.com");
        // MAC lists have nothing in common, yet negotiation succeeds: AEAD.
        assert_eq!(n.mac_client_to_server, Mac::ImplicitAead);
        assert_eq!(n.mac_server_to_client.as_str(), "implicit (AEAD)");
        assert_eq!(n.compression_client_to_server, "none");
        assert_eq!(n.compression_server_to_client, "none");
        assert!(n.ext_info);
        assert!(!n.server_guess_wrong);
        assert_eq!(
            n.strict_kex,
            StrictKex {
                offered_pre_standard: true,
                offered_standard: true,
                server_pre_standard: true,
                server_standard: false,
                negotiated: true,
            }
        );
        n.check_profile().unwrap();
    }

    #[test]
    fn markers_are_never_selected_as_methods() {
        // Server lists only markers: nothing negotiable even though the
        // client also lists markers.
        let server = Lists {
            kex: "ext-info-s,kex-strict-s-v00@openssh.com",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonKex)
        );
        // Client and server share a marker name literally (a confused peer
        // echoing the client marker); still excluded on both sides.
        let server = Lists {
            kex: "ext-info-c,kex-strict-c",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonKex)
        );
        // Marker listed before the method on the server side is skipped.
        let server = Lists {
            kex: "kex-strict-s-v00@openssh.com,curve25519-sha256",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server).unwrap().kex,
            "curve25519-sha256"
        );
    }

    #[test]
    fn client_preference_order_wins() {
        let client = Lists {
            kex: "a-method,curve25519-sha256",
            ..Lists::default()
        };
        let server = Lists {
            kex: "curve25519-sha256,a-method",
            ..Lists::default()
        };
        let n = run(&client, &server).unwrap();
        assert_eq!(n.kex, "a-method");
        assert_eq!(
            n.check_profile(),
            Err(NegotiationError::UnsupportedSelection {
                field: "kex_algorithms",
                name: String::from("a-method"),
            })
        );
    }

    #[test]
    fn each_missing_list_fails_with_its_own_error() {
        let server = Lists {
            host_key: "rsa-sha2-512,ecdsa-sha2-nistp256",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonHostKey)
        );
        let server = Lists {
            enc_c2s: "aes256-ctr",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonCipher(Direction::ClientToServer))
        );
        let server = Lists {
            enc_s2c: "aes256-gcm@openssh.com",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonCipher(Direction::ServerToClient))
        );
        let server = Lists {
            comp_c2s: "zlib",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonCompression(
                Direction::ClientToServer
            ))
        );
        let server = Lists {
            comp_s2c: "zlib@openssh.com",
            ..Lists::default()
        };
        assert_eq!(
            run(&client_lists(), &server),
            Err(NegotiationError::NoCommonCompression(
                Direction::ServerToClient
            ))
        );
    }

    #[test]
    fn non_aead_selection_fails_because_no_mac_is_implemented() {
        // A hand-built client that offers a non-AEAD cipher first.
        let client = Lists {
            enc_c2s: "aes128-ctr,aes128-gcm@openssh.com",
            ..client_lists()
        };
        let server = Lists {
            enc_c2s: "aes128-ctr,aes128-gcm@openssh.com",
            ..Lists::default()
        };
        assert_eq!(
            run(&client, &server),
            Err(NegotiationError::NoMacImplemented(
                Direction::ClientToServer
            ))
        );
        let client = Lists {
            enc_s2c: "aes256-ctr",
            ..client_lists()
        };
        let server = Lists {
            enc_s2c: "aes256-ctr",
            ..Lists::default()
        };
        assert_eq!(
            run(&client, &server),
            Err(NegotiationError::NoMacImplemented(
                Direction::ServerToClient
            ))
        );
    }

    #[test]
    fn strict_kex_requires_matching_spellings() {
        let both = client_lists();
        let pre_only = Lists {
            kex: "curve25519-sha256,kex-strict-c-v00@openssh.com",
            ..Lists::default()
        };
        let std_only = Lists {
            kex: "curve25519-sha256,kex-strict-c",
            ..Lists::default()
        };
        let none = Lists::default();

        let server_pre = Lists {
            kex: "curve25519-sha256,kex-strict-s-v00@openssh.com",
            ..Lists::default()
        };
        let server_std = Lists {
            kex: "curve25519-sha256,kex-strict-s",
            ..Lists::default()
        };
        let server_both = Lists {
            kex: "curve25519-sha256,kex-strict-s,kex-strict-s-v00@openssh.com",
            ..Lists::default()
        };
        let server_none = Lists::default();
        // A server sending the *client* marker does not count.
        let server_wrong_role = Lists {
            kex: "curve25519-sha256,kex-strict-c-v00@openssh.com,kex-strict-c",
            ..Lists::default()
        };

        let strict = |c: &Lists, s: &Lists| run(c, s).unwrap().strict_kex;

        assert!(strict(&both, &server_pre).negotiated);
        assert!(strict(&both, &server_std).negotiated);
        assert!(strict(&both, &server_both).negotiated);
        assert!(!strict(&both, &server_none).negotiated);
        assert!(!strict(&both, &server_wrong_role).negotiated);

        assert!(strict(&pre_only, &server_pre).negotiated);
        assert!(
            !strict(&pre_only, &server_std).negotiated,
            "mixed spellings"
        );
        assert!(strict(&pre_only, &server_both).negotiated);

        assert!(strict(&std_only, &server_std).negotiated);
        assert!(
            !strict(&std_only, &server_pre).negotiated,
            "mixed spellings"
        );
        assert!(strict(&std_only, &server_both).negotiated);

        assert!(!strict(&none, &server_both).negotiated);
        assert_eq!(
            strict(&none, &server_both),
            StrictKex {
                offered_pre_standard: false,
                offered_standard: false,
                server_pre_standard: true,
                server_standard: true,
                negotiated: false,
            }
        );
        assert_eq!(
            strict(&pre_only, &server_std),
            StrictKex {
                offered_pre_standard: true,
                offered_standard: false,
                server_pre_standard: false,
                server_standard: true,
                negotiated: false,
            }
        );

        let c = payload(&both);
        assert_eq!(
            StrictKex::offered(&KexInit::decode(&c).unwrap()),
            StrictKex {
                offered_pre_standard: true,
                offered_standard: true,
                ..StrictKex::default()
            }
        );
    }

    #[test]
    fn ext_info_reflects_server_marker_only() {
        let n = run(&client_lists(), &Lists::default()).unwrap();
        assert!(!n.ext_info);
        let server = Lists {
            kex: "curve25519-sha256,ext-info-s",
            ..Lists::default()
        };
        assert!(run(&client_lists(), &server).unwrap().ext_info);
        // `ext-info-c` from the server is not `ext-info-s`.
        let server = Lists {
            kex: "curve25519-sha256,ext-info-c",
            ..Lists::default()
        };
        assert!(!run(&client_lists(), &server).unwrap().ext_info);
    }

    #[test]
    fn server_guess_is_evaluated_on_first_method_and_host_key() {
        // Flag unset: never wrong, whatever the lists.
        let server = Lists {
            kex: "other,curve25519-sha256",
            ..Lists::default()
        };
        assert!(!run(&client_lists(), &server).unwrap().server_guess_wrong);

        // Flag set, first methods and host keys agree (markers skipped).
        let server = Lists {
            kex: "kex-strict-s-v00@openssh.com,curve25519-sha256",
            first_kex_packet_follows: true,
            ..Lists::default()
        };
        assert!(!run(&client_lists(), &server).unwrap().server_guess_wrong);

        // Flag set, different first method.
        let server = Lists {
            kex: "other,curve25519-sha256",
            first_kex_packet_follows: true,
            ..Lists::default()
        };
        assert!(run(&client_lists(), &server).unwrap().server_guess_wrong);

        // Flag set, same method, different first host key.
        let server = Lists {
            host_key: "rsa-sha2-512,ssh-ed25519",
            first_kex_packet_follows: true,
            ..Lists::default()
        };
        assert!(run(&client_lists(), &server).unwrap().server_guess_wrong);
    }

    #[test]
    fn error_codes_and_display() {
        assert_eq!(NegotiationError::NoCommonKex.code(), "no_common_kex");
        assert_eq!(
            NegotiationError::NoCommonCipher(Direction::ServerToClient).code(),
            "no_common_cipher"
        );
        assert_eq!(
            alloc::format!(
                "{}",
                NegotiationError::NoMacImplemented(Direction::ClientToServer)
            ),
            "selected client-to-server cipher is not an AEAD and no MAC is implemented"
        );
        assert_eq!(alloc::format!("{}", Mac::ImplicitAead), "implicit (AEAD)");
    }
}
