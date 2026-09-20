//! SSH message numbers used by this workspace.
//!
//! Values are from the IANA "SSH Protocol Parameters" registry as assigned by
//! RFC 4253 §12, RFC 4254 §9 and RFC 8308 §2.3. Only numbers with a consumer
//! in the workspace are listed; add others as codecs arrive.

/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
pub const DISCONNECT: u8 = 1;
/// `SSH_MSG_IGNORE` (RFC 4253 §11.2).
pub const IGNORE: u8 = 2;
/// `SSH_MSG_UNIMPLEMENTED` (RFC 4253 §11.4).
pub const UNIMPLEMENTED: u8 = 3;
/// `SSH_MSG_DEBUG` (RFC 4253 §11.3).
pub const DEBUG: u8 = 4;
/// `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §10).
pub const SERVICE_REQUEST: u8 = 5;
/// `SSH_MSG_SERVICE_ACCEPT` (RFC 4253 §10).
pub const SERVICE_ACCEPT: u8 = 6;
/// `SSH_MSG_EXT_INFO` (RFC 8308 §2.3).
pub const EXT_INFO: u8 = 7;
/// `SSH_MSG_KEXINIT` (RFC 4253 §7.1).
pub const KEXINIT: u8 = 20;
/// `SSH_MSG_NEWKEYS` (RFC 4253 §7.3).
pub const NEWKEYS: u8 = 21;
/// `SSH_MSG_CHANNEL_OPEN` (RFC 4254 §5.1).
pub const CHANNEL_OPEN: u8 = 90;
/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (RFC 4254 §5.1).
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// `SSH_MSG_CHANNEL_OPEN_FAILURE` (RFC 4254 §5.1).
pub const CHANNEL_OPEN_FAILURE: u8 = 92;

/// Returns `true` for message numbers in the key-exchange-method-specific
/// range 30–49 (RFC 4253 §12), whose meaning depends on the negotiated method.
#[must_use]
pub const fn is_kex_method_specific(number: u8) -> bool {
    number >= 30 && number <= 49
}

/// Best-effort human-readable name for a message number, for diagnostics.
/// Unknown numbers return `None`; callers must not treat a name as validation.
#[must_use]
pub const fn name(number: u8) -> Option<&'static str> {
    Some(match number {
        DISCONNECT => "SSH_MSG_DISCONNECT",
        IGNORE => "SSH_MSG_IGNORE",
        UNIMPLEMENTED => "SSH_MSG_UNIMPLEMENTED",
        DEBUG => "SSH_MSG_DEBUG",
        SERVICE_REQUEST => "SSH_MSG_SERVICE_REQUEST",
        SERVICE_ACCEPT => "SSH_MSG_SERVICE_ACCEPT",
        EXT_INFO => "SSH_MSG_EXT_INFO",
        KEXINIT => "SSH_MSG_KEXINIT",
        NEWKEYS => "SSH_MSG_NEWKEYS",
        CHANNEL_OPEN => "SSH_MSG_CHANNEL_OPEN",
        CHANNEL_OPEN_CONFIRMATION => "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
        CHANNEL_OPEN_FAILURE => "SSH_MSG_CHANNEL_OPEN_FAILURE",
        _ => return None,
    })
}
