//! RFC 3339 timestamps for QUIC records.
//!
//! Same algorithm as `server::observe::rfc3339`, which is only compiled with
//! the `tcp` feature; the owner of `server.rs` may want to hoist it to a
//! shared module so both observers use one copy.

use alloc::string::String;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Current time as RFC 3339 UTC with millisecond precision.
#[must_use]
pub fn now_rfc3339() -> String {
    rfc3339(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

/// Formats seconds since the Unix epoch as RFC 3339 UTC with millisecond
/// precision, e.g. `2026-09-20T12:34:56.789Z`.
#[must_use]
pub fn rfc3339(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    alloc::format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian calendar).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Milliseconds, saturating.
#[must_use]
pub fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339(Duration::ZERO), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(Duration::from_millis(1_789_907_696_789)),
            "2026-09-20T12:34:56.789Z"
        );
        assert_eq!(
            rfc3339(Duration::from_secs(1_709_251_199)),
            "2024-02-29T23:59:59.000Z"
        );
    }
}
