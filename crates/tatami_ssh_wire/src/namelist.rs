//! Borrowed, validated SSH `name-list` (RFC 4251 §5).
//!
//! A name list is a comma-separated sequence of names carried in an SSH
//! `string`. Names are printable US-ASCII without commas and must not be
//! empty. The list as a whole may be empty. This module validates syntax
//! only; it attaches no meaning to any name.

use crate::error::InvalidEncoding;

/// A syntactically valid name list borrowed from its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameList<'a> {
    body: &'a [u8],
}

impl<'a> NameList<'a> {
    /// An empty list.
    pub const EMPTY: NameList<'static> = NameList { body: &[] };

    /// Validates `body` (the bytes inside the `string`, without the length
    /// prefix) and wraps it.
    ///
    /// Rules: every byte is printable US-ASCII (`0x21..=0x7e`), no name is
    /// empty. An entirely empty body is a valid empty list.
    pub fn parse(body: &'a [u8]) -> Result<Self, InvalidEncoding> {
        if body.is_empty() {
            return Ok(NameList { body });
        }
        let mut name_start = 0usize;
        for (offset, &b) in body.iter().enumerate() {
            if b == b',' {
                if offset == name_start {
                    return Err(InvalidEncoding::NameListEmptyName { offset });
                }
                name_start = offset + 1;
            } else if !is_name_byte(b) {
                return Err(InvalidEncoding::NameListNonAscii { offset });
            }
        }
        if name_start == body.len() {
            // Trailing comma.
            return Err(InvalidEncoding::NameListEmptyName { offset: name_start });
        }
        Ok(NameList { body })
    }

    /// The raw body bytes, exactly as received.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.body
    }

    /// The body as text. Always succeeds for a parsed list because every
    /// byte is US-ASCII.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Validated ASCII in `parse`; ASCII is valid UTF-8.
        core::str::from_utf8(self.body).unwrap_or("")
    }

    /// Returns `true` for a zero-length list.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Iterates over the names in their original order.
    #[must_use]
    pub fn iter(&self) -> Names<'a> {
        Names {
            rest: if self.body.is_empty() {
                None
            } else {
                Some(self.body)
            },
        }
    }

    /// Number of names in the list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Returns `true` if `name` appears anywhere in the list.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.iter().any(|n| n == name)
    }
}

impl<'a> IntoIterator for NameList<'a> {
    type Item = &'a [u8];
    type IntoIter = Names<'a>;

    fn into_iter(self) -> Names<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &NameList<'a> {
    type Item = &'a [u8];
    type IntoIter = Names<'a>;

    fn into_iter(self) -> Names<'a> {
        self.iter()
    }
}

/// Iterator over the names of a [`NameList`].
#[derive(Clone, Debug)]
pub struct Names<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for Names<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.rest?;
        match rest.iter().position(|&b| b == b',') {
            Some(i) => {
                self.rest = Some(&rest[i + 1..]);
                Some(&rest[..i])
            }
            None => {
                self.rest = None;
                Some(rest)
            }
        }
    }
}

/// Returns `true` if `b` may appear inside a name: printable US-ASCII
/// excluding the comma separator.
#[must_use]
pub const fn is_name_byte(b: u8) -> bool {
    b > 0x20 && b < 0x7f && b != b','
}

/// Returns `true` if `name` is a valid single SSH name: non-empty and made
/// only of [`is_name_byte`] bytes.
#[must_use]
pub fn is_valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| is_name_byte(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(list: NameList<'_>) -> [Option<&[u8]>; 4] {
        let mut it = list.iter();
        [it.next(), it.next(), it.next(), it.next()]
    }

    #[test]
    fn parses_ordered_names() {
        let l = NameList::parse(b"zlib,none,a").unwrap();
        assert_eq!(
            collect(l),
            [Some(&b"zlib"[..]), Some(b"none"), Some(b"a"), None]
        );
        assert_eq!(l.len(), 3);
        assert!(l.contains(b"none"));
        assert!(!l.contains(b"non"));
        assert_eq!(l.as_str(), "zlib,none,a");
    }

    #[test]
    fn empty_list_is_valid_and_yields_nothing() {
        let l = NameList::parse(b"").unwrap();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert_eq!(collect(l), [None, None, None, None]);
    }

    #[test]
    fn rejects_empty_names() {
        assert_eq!(
            NameList::parse(b",a"),
            Err(InvalidEncoding::NameListEmptyName { offset: 0 })
        );
        assert_eq!(
            NameList::parse(b"a,,b"),
            Err(InvalidEncoding::NameListEmptyName { offset: 2 })
        );
        assert_eq!(
            NameList::parse(b"a,"),
            Err(InvalidEncoding::NameListEmptyName { offset: 2 })
        );
        assert_eq!(
            NameList::parse(b","),
            Err(InvalidEncoding::NameListEmptyName { offset: 0 })
        );
    }

    #[test]
    fn rejects_non_printable_and_non_ascii() {
        assert_eq!(
            NameList::parse(b"a b"),
            Err(InvalidEncoding::NameListNonAscii { offset: 1 })
        );
        assert_eq!(
            NameList::parse(b"ab\xc3\xa9"),
            Err(InvalidEncoding::NameListNonAscii { offset: 2 })
        );
        assert_eq!(
            NameList::parse(b"a\x7f"),
            Err(InvalidEncoding::NameListNonAscii { offset: 1 })
        );
    }

    #[test]
    fn unknown_names_are_preserved_verbatim() {
        let l = NameList::parse(b"ext-info-s,kex-strict-s-v00@openssh.com,made-up").unwrap();
        let mut it = l.iter();
        assert_eq!(it.next(), Some(&b"ext-info-s"[..]));
        assert_eq!(it.next(), Some(&b"kex-strict-s-v00@openssh.com"[..]));
        assert_eq!(it.next(), Some(&b"made-up"[..]));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn name_validity() {
        assert!(is_valid_name(b"aes128-ctr"));
        assert!(!is_valid_name(b""));
        assert!(!is_valid_name(b"a,b"));
        assert!(!is_valid_name(b"a b"));
    }
}
