//! Host operating-system adapters.
//!
//! Available only with the `std` feature. Filesystem reads, interactive trust
//! prompts, process launching, PTY allocation and outbound forwarding sockets
//! belong here rather than in protocol packages. An OS-backed implementation
//! is not portable and is not presented as such.

pub mod environment;
pub mod process;
pub mod pty;
