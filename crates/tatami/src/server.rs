//! Reusable SSH server composition.
//!
//! This module will assemble the shared auth and connection engines with a
//! selected transport binding into a server usable as a library. CLI entry
//! points are expected to stay thin wrappers over this module.
//!
//! Server-side admission callbacks may refuse a requested channel
//! independently of transport resources. User authorization
//! (`authorized_keys`) remains a caller-supplied policy distinct from host
//! trust and signature validity.
