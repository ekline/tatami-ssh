//! Reusable SSH client composition.
//!
//! This module will assemble the shared auth and connection engines with a
//! selected transport binding into a client usable as a library. CLI entry
//! points are expected to stay thin wrappers over this module.
//!
//! Callers can configure and inspect the TCP and QUIC bindings separately;
//! there is no common transport trait. Host trust (`known_hosts`) remains a
//! caller-supplied policy distinct from user authentication.
