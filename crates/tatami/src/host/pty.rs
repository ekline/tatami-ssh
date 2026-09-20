//! Host pseudo-terminal adapters for `pty-req` and window-change handling.
//!
//! A PTY may merge stdout and stderr before SSH frames them; the binding
//! preserves the sender's chosen per-direction order, not pipe timing.
