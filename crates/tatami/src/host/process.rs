//! Host process adapters: launching commands and shells for session channels.
//!
//! A process bound to a channel does not outlive the SSH connection; session
//! resurrection after transport loss is out of scope.
