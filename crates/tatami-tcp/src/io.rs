//! Host socket and runtime adapters for the TCP binding.
//!
//! Available only with the `std` feature. This module will hold the glue
//! between the portable transport state machine and OS-backed TCP sockets
//! and async runtimes. No runtime has been selected; whichever is chosen must
//! remain confined to this module and its explicit backend features.
