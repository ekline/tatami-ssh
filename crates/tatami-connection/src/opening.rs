//! Channel-opening lifecycle engine (RFC 4254 §5.1), transport independent.
//!
//! The engine owns the state between "someone wants a channel" and "both
//! sides agree it exists". It takes typed commands from the application and
//! decoded messages from the peer, and produces typed [`Event`]s for the
//! application plus [`Outgoing`] messages for the binding to send. It has no
//! sockets, futures, clocks or QUIC stream concepts.
//!
//! # Identities
//!
//! Three identifiers are kept strictly apart:
//!
//! - [`LocalNumber`]: the `sender channel` we put on the wire. Allocated by
//!   this engine.
//! - [`PeerNumber`]: the `sender channel` the peer put on the wire. Only
//!   meaningful when echoed back to the peer as `recipient channel`.
//! - [`ChannelHandle`]: an application-facing token with a generation
//!   counter, never sent on the wire, so a stale handle cannot alias a newer
//!   channel that reused the same slot.
//!
//! The two number spaces are independent: the peer may open its channel 0
//! while we have our own channel 0 pending. Incoming opens are correlated by
//! peer number and outgoing opens by local number, so no confusion arises.
//!
//! # Lifecycle
//!
//! ```text
//! open()  ──▶ PendingOutgoing ──confirmation──▶ Established
//!                   │ ├──failure──────────▶ Event::Refused
//!                   │ └──cancel()────────▶ tombstone (see below)
//! OPEN rx ──▶ PendingIncoming ──accept()─────▶ Established
//!                              └──refuse()───▶ (gone)
//! ```
//!
//! A stream or socket becoming available never creates a channel; only a
//! decoded confirmation (outgoing) or an explicit `accept` (incoming) does.
//!
//! # Local-number allocation and late replies
//!
//! Numbers are allocated from a monotonically increasing counter and are
//! **never reused** by this engine version. Channel close is not yet
//! modelled, so no number is ever released; when close arrives, release
//! must wait until the peer can no longer send a message naming the number.
//! Exhausting the 32-bit space yields [`OpenError::NumbersExhausted`].
//!
//! RFC 4254 has no message for withdrawing an `OPEN`. When the application
//! cancels a pending outgoing open, the local number is moved to a bounded
//! tombstone list so that a reply arriving afterwards is classified as
//! [`Event::LateReply`] rather than a protocol violation. A late
//! *confirmation* means the peer considers the channel open; closing it is
//! the responsibility of the future close lifecycle, and the event carries
//! the numbers needed to do so. If the tombstone list overflows, the oldest
//! entry is dropped and a reply for it becomes
//! [`Violation::UnknownRecipient`], which is still safe because the number
//! is never reissued.
//!
//! # What is deliberately absent
//!
//! Window and maximum-packet values are stored as received and echoed as
//! configured. No credit accounting, data transfer, EOF or close is
//! implemented here, and no QUIC meaning is attached to any field. Those
//! protocol audits remain open.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use tatami_wire::EncodeError;
use tatami_wire::channel::{
    ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure, open_failure_reason,
};

/// Our `sender channel` number for a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalNumber(pub u32);

/// The peer's `sender channel` number for a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerNumber(pub u32);

/// Application-facing handle. Not a wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelHandle {
    index: u32,
    generation: u32,
}

/// Window and maximum-packet parameters, retained verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credit {
    /// `initial window size` as sent.
    pub initial_window_size: u32,
    /// `maximum packet size` as sent.
    pub maximum_packet_size: u32,
}

/// Resource bounds. Defaults are local policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpeningLimits {
    /// Maximum outgoing opens awaiting a peer reply.
    pub max_pending_outgoing: usize,
    /// Maximum incoming opens awaiting an application decision. Further
    /// opens are refused with `SSH_OPEN_RESOURCE_SHORTAGE`.
    pub max_pending_incoming: usize,
    /// Maximum channels in any state (pending or established).
    pub max_channels: usize,
    /// Maximum remembered cancelled local numbers.
    pub max_tombstones: usize,
}

impl Default for OpeningLimits {
    fn default() -> Self {
        OpeningLimits {
            max_pending_outgoing: 16,
            max_pending_incoming: 16,
            max_channels: 256,
            max_tombstones: 64,
        }
    }
}

/// Parameters for an outgoing open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenParams {
    /// Channel type name.
    pub channel_type: Vec<u8>,
    /// Our advertised credit.
    pub local: Credit,
    /// Type-specific data to append.
    pub type_specific: Vec<u8>,
}

/// Parameters for accepting an incoming open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptParams {
    /// Our advertised credit.
    pub local: Credit,
    /// Type-specific data to append to the confirmation.
    pub type_specific: Vec<u8>,
}

/// Which phase a channel was in, for [`Event::TransportLost`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Sent `OPEN`, awaiting reply.
    PendingOutgoing,
    /// Received `OPEN`, awaiting application decision.
    PendingIncoming,
    /// Both sides agreed.
    Established,
}

/// Events for the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The peer asked to open a channel. The application must call
    /// [`OpeningEngine::accept`] or [`OpeningEngine::refuse`].
    IncomingOpen {
        /// Handle for the decision.
        handle: ChannelHandle,
        /// Requested channel type, preserved even if unknown.
        channel_type: Vec<u8>,
        /// Peer's number and credit.
        peer_number: PeerNumber,
        /// Peer's advertised credit.
        peer: Credit,
        /// Bounded type-specific tail, uninterpreted.
        type_specific: Vec<u8>,
    },
    /// A channel is now open in both directions.
    Established {
        /// Handle.
        handle: ChannelHandle,
        /// Channel type (from the `OPEN`, since confirmations omit it).
        channel_type: Vec<u8>,
        /// Our number.
        local_number: LocalNumber,
        /// Peer's number.
        peer_number: PeerNumber,
        /// Our credit as advertised.
        local: Credit,
        /// Peer's credit as advertised.
        peer: Credit,
        /// Type-specific tail of the peer's confirmation (empty for
        /// incoming channels, where we sent the confirmation).
        peer_type_specific: Vec<u8>,
    },
    /// The peer refused our open.
    Refused {
        /// Handle (now invalid).
        handle: ChannelHandle,
        /// Reason code, possibly unregistered.
        reason_code: u32,
        /// Raw description. Untrusted.
        description: Vec<u8>,
        /// Raw language tag. Untrusted.
        language_tag: Vec<u8>,
    },
    /// An incoming open was refused automatically because
    /// [`OpeningLimits::max_pending_incoming`] or
    /// [`OpeningLimits::max_channels`] was reached.
    IncomingRefusedByLimit {
        /// Peer's number.
        peer_number: PeerNumber,
        /// Requested type.
        channel_type: Vec<u8>,
    },
    /// A reply arrived for an open the application had cancelled.
    LateReply {
        /// The cancelled local number.
        local_number: LocalNumber,
        /// What the peer said.
        reply: LateReply,
    },
    /// The transport ended; the channel is gone without any peer message.
    TransportLost {
        /// Handle (now invalid).
        handle: ChannelHandle,
        /// Phase at loss.
        phase: Phase,
    },
}

/// Detail for [`Event::LateReply`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LateReply {
    /// Peer confirmed; it believes the channel is open. A future close
    /// lifecycle must close it using `peer_number`.
    Confirmed {
        /// Peer's number for the channel.
        peer_number: PeerNumber,
        /// Peer's credit.
        peer: Credit,
    },
    /// Peer refused; nothing further is needed.
    Refused {
        /// Reason code.
        reason_code: u32,
    },
}

/// Messages the binding must send, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outgoing {
    /// `SSH_MSG_CHANNEL_OPEN`.
    Open {
        /// Channel type.
        channel_type: Vec<u8>,
        /// Our number.
        sender_channel: LocalNumber,
        /// Our credit.
        local: Credit,
        /// Type-specific data.
        type_specific: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
    OpenConfirmation {
        /// Peer's number.
        recipient_channel: PeerNumber,
        /// Our number.
        sender_channel: LocalNumber,
        /// Our credit.
        local: Credit,
        /// Type-specific data.
        type_specific: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
    OpenFailure {
        /// Peer's number.
        recipient_channel: PeerNumber,
        /// Reason code.
        reason_code: u32,
        /// Description.
        description: Vec<u8>,
        /// Language tag.
        language_tag: Vec<u8>,
    },
}

impl Outgoing {
    /// Encodes the message payload with the `tatami-wire` codecs.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        match self {
            Outgoing::Open {
                channel_type,
                sender_channel,
                local,
                type_specific,
            } => ChannelOpen {
                channel_type,
                sender_channel: sender_channel.0,
                initial_window_size: local.initial_window_size,
                maximum_packet_size: local.maximum_packet_size,
                type_specific,
            }
            .encode(out),
            Outgoing::OpenConfirmation {
                recipient_channel,
                sender_channel,
                local,
                type_specific,
            } => ChannelOpenConfirmation {
                recipient_channel: recipient_channel.0,
                sender_channel: sender_channel.0,
                initial_window_size: local.initial_window_size,
                maximum_packet_size: local.maximum_packet_size,
                type_specific,
            }
            .encode(out),
            Outgoing::OpenFailure {
                recipient_channel,
                reason_code,
                description,
                language_tag,
            } => ChannelOpenFailure {
                recipient_channel: recipient_channel.0,
                reason_code: *reason_code,
                description,
                language_tag,
            }
            .encode(out),
        }
    }
}

/// Peer behaviour that violates RFC 4254. The engine leaves its state
/// unchanged; the binding decides whether to disconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A reply named a local number that is neither pending nor
    /// tombstoned.
    UnknownRecipient {
        /// The `recipient channel` value.
        recipient: u32,
    },
    /// A reply named a channel that is already established (a second
    /// confirmation or a failure after confirmation).
    DuplicateReply {
        /// Our number.
        local_number: LocalNumber,
    },
    /// A reply named a channel that is pending *incoming*, i.e. the peer
    /// answered its own request.
    ReplyToIncoming {
        /// The `recipient channel` value.
        recipient: u32,
    },
    /// The peer opened with a sender number already in use by one of its
    /// pending or established channels.
    DuplicatePeerNumber {
        /// The repeated number.
        peer_number: PeerNumber,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::UnknownRecipient { recipient } => {
                write!(f, "reply for unknown recipient channel {recipient}")
            }
            Violation::DuplicateReply { local_number } => {
                write!(
                    f,
                    "duplicate reply for established channel {}",
                    local_number.0
                )
            }
            Violation::ReplyToIncoming { recipient } => {
                write!(f, "peer replied to its own open (recipient {recipient})")
            }
            Violation::DuplicatePeerNumber { peer_number } => {
                write!(f, "peer reused sender channel {}", peer_number.0)
            }
        }
    }
}

impl core::error::Error for Violation {}

/// Why an application command was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// [`OpeningLimits::max_pending_outgoing`] reached.
    TooManyPendingOutgoing,
    /// [`OpeningLimits::max_channels`] reached.
    TooManyChannels,
    /// Local number space exhausted.
    NumbersExhausted,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpenError::TooManyPendingOutgoing => "too many outgoing opens pending",
            OpenError::TooManyChannels => "too many channels",
            OpenError::NumbersExhausted => "local channel numbers exhausted",
        })
    }
}

impl core::error::Error for OpenError {}

/// Why a handle-based command was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// The handle does not refer to a live channel (never existed, already
    /// resolved, or its slot has since been reused).
    Stale,
    /// The channel exists but is not in the phase the command requires.
    WrongPhase {
        /// The channel's actual phase.
        actual: Phase,
    },
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandleError::Stale => f.write_str("stale channel handle"),
            HandleError::WrongPhase { actual } => write!(f, "channel is {actual:?}"),
        }
    }
}

impl core::error::Error for HandleError {}

#[derive(Clone, Debug)]
enum State {
    PendingOutgoing {
        channel_type: Vec<u8>,
        local_number: LocalNumber,
        local: Credit,
    },
    PendingIncoming {
        channel_type: Vec<u8>,
        peer_number: PeerNumber,
        peer: Credit,
    },
    Established {
        local_number: LocalNumber,
        peer_number: PeerNumber,
    },
}

impl State {
    fn phase(&self) -> Phase {
        match self {
            State::PendingOutgoing { .. } => Phase::PendingOutgoing,
            State::PendingIncoming { .. } => Phase::PendingIncoming,
            State::Established { .. } => Phase::Established,
        }
    }
}

#[derive(Clone, Debug)]
struct Slot {
    generation: u32,
    state: Option<State>,
}

/// The opening engine. See the module documentation.
#[derive(Clone, Debug)]
pub struct OpeningEngine {
    limits: OpeningLimits,
    slots: Vec<Slot>,
    free: Vec<u32>,
    next_local: u32,
    numbers_exhausted: bool,
    tombstones: VecDeque<LocalNumber>,
    outgoing: VecDeque<Outgoing>,
    pending_outgoing: usize,
    pending_incoming: usize,
    live: usize,
}

impl OpeningEngine {
    /// Creates an engine with the given limits.
    #[must_use]
    pub fn new(limits: OpeningLimits) -> Self {
        OpeningEngine {
            limits,
            slots: Vec::new(),
            free: Vec::new(),
            next_local: 0,
            numbers_exhausted: false,
            tombstones: VecDeque::new(),
            outgoing: VecDeque::new(),
            pending_outgoing: 0,
            pending_incoming: 0,
            live: 0,
        }
    }

    /// Removes and returns the next message the binding must send.
    pub fn next_outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.pop_front()
    }

    /// Number of channels in any live phase.
    #[must_use]
    pub const fn live_channels(&self) -> usize {
        self.live
    }

    /// Number of outgoing opens awaiting a reply.
    #[must_use]
    pub const fn pending_outgoing(&self) -> usize {
        self.pending_outgoing
    }

    /// Number of incoming opens awaiting a decision.
    #[must_use]
    pub const fn pending_incoming(&self) -> usize {
        self.pending_incoming
    }

    /// Current phase of a handle, if live.
    #[must_use]
    pub fn phase(&self, handle: ChannelHandle) -> Option<Phase> {
        self.get(handle).map(State::phase)
    }

    // ----- application commands -------------------------------------------------

    /// Requests a new channel. Queues an `OPEN`; the channel becomes
    /// established only on the peer's confirmation.
    pub fn open(&mut self, params: OpenParams) -> Result<ChannelHandle, OpenError> {
        if self.pending_outgoing >= self.limits.max_pending_outgoing {
            return Err(OpenError::TooManyPendingOutgoing);
        }
        if self.live >= self.limits.max_channels {
            return Err(OpenError::TooManyChannels);
        }
        let local_number = self.allocate_number()?;
        let handle = self.insert(State::PendingOutgoing {
            channel_type: params.channel_type.clone(),
            local_number,
            local: params.local,
        });
        self.pending_outgoing += 1;
        self.outgoing.push_back(Outgoing::Open {
            channel_type: params.channel_type,
            sender_channel: local_number,
            local: params.local,
            type_specific: params.type_specific,
        });
        Ok(handle)
    }

    /// Withdraws interest in a pending outgoing open. No message is sent
    /// (the protocol has none); the local number is tombstoned so a later
    /// reply is reported as [`Event::LateReply`].
    pub fn cancel(&mut self, handle: ChannelHandle) -> Result<(), HandleError> {
        let state = self.get(handle).ok_or(HandleError::Stale)?;
        let State::PendingOutgoing { local_number, .. } = state else {
            return Err(HandleError::WrongPhase {
                actual: state.phase(),
            });
        };
        let local_number = *local_number;
        self.remove(handle);
        self.pending_outgoing -= 1;
        // Push, then trim to the limit, so `max_tombstones == 0` keeps none.
        self.tombstones.push_back(local_number);
        while self.tombstones.len() > self.limits.max_tombstones {
            self.tombstones.pop_front();
        }
        Ok(())
    }

    /// Accepts a pending incoming open. Queues a confirmation and
    /// establishes the channel.
    pub fn accept(
        &mut self,
        handle: ChannelHandle,
        params: AcceptParams,
    ) -> Result<Event, HandleError> {
        let state = self.get(handle).ok_or(HandleError::Stale)?;
        let State::PendingIncoming {
            channel_type,
            peer_number,
            peer,
        } = state
        else {
            return Err(HandleError::WrongPhase {
                actual: state.phase(),
            });
        };
        let (channel_type, peer_number, peer) = (channel_type.clone(), *peer_number, *peer);
        let local_number = self.allocate_number().map_err(|_| HandleError::WrongPhase {
            // Number exhaustion on accept is surfaced as a refusal instead.
            actual: Phase::PendingIncoming,
        });
        let local_number = match local_number {
            Ok(n) => n,
            Err(_) => {
                self.refuse_with(
                    handle,
                    peer_number,
                    open_failure_reason::RESOURCE_SHORTAGE,
                    b"channel numbers exhausted".to_vec(),
                );
                return Err(HandleError::Stale);
            }
        };
        self.set(
            handle,
            State::Established {
                local_number,
                peer_number,
            },
        );
        self.pending_incoming -= 1;
        self.outgoing.push_back(Outgoing::OpenConfirmation {
            recipient_channel: peer_number,
            sender_channel: local_number,
            local: params.local,
            type_specific: params.type_specific,
        });
        Ok(Event::Established {
            handle,
            channel_type,
            local_number,
            peer_number,
            local: params.local,
            peer,
            peer_type_specific: Vec::new(),
        })
    }

    /// Refuses a pending incoming open. Queues an `OPEN_FAILURE`.
    pub fn refuse(
        &mut self,
        handle: ChannelHandle,
        reason_code: u32,
        description: Vec<u8>,
    ) -> Result<(), HandleError> {
        let state = self.get(handle).ok_or(HandleError::Stale)?;
        let State::PendingIncoming { peer_number, .. } = state else {
            return Err(HandleError::WrongPhase {
                actual: state.phase(),
            });
        };
        let peer_number = *peer_number;
        self.refuse_with(handle, peer_number, reason_code, description);
        Ok(())
    }

    fn refuse_with(
        &mut self,
        handle: ChannelHandle,
        peer_number: PeerNumber,
        reason_code: u32,
        description: Vec<u8>,
    ) {
        self.remove(handle);
        self.pending_incoming -= 1;
        self.outgoing.push_back(Outgoing::OpenFailure {
            recipient_channel: peer_number,
            reason_code,
            description,
            language_tag: Vec::new(),
        });
    }

    /// The transport is gone. Every live channel is reported as lost, in
    /// slot order, and the engine is left empty. Queued outgoing messages
    /// are discarded, since nothing can carry them.
    pub fn transport_lost(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let Some(state) = slot.state.take() {
                events.push(Event::TransportLost {
                    handle: ChannelHandle {
                        index: index as u32,
                        generation: slot.generation,
                    },
                    phase: state.phase(),
                });
                slot.generation = slot.generation.wrapping_add(1);
                self.free.push(index as u32);
            }
        }
        self.pending_outgoing = 0;
        self.pending_incoming = 0;
        self.live = 0;
        self.outgoing.clear();
        events
    }

    // ----- peer messages -------------------------------------------------------

    /// Handles a decoded `CHANNEL_OPEN` from the peer.
    pub fn handle_open(&mut self, msg: &ChannelOpen<'_>) -> Result<Event, Violation> {
        let peer_number = PeerNumber(msg.sender_channel);
        if self.peer_number_in_use(peer_number) {
            return Err(Violation::DuplicatePeerNumber { peer_number });
        }
        let peer = Credit {
            initial_window_size: msg.initial_window_size,
            maximum_packet_size: msg.maximum_packet_size,
        };
        if self.pending_incoming >= self.limits.max_pending_incoming
            || self.live >= self.limits.max_channels
        {
            self.outgoing.push_back(Outgoing::OpenFailure {
                recipient_channel: peer_number,
                reason_code: open_failure_reason::RESOURCE_SHORTAGE,
                description: b"too many pending channels".to_vec(),
                language_tag: Vec::new(),
            });
            return Ok(Event::IncomingRefusedByLimit {
                peer_number,
                channel_type: msg.channel_type.to_vec(),
            });
        }
        let handle = self.insert(State::PendingIncoming {
            channel_type: msg.channel_type.to_vec(),
            peer_number,
            peer,
        });
        self.pending_incoming += 1;
        Ok(Event::IncomingOpen {
            handle,
            channel_type: msg.channel_type.to_vec(),
            peer_number,
            peer,
            type_specific: msg.type_specific.to_vec(),
        })
    }

    /// Handles a decoded `CHANNEL_OPEN_CONFIRMATION` from the peer.
    pub fn handle_open_confirmation(
        &mut self,
        msg: &ChannelOpenConfirmation<'_>,
    ) -> Result<Event, Violation> {
        let peer_number = PeerNumber(msg.sender_channel);
        let peer = Credit {
            initial_window_size: msg.initial_window_size,
            maximum_packet_size: msg.maximum_packet_size,
        };
        match self.find_reply_target(msg.recipient_channel)? {
            ReplyTarget::Pending(handle) => {
                let Some(State::PendingOutgoing {
                    channel_type,
                    local_number,
                    local,
                }) = self.get(handle).cloned()
                else {
                    unreachable!("find_reply_target returned a pending outgoing slot")
                };
                self.set(
                    handle,
                    State::Established {
                        local_number,
                        peer_number,
                    },
                );
                self.pending_outgoing -= 1;
                Ok(Event::Established {
                    handle,
                    channel_type,
                    local_number,
                    peer_number,
                    local,
                    peer,
                    peer_type_specific: msg.type_specific.to_vec(),
                })
            }
            ReplyTarget::Tombstone(local_number) => Ok(Event::LateReply {
                local_number,
                reply: LateReply::Confirmed { peer_number, peer },
            }),
        }
    }

    /// Handles a decoded `CHANNEL_OPEN_FAILURE` from the peer.
    pub fn handle_open_failure(
        &mut self,
        msg: &ChannelOpenFailure<'_>,
    ) -> Result<Event, Violation> {
        match self.find_reply_target(msg.recipient_channel)? {
            ReplyTarget::Pending(handle) => {
                self.remove(handle);
                self.pending_outgoing -= 1;
                Ok(Event::Refused {
                    handle,
                    reason_code: msg.reason_code,
                    description: msg.description.to_vec(),
                    language_tag: msg.language_tag.to_vec(),
                })
            }
            ReplyTarget::Tombstone(local_number) => Ok(Event::LateReply {
                local_number,
                reply: LateReply::Refused {
                    reason_code: msg.reason_code,
                },
            }),
        }
    }

    // ----- internals -----------------------------------------------------------

    fn find_reply_target(&mut self, recipient: u32) -> Result<ReplyTarget, Violation> {
        let wanted = LocalNumber(recipient);
        for (index, slot) in self.slots.iter().enumerate() {
            match &slot.state {
                Some(State::PendingOutgoing { local_number, .. }) if *local_number == wanted => {
                    return Ok(ReplyTarget::Pending(ChannelHandle {
                        index: index as u32,
                        generation: slot.generation,
                    }));
                }
                Some(State::Established { local_number, .. }) if *local_number == wanted => {
                    return Err(Violation::DuplicateReply {
                        local_number: wanted,
                    });
                }
                _ => {}
            }
        }
        if let Some(pos) = self.tombstones.iter().position(|n| *n == wanted) {
            self.tombstones.remove(pos);
            return Ok(ReplyTarget::Tombstone(wanted));
        }
        // A number we never allocated, or one belonging to a pending
        // incoming open (which has no local number yet).
        if self.slots.iter().any(|s| {
            matches!(&s.state, Some(State::PendingIncoming { peer_number, .. }) if peer_number.0 == recipient)
        }) && recipient >= self.next_local
        {
            return Err(Violation::ReplyToIncoming { recipient });
        }
        Err(Violation::UnknownRecipient { recipient })
    }

    fn peer_number_in_use(&self, peer_number: PeerNumber) -> bool {
        self.slots.iter().any(|s| match &s.state {
            Some(State::PendingIncoming { peer_number: p, .. })
            | Some(State::Established { peer_number: p, .. }) => *p == peer_number,
            _ => false,
        })
    }

    fn allocate_number(&mut self) -> Result<LocalNumber, OpenError> {
        if self.numbers_exhausted {
            return Err(OpenError::NumbersExhausted);
        }
        let n = self.next_local;
        match n.checked_add(1) {
            Some(next) => self.next_local = next,
            None => self.numbers_exhausted = true,
        }
        Ok(LocalNumber(n))
    }

    fn insert(&mut self, state: State) -> ChannelHandle {
        self.live += 1;
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.state = Some(state);
            return ChannelHandle {
                index,
                generation: slot.generation,
            };
        }
        let index = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 0,
            state: Some(state),
        });
        ChannelHandle {
            index,
            generation: 0,
        }
    }

    fn get(&self, handle: ChannelHandle) -> Option<&State> {
        let slot = self.slots.get(handle.index as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        slot.state.as_ref()
    }

    fn set(&mut self, handle: ChannelHandle, state: State) {
        self.slots[handle.index as usize].state = Some(state);
    }

    fn remove(&mut self, handle: ChannelHandle) {
        let slot = &mut self.slots[handle.index as usize];
        slot.state = None;
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(handle.index);
        self.live -= 1;
    }
}

enum ReplyTarget {
    Pending(ChannelHandle),
    Tombstone(LocalNumber),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credit(w: u32, p: u32) -> Credit {
        Credit {
            initial_window_size: w,
            maximum_packet_size: p,
        }
    }

    fn session(w: u32) -> OpenParams {
        OpenParams {
            channel_type: b"session".to_vec(),
            local: credit(w, 32768),
            type_specific: Vec::new(),
        }
    }

    fn engine() -> OpeningEngine {
        OpeningEngine::new(OpeningLimits::default())
    }

    fn confirmation(recipient: u32, sender: u32) -> ChannelOpenConfirmation<'static> {
        ChannelOpenConfirmation {
            recipient_channel: recipient,
            sender_channel: sender,
            initial_window_size: 1000,
            maximum_packet_size: 500,
            type_specific: &[],
        }
    }

    fn failure(recipient: u32, code: u32) -> ChannelOpenFailure<'static> {
        ChannelOpenFailure {
            recipient_channel: recipient,
            reason_code: code,
            description: b"no",
            language_tag: b"",
        }
    }

    fn peer_open(sender: u32, ty: &'static [u8]) -> ChannelOpen<'static> {
        ChannelOpen {
            channel_type: ty,
            sender_channel: sender,
            initial_window_size: 777,
            maximum_packet_size: 99,
            type_specific: &[0xAB],
        }
    }

    #[test]
    fn outgoing_open_established_with_asymmetric_numbers() {
        let mut e = engine();
        let h = e.open(session(2_000_000)).unwrap();
        assert_eq!(e.phase(h), Some(Phase::PendingOutgoing));
        assert_eq!(e.pending_outgoing(), 1);

        let out = e.next_outgoing().unwrap();
        assert_eq!(
            out,
            Outgoing::Open {
                channel_type: b"session".to_vec(),
                sender_channel: LocalNumber(0),
                local: credit(2_000_000, 32768),
                type_specific: Vec::new(),
            }
        );
        let mut buf = [0u8; 64];
        let n = out.encode(&mut buf).unwrap();
        let decoded = ChannelOpen::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.sender_channel, 0);
        assert!(e.next_outgoing().is_none());

        // Peer picks a completely different number for its side.
        let ev = e.handle_open_confirmation(&confirmation(0, 4242)).unwrap();
        assert_eq!(
            ev,
            Event::Established {
                handle: h,
                channel_type: b"session".to_vec(),
                local_number: LocalNumber(0),
                peer_number: PeerNumber(4242),
                local: credit(2_000_000, 32768),
                peer: credit(1000, 500),
                peer_type_specific: Vec::new(),
            }
        );
        assert_eq!(e.phase(h), Some(Phase::Established));
        assert_eq!(e.pending_outgoing(), 0);
        assert_eq!(e.live_channels(), 1);
    }

    #[test]
    fn peer_refusal_is_distinct_and_invalidates_handle() {
        let mut e = engine();
        let h = e.open(session(1)).unwrap();
        let ev = e.handle_open_failure(&failure(0, 200)).unwrap();
        assert_eq!(
            ev,
            Event::Refused {
                handle: h,
                reason_code: 200,
                description: b"no".to_vec(),
                language_tag: Vec::new(),
            }
        );
        assert_eq!(e.phase(h), None);
        assert_eq!(e.cancel(h), Err(HandleError::Stale));
        assert_eq!(e.live_channels(), 0);
    }

    #[test]
    fn simultaneous_opens_with_coinciding_sender_numbers() {
        let mut e = engine();
        // We open our channel 0; peer simultaneously opens its channel 0.
        let ours = e.open(session(1)).unwrap();
        let _ = e.next_outgoing();
        let ev = e.handle_open(&peer_open(0, b"session")).unwrap();
        let Event::IncomingOpen {
            handle: theirs,
            peer_number,
            peer,
            type_specific,
            ..
        } = ev
        else {
            panic!("{ev:?}")
        };
        assert_eq!(peer_number, PeerNumber(0));
        assert_eq!(peer, credit(777, 99));
        assert_eq!(type_specific, [0xAB]);
        assert_ne!(ours, theirs);

        // Peer confirms ours (recipient = our 0, its sender = 5).
        let ev = e.handle_open_confirmation(&confirmation(0, 5)).unwrap();
        assert!(matches!(ev, Event::Established { handle, .. } if handle == ours));

        // We accept theirs; our sender number for it is 1, not 0.
        let ev = e
            .accept(
                theirs,
                AcceptParams {
                    local: credit(10, 20),
                    type_specific: Vec::new(),
                },
            )
            .unwrap();
        assert!(matches!(
            ev,
            Event::Established {
                handle,
                local_number: LocalNumber(1),
                peer_number: PeerNumber(0),
                ..
            } if handle == theirs
        ));
        assert_eq!(
            e.next_outgoing().unwrap(),
            Outgoing::OpenConfirmation {
                recipient_channel: PeerNumber(0),
                sender_channel: LocalNumber(1),
                local: credit(10, 20),
                type_specific: Vec::new(),
            }
        );
        assert_eq!(e.live_channels(), 2);
    }

    #[test]
    fn incoming_refuse_sends_failure_with_peer_number() {
        let mut e = engine();
        let Event::IncomingOpen { handle, .. } =
            e.handle_open(&peer_open(9, b"x@example")).unwrap()
        else {
            panic!()
        };
        assert_eq!(e.pending_incoming(), 1);
        e.refuse(
            handle,
            open_failure_reason::UNKNOWN_CHANNEL_TYPE,
            b"unknown".to_vec(),
        )
        .unwrap();
        assert_eq!(
            e.next_outgoing().unwrap(),
            Outgoing::OpenFailure {
                recipient_channel: PeerNumber(9),
                reason_code: 3,
                description: b"unknown".to_vec(),
                language_tag: Vec::new(),
            }
        );
        assert_eq!(e.pending_incoming(), 0);
        assert_eq!(e.phase(handle), None);
        assert_eq!(e.refuse(handle, 1, Vec::new()), Err(HandleError::Stale));
    }

    #[test]
    fn duplicate_and_unknown_replies_are_violations() {
        let mut e = engine();
        let _ = e.open(session(1)).unwrap();
        e.handle_open_confirmation(&confirmation(0, 1)).unwrap();
        assert_eq!(
            e.handle_open_confirmation(&confirmation(0, 1)),
            Err(Violation::DuplicateReply {
                local_number: LocalNumber(0)
            })
        );
        assert_eq!(
            e.handle_open_failure(&failure(0, 1)),
            Err(Violation::DuplicateReply {
                local_number: LocalNumber(0)
            })
        );
        assert_eq!(
            e.handle_open_confirmation(&confirmation(77, 1)),
            Err(Violation::UnknownRecipient { recipient: 77 })
        );
        // State untouched by violations.
        assert_eq!(e.live_channels(), 1);
    }

    #[test]
    fn reply_to_peer_own_open_is_a_violation() {
        let mut e = engine();
        let _ = e.handle_open(&peer_open(3, b"session")).unwrap();
        assert_eq!(
            e.handle_open_confirmation(&confirmation(3, 0)),
            Err(Violation::ReplyToIncoming { recipient: 3 })
        );
    }

    #[test]
    fn peer_number_reuse_is_a_violation() {
        let mut e = engine();
        let _ = e.handle_open(&peer_open(3, b"session")).unwrap();
        assert_eq!(
            e.handle_open(&peer_open(3, b"session")),
            Err(Violation::DuplicatePeerNumber {
                peer_number: PeerNumber(3)
            })
        );
        assert_eq!(e.pending_incoming(), 1);
    }

    #[test]
    fn cancellation_tombstones_number_and_classifies_late_replies() {
        let mut e = engine();
        let h = e.open(session(1)).unwrap();
        let _ = e.next_outgoing();
        e.cancel(h).unwrap();
        assert_eq!(e.phase(h), None);
        assert_eq!(e.pending_outgoing(), 0);
        assert_eq!(e.live_channels(), 0);

        // Late confirmation: reported, with what is needed to close later.
        let ev = e.handle_open_confirmation(&confirmation(0, 8)).unwrap();
        assert_eq!(
            ev,
            Event::LateReply {
                local_number: LocalNumber(0),
                reply: LateReply::Confirmed {
                    peer_number: PeerNumber(8),
                    peer: credit(1000, 500),
                },
            }
        );
        // Tombstone consumed: a second reply is now unknown.
        assert_eq!(
            e.handle_open_confirmation(&confirmation(0, 8)),
            Err(Violation::UnknownRecipient { recipient: 0 })
        );

        // Late failure variant.
        let h = e.open(session(1)).unwrap();
        let _ = e.next_outgoing();
        e.cancel(h).unwrap();
        assert_eq!(
            e.handle_open_failure(&failure(1, 2)).unwrap(),
            Event::LateReply {
                local_number: LocalNumber(1),
                reply: LateReply::Refused { reason_code: 2 },
            }
        );

        // Numbers are never reused, even after cancellation.
        let h = e.open(session(1)).unwrap();
        assert!(matches!(
            e.next_outgoing(),
            Some(Outgoing::Open {
                sender_channel: LocalNumber(2),
                ..
            })
        ));
        assert_eq!(
            e.cancel(h).and_then(|()| e.cancel(h)),
            Err(HandleError::Stale)
        );
    }

    #[test]
    fn tombstone_list_is_bounded() {
        let mut e = OpeningEngine::new(OpeningLimits {
            max_tombstones: 2,
            ..OpeningLimits::default()
        });
        for _ in 0..3 {
            let h = e.open(session(1)).unwrap();
            e.cancel(h).unwrap();
        }
        // Oldest (0) evicted; 1 and 2 remembered.
        assert_eq!(
            e.handle_open_failure(&failure(0, 1)),
            Err(Violation::UnknownRecipient { recipient: 0 })
        );
        assert!(matches!(
            e.handle_open_failure(&failure(1, 1)),
            Ok(Event::LateReply { .. })
        ));
    }

    #[test]
    fn zero_tombstones_forgets_cancelled_numbers_immediately() {
        // Regression: found by the `channel_opening` fuzz target. With
        // `max_tombstones == 0` the engine used to evict before pushing and
        // therefore always kept one tombstone, classifying a late reply as
        // `LateReply` instead of `UnknownRecipient`.
        let mut e = OpeningEngine::new(OpeningLimits {
            max_tombstones: 0,
            ..OpeningLimits::default()
        });
        let h = e.open(session(1)).unwrap();
        let _ = e.next_outgoing();
        e.cancel(h).unwrap();
        assert_eq!(
            e.handle_open_confirmation(&confirmation(0, 1)),
            Err(Violation::UnknownRecipient { recipient: 0 })
        );
        assert_eq!(
            e.handle_open_failure(&failure(0, 1)),
            Err(Violation::UnknownRecipient { recipient: 0 })
        );
        assert_eq!(e.live_channels(), 0);
    }

    #[test]
    fn cancel_requires_pending_outgoing() {
        let mut e = engine();
        let Event::IncomingOpen { handle, .. } = e.handle_open(&peer_open(1, b"session")).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            e.cancel(handle),
            Err(HandleError::WrongPhase {
                actual: Phase::PendingIncoming
            })
        );
        let h = e.open(session(1)).unwrap();
        e.handle_open_confirmation(&confirmation(0, 1)).unwrap();
        assert_eq!(
            e.cancel(h),
            Err(HandleError::WrongPhase {
                actual: Phase::Established
            })
        );
        assert_eq!(
            e.accept(
                h,
                AcceptParams {
                    local: credit(1, 1),
                    type_specific: Vec::new()
                }
            ),
            Err(HandleError::WrongPhase {
                actual: Phase::Established
            })
        );
    }

    #[test]
    fn stale_handle_after_slot_reuse_is_rejected() {
        let mut e = engine();
        let h1 = e.open(session(1)).unwrap();
        e.handle_open_failure(&failure(0, 1)).unwrap();
        let h2 = e.open(session(1)).unwrap();
        // Same slot, new generation.
        assert_ne!(h1, h2);
        assert_eq!(e.cancel(h1), Err(HandleError::Stale));
        assert_eq!(e.phase(h2), Some(Phase::PendingOutgoing));
    }

    #[test]
    fn outgoing_limit_and_channel_limit() {
        let mut e = OpeningEngine::new(OpeningLimits {
            max_pending_outgoing: 2,
            max_channels: 3,
            ..OpeningLimits::default()
        });
        e.open(session(1)).unwrap();
        e.open(session(1)).unwrap();
        assert_eq!(e.open(session(1)), Err(OpenError::TooManyPendingOutgoing));
        e.handle_open_confirmation(&confirmation(0, 0)).unwrap();
        e.handle_open_confirmation(&confirmation(1, 1)).unwrap();
        e.open(session(1)).unwrap();
        e.handle_open_confirmation(&confirmation(2, 2)).unwrap();
        assert_eq!(e.open(session(1)), Err(OpenError::TooManyChannels));
    }

    #[test]
    fn incoming_limit_auto_refuses_with_resource_shortage() {
        let mut e = OpeningEngine::new(OpeningLimits {
            max_pending_incoming: 1,
            ..OpeningLimits::default()
        });
        let _ = e.handle_open(&peer_open(0, b"session")).unwrap();
        let ev = e.handle_open(&peer_open(1, b"session")).unwrap();
        assert_eq!(
            ev,
            Event::IncomingRefusedByLimit {
                peer_number: PeerNumber(1),
                channel_type: b"session".to_vec(),
            }
        );
        assert_eq!(
            e.next_outgoing().unwrap(),
            Outgoing::OpenFailure {
                recipient_channel: PeerNumber(1),
                reason_code: open_failure_reason::RESOURCE_SHORTAGE,
                description: b"too many pending channels".to_vec(),
                language_tag: Vec::new(),
            }
        );
        assert_eq!(e.pending_incoming(), 1);
    }

    #[test]
    fn numbers_exhaust_without_wrapping() {
        let mut e = OpeningEngine::new(OpeningLimits {
            max_pending_outgoing: usize::MAX,
            max_channels: usize::MAX,
            ..OpeningLimits::default()
        });
        e.next_local = u32::MAX - 1;
        let a = e.open(session(1)).unwrap();
        let b = e.open(session(1)).unwrap();
        assert_eq!(e.open(session(1)), Err(OpenError::NumbersExhausted));
        // Cancelling does not bring numbers back.
        e.cancel(a).unwrap();
        e.cancel(b).unwrap();
        assert_eq!(e.open(session(1)), Err(OpenError::NumbersExhausted));
    }

    #[test]
    fn transport_loss_is_distinct_and_clears_everything() {
        let mut e = engine();
        let out = e.open(session(1)).unwrap();
        let Event::IncomingOpen { handle: inc, .. } =
            e.handle_open(&peer_open(0, b"session")).unwrap()
        else {
            panic!()
        };
        let est = e.open(session(1)).unwrap();
        e.handle_open_confirmation(&confirmation(1, 1)).unwrap();

        let events = e.transport_lost();
        assert_eq!(
            events,
            [
                Event::TransportLost {
                    handle: out,
                    phase: Phase::PendingOutgoing
                },
                Event::TransportLost {
                    handle: inc,
                    phase: Phase::PendingIncoming
                },
                Event::TransportLost {
                    handle: est,
                    phase: Phase::Established
                },
            ]
        );
        assert_eq!(e.live_channels(), 0);
        assert_eq!(e.pending_outgoing(), 0);
        assert_eq!(e.pending_incoming(), 0);
        assert!(e.next_outgoing().is_none(), "queued sends discarded");
        assert_eq!(e.phase(est), None);
        assert_eq!(e.cancel(out), Err(HandleError::Stale));
    }

    #[test]
    fn window_fields_are_retained_verbatim_without_semantics() {
        // Zero window and zero max packet are stored, echoed and never
        // interpreted: the engine has no notion of credit.
        let mut e = engine();
        let h = e
            .open(OpenParams {
                channel_type: b"session".to_vec(),
                local: credit(0, 0),
                type_specific: Vec::new(),
            })
            .unwrap();
        assert!(matches!(
            e.next_outgoing(),
            Some(Outgoing::Open { local, .. }) if local == credit(0, 0)
        ));
        let ev = e
            .handle_open_confirmation(&ChannelOpenConfirmation {
                recipient_channel: 0,
                sender_channel: 1,
                initial_window_size: u32::MAX,
                maximum_packet_size: 0,
                type_specific: &[1, 2, 3],
            })
            .unwrap();
        assert!(matches!(
            ev,
            Event::Established { handle, peer, peer_type_specific, .. }
                if handle == h && peer == credit(u32::MAX, 0) && peer_type_specific == [1, 2, 3]
        ));
    }
}
