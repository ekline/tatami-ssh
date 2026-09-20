//! Helpers for the channel-opening and JSON/report targets.
//!
//! Harness-only code; never a dependency of a production package.
//!
//! - [`opening_model`]: an independent model of the channel-opening engine
//!   (`tatami_connection::opening`) written from its documented contract. It
//!   keys state by protocol identities (local numbers, peer numbers, handles
//!   as opaque tokens) rather than mirroring the engine's slot/generation
//!   bookkeeping, and predicts every result, event and outgoing message.
//! - [`json_ref`]: an independent RFC 8259 reference for `tatami::json`: a
//!   shadow tree, a compact serializer, a string tokenizer/unescaper and an
//!   inverse of the `tatami::text` terminal escaping.
//! - [`record_ref`]: independent RFC 3339 formatting (Fliegel–Van Flandern),
//!   the closed sets of stable codes an observer record may contain, and the
//!   size bound of a truncated observation record.

/// Independent model of `tatami_connection::opening::OpeningEngine`.
pub mod opening_model {
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

    use tatami_connection::opening::{
        AcceptParams, ChannelHandle, Credit, Event, HandleError, LateReply, LocalNumber, OpenError,
        OpenParams, OpeningEngine, OpeningLimits, Outgoing, PeerNumber, Phase, Violation,
    };
    use tatami_wire::EncodeError;
    use tatami_wire::channel::{
        ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure, open_failure_reason,
    };

    /// Description the engine attaches to an automatic limit refusal.
    pub const LIMIT_REFUSAL_DESCRIPTION: &[u8] = b"too many pending channels";
    /// Description the engine attaches when `accept` finds no local number.
    pub const EXHAUSTED_REFUSAL_DESCRIPTION: &[u8] = b"channel numbers exhausted";

    // Finding history: with `max_tombstones == 0` the engine used to keep one
    // tombstone (evict-before-push). Fixed in `tatami-connection` with the
    // regression test `zero_tombstones_forgets_cancelled_numbers_immediately`;
    // the model now follows the documented capacity exactly.

    #[derive(Clone, Debug)]
    struct PendingOut {
        handle: ChannelHandle,
        channel_type: Vec<u8>,
        local: Credit,
    }

    #[derive(Clone, Debug)]
    struct PendingIn {
        channel_type: Vec<u8>,
        peer: Credit,
    }

    #[derive(Clone, Debug)]
    struct Established {
        peer: PeerNumber,
    }

    /// Where a live handle currently is (key into the respective map).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Live {
        Out(u32),
        In(u32),
        Est(u32),
    }

    /// The model. See the module docs of `tatami_connection::opening` for
    /// the contract this encodes.
    #[derive(Clone, Debug)]
    pub struct Model {
        limits: OpeningLimits,
        /// Next local number to allocate; `u64` so exhaustion is representable.
        next_local: u64,
        /// Pending outgoing opens keyed by our local number.
        pending_out: BTreeMap<u32, PendingOut>,
        /// Pending incoming opens keyed by the peer's number.
        pending_in: BTreeMap<u32, PendingIn>,
        /// Established channels keyed by our local number.
        established: BTreeMap<u32, Established>,
        /// Cancelled local numbers, oldest first, bounded.
        tombstones: VecDeque<u32>,
        /// Messages the engine must hand out next, in order.
        expected_outgoing: VecDeque<Outgoing>,
        /// Every handle the engine ever issued, in issue order.
        handles: Vec<ChannelHandle>,
        /// Live handles and where they are.
        live: HashMap<ChannelHandle, Live>,
        /// Local numbers seen as `sender channel` in drained outgoing
        /// messages, for the never-reissued check.
        wire_locals: BTreeSet<u32>,
        last_wire_local: Option<u32>,
    }

    impl Model {
        /// Model of a fresh engine with `limits`.
        #[must_use]
        pub fn new(limits: OpeningLimits) -> Self {
            Model {
                limits,
                next_local: 0,
                pending_out: BTreeMap::new(),
                pending_in: BTreeMap::new(),
                established: BTreeMap::new(),
                tombstones: VecDeque::new(),
                expected_outgoing: VecDeque::new(),
                handles: Vec::new(),
                live: HashMap::new(),
                wire_locals: BTreeSet::new(),
                last_wire_local: None,
            }
        }

        // ----- queries used by the harness to pick interesting inputs -----

        /// Channels in any live phase.
        #[must_use]
        pub fn live_count(&self) -> usize {
            self.pending_out.len() + self.pending_in.len() + self.established.len()
        }

        /// Every handle ever issued.
        #[must_use]
        pub fn handles(&self) -> &[ChannelHandle] {
            &self.handles
        }

        /// Handles that are currently live, in issue order.
        #[must_use]
        pub fn live_handles(&self) -> Vec<ChannelHandle> {
            self.handles
                .iter()
                .copied()
                .filter(|h| self.live.contains_key(h))
                .collect()
        }

        /// Local numbers of pending outgoing opens.
        #[must_use]
        pub fn pending_out_numbers(&self) -> Vec<u32> {
            self.pending_out.keys().copied().collect()
        }

        /// Local numbers of established channels.
        #[must_use]
        pub fn established_numbers(&self) -> Vec<u32> {
            self.established.keys().copied().collect()
        }

        /// Remembered cancelled local numbers.
        #[must_use]
        pub fn tombstoned_numbers(&self) -> Vec<u32> {
            self.tombstones.iter().copied().collect()
        }

        /// Peer numbers currently in use (pending incoming or established).
        #[must_use]
        pub fn in_use_peer_numbers(&self) -> Vec<u32> {
            let mut v: Vec<u32> = self.pending_in.keys().copied().collect();
            v.extend(self.established.values().map(|e| e.peer.0));
            v
        }

        /// Local numbers that were allocated and are no longer pending,
        /// established or tombstoned: a reply naming one must be
        /// `UnknownRecipient`.
        #[must_use]
        pub fn retired_numbers(&self) -> Vec<u32> {
            (0..self.next_local)
                .map(|n| n as u32)
                .filter(|n| {
                    !self.pending_out.contains_key(n)
                        && !self.established.contains_key(n)
                        && !self.tombstones.contains(n)
                })
                .collect()
        }

        /// Next local number the engine will allocate.
        #[must_use]
        pub fn next_local(&self) -> u64 {
            self.next_local
        }

        /// Phase of `handle` according to the model.
        #[must_use]
        pub fn phase(&self, handle: ChannelHandle) -> Option<Phase> {
            self.live.get(&handle).map(|l| match l {
                Live::Out(_) => Phase::PendingOutgoing,
                Live::In(_) => Phase::PendingIncoming,
                Live::Est(_) => Phase::Established,
            })
        }

        // ----- internals -----

        fn allocate(&mut self) -> Option<u32> {
            if self.next_local > u64::from(u32::MAX) {
                return None;
            }
            let n = self.next_local as u32;
            self.next_local += 1;
            Some(n)
        }

        fn note_fresh_handle(&mut self, h: ChannelHandle, at: Live) {
            assert!(
                !self.handles.contains(&h),
                "handle {h:?} was issued before; handles must never be reissued"
            );
            self.handles.push(h);
            let prev = self.live.insert(h, at);
            assert!(prev.is_none());
        }

        fn tombstone(&mut self, n: u32) {
            self.tombstones.push_back(n);
            while self.tombstones.len() > self.limits.max_tombstones {
                self.tombstones.pop_front();
            }
        }

        fn phase_error(&self, handle: ChannelHandle, wanted: Phase) -> Result<(), HandleError> {
            match self.phase(handle) {
                Some(actual) if actual == wanted => Ok(()),
                Some(actual) => Err(HandleError::WrongPhase { actual }),
                None => Err(HandleError::Stale),
            }
        }

        // ----- application commands -----

        /// Checks the result of `engine.open(params)`.
        pub fn open(&mut self, params: &OpenParams, result: &Result<ChannelHandle, OpenError>) {
            let expected_err = if self.pending_out.len() >= self.limits.max_pending_outgoing {
                Some(OpenError::TooManyPendingOutgoing)
            } else if self.live_count() >= self.limits.max_channels {
                Some(OpenError::TooManyChannels)
            } else if self.next_local > u64::from(u32::MAX) {
                Some(OpenError::NumbersExhausted)
            } else {
                None
            };
            match (expected_err, result) {
                (Some(e), Err(actual)) => assert_eq!(*actual, e, "open error"),
                (None, Ok(h)) => {
                    let n = self.allocate().expect("checked above");
                    self.note_fresh_handle(*h, Live::Out(n));
                    self.pending_out.insert(
                        n,
                        PendingOut {
                            handle: *h,
                            channel_type: params.channel_type.clone(),
                            local: params.local,
                        },
                    );
                    self.expected_outgoing.push_back(Outgoing::Open {
                        channel_type: params.channel_type.clone(),
                        sender_channel: LocalNumber(n),
                        local: params.local,
                        type_specific: params.type_specific.clone(),
                    });
                }
                (e, r) => panic!("open: model expected error {e:?}, engine returned {r:?}"),
            }
        }

        /// Checks the result of `engine.cancel(handle)`.
        pub fn cancel(&mut self, handle: ChannelHandle, result: &Result<(), HandleError>) {
            let expected = self.phase_error(handle, Phase::PendingOutgoing);
            assert_eq!(*result, expected, "cancel({handle:?})");
            if expected.is_ok() {
                let Some(Live::Out(n)) = self.live.remove(&handle) else {
                    unreachable!()
                };
                self.pending_out
                    .remove(&n)
                    .expect("pending outgoing present");
                self.tombstone(n);
            }
        }

        /// Checks the result of `engine.accept(handle, params)`.
        pub fn accept(
            &mut self,
            handle: ChannelHandle,
            params: &AcceptParams,
            result: &Result<Event, HandleError>,
        ) {
            if let Err(e) = self.phase_error(handle, Phase::PendingIncoming) {
                assert_eq!(*result, Err(e), "accept({handle:?})");
                return;
            }
            let Some(Live::In(peer)) = self.live.remove(&handle) else {
                unreachable!()
            };
            let pin = self
                .pending_in
                .remove(&peer)
                .expect("pending incoming present");
            match self.allocate() {
                None => {
                    // Number exhaustion on accept is surfaced as a refusal.
                    assert_eq!(*result, Err(HandleError::Stale));
                    self.expected_outgoing.push_back(Outgoing::OpenFailure {
                        recipient_channel: PeerNumber(peer),
                        reason_code: open_failure_reason::RESOURCE_SHORTAGE,
                        description: EXHAUSTED_REFUSAL_DESCRIPTION.to_vec(),
                        language_tag: Vec::new(),
                    });
                }
                Some(n) => {
                    let expected = Event::Established {
                        handle,
                        channel_type: pin.channel_type,
                        local_number: LocalNumber(n),
                        peer_number: PeerNumber(peer),
                        local: params.local,
                        peer: pin.peer,
                        peer_type_specific: Vec::new(),
                    };
                    assert_eq!(*result, Ok(expected), "accept({handle:?})");
                    self.live.insert(handle, Live::Est(n));
                    self.established.insert(
                        n,
                        Established {
                            peer: PeerNumber(peer),
                        },
                    );
                    self.expected_outgoing
                        .push_back(Outgoing::OpenConfirmation {
                            recipient_channel: PeerNumber(peer),
                            sender_channel: LocalNumber(n),
                            local: params.local,
                            type_specific: params.type_specific.clone(),
                        });
                }
            }
        }

        /// Checks the result of `engine.refuse(handle, reason_code, description)`.
        pub fn refuse(
            &mut self,
            handle: ChannelHandle,
            reason_code: u32,
            description: &[u8],
            result: &Result<(), HandleError>,
        ) {
            let expected = self.phase_error(handle, Phase::PendingIncoming);
            assert_eq!(*result, expected, "refuse({handle:?})");
            if expected.is_ok() {
                let Some(Live::In(peer)) = self.live.remove(&handle) else {
                    unreachable!()
                };
                self.pending_in
                    .remove(&peer)
                    .expect("pending incoming present");
                self.expected_outgoing.push_back(Outgoing::OpenFailure {
                    recipient_channel: PeerNumber(peer),
                    reason_code,
                    description: description.to_vec(),
                    language_tag: Vec::new(),
                });
            }
        }

        /// Checks the events of `engine.transport_lost()`: exactly one
        /// `TransportLost` per live channel with its phase (order is the
        /// engine's business), then everything live is gone and the queued
        /// outgoing messages are discarded. Tombstones survive: the number
        /// space is never reset, so a late reply is still classifiable.
        pub fn transport_lost(&mut self, events: &[Event]) {
            let mut expected: Vec<(ChannelHandle, Phase)> = self
                .live
                .iter()
                .map(|(h, l)| {
                    (
                        *h,
                        match l {
                            Live::Out(_) => Phase::PendingOutgoing,
                            Live::In(_) => Phase::PendingIncoming,
                            Live::Est(_) => Phase::Established,
                        },
                    )
                })
                .collect();
            for ev in events {
                let Event::TransportLost { handle, phase } = ev else {
                    panic!("transport_lost produced a non-TransportLost event: {ev:?}")
                };
                let pos = expected
                    .iter()
                    .position(|e| e == &(*handle, *phase))
                    .unwrap_or_else(|| panic!("unexpected or duplicate TransportLost {ev:?}"));
                expected.swap_remove(pos);
            }
            assert!(
                expected.is_empty(),
                "live channels without a TransportLost event: {expected:?}"
            );
            self.pending_out.clear();
            self.pending_in.clear();
            self.established.clear();
            self.live.clear();
            self.expected_outgoing.clear();
        }

        // ----- peer messages -----

        /// Checks the result of `engine.handle_open(msg)`.
        pub fn peer_open(&mut self, msg: &ChannelOpen<'_>, result: &Result<Event, Violation>) {
            let peer = msg.sender_channel;
            let credit = Credit {
                initial_window_size: msg.initial_window_size,
                maximum_packet_size: msg.maximum_packet_size,
            };
            if self.pending_in.contains_key(&peer)
                || self.established.values().any(|e| e.peer.0 == peer)
            {
                assert_eq!(
                    *result,
                    Err(Violation::DuplicatePeerNumber {
                        peer_number: PeerNumber(peer)
                    }),
                    "peer reused sender {peer}"
                );
            } else if self.pending_in.len() >= self.limits.max_pending_incoming
                || self.live_count() >= self.limits.max_channels
            {
                assert_eq!(
                    *result,
                    Ok(Event::IncomingRefusedByLimit {
                        peer_number: PeerNumber(peer),
                        channel_type: msg.channel_type.to_vec(),
                    }),
                    "incoming open at limit"
                );
                self.expected_outgoing.push_back(Outgoing::OpenFailure {
                    recipient_channel: PeerNumber(peer),
                    reason_code: open_failure_reason::RESOURCE_SHORTAGE,
                    description: LIMIT_REFUSAL_DESCRIPTION.to_vec(),
                    language_tag: Vec::new(),
                });
            } else {
                let Ok(Event::IncomingOpen {
                    handle,
                    channel_type,
                    peer_number,
                    peer: got_credit,
                    type_specific,
                }) = result
                else {
                    panic!("expected IncomingOpen, engine returned {result:?}")
                };
                assert_eq!(channel_type, msg.channel_type);
                assert_eq!(*peer_number, PeerNumber(peer));
                assert_eq!(*got_credit, credit, "peer credit must be echoed verbatim");
                assert_eq!(type_specific, msg.type_specific);
                self.note_fresh_handle(*handle, Live::In(peer));
                self.pending_in.insert(
                    peer,
                    PendingIn {
                        channel_type: msg.channel_type.to_vec(),
                        peer: credit,
                    },
                );
            }
        }

        /// Where a reply naming `recipient` lands, per the contract.
        fn reply_target(&mut self, recipient: u32) -> Result<ReplyTarget, Violation> {
            if self.pending_out.contains_key(&recipient) {
                return Ok(ReplyTarget::Pending);
            }
            if self.established.contains_key(&recipient) {
                return Err(Violation::DuplicateReply {
                    local_number: LocalNumber(recipient),
                });
            }
            if let Some(pos) = self.tombstones.iter().position(|&n| n == recipient) {
                self.tombstones.remove(pos);
                return Ok(ReplyTarget::Tombstone);
            }
            // A number we never allocated that names a pending incoming open
            // is the peer answering its own request. A number we did
            // allocate (below `next_local`) is simply unknown by now.
            if u64::from(recipient) >= self.next_local && self.pending_in.contains_key(&recipient) {
                return Err(Violation::ReplyToIncoming { recipient });
            }
            Err(Violation::UnknownRecipient { recipient })
        }

        /// Checks the result of `engine.handle_open_confirmation(msg)`.
        pub fn peer_confirm(
            &mut self,
            msg: &ChannelOpenConfirmation<'_>,
            result: &Result<Event, Violation>,
        ) {
            let r = msg.recipient_channel;
            let peer = PeerNumber(msg.sender_channel);
            let credit = Credit {
                initial_window_size: msg.initial_window_size,
                maximum_packet_size: msg.maximum_packet_size,
            };
            match self.reply_target(r) {
                Ok(ReplyTarget::Pending) => {
                    let p = self.pending_out.remove(&r).expect("pending");
                    let expected = Event::Established {
                        handle: p.handle,
                        channel_type: p.channel_type,
                        local_number: LocalNumber(r),
                        peer_number: peer,
                        local: p.local,
                        peer: credit,
                        peer_type_specific: msg.type_specific.to_vec(),
                    };
                    assert_eq!(*result, Ok(expected), "confirmation of {r}");
                    self.live.insert(p.handle, Live::Est(r));
                    self.established.insert(r, Established { peer });
                }
                Ok(ReplyTarget::Tombstone) => assert_eq!(
                    *result,
                    Ok(Event::LateReply {
                        local_number: LocalNumber(r),
                        reply: LateReply::Confirmed {
                            peer_number: peer,
                            peer: credit,
                        },
                    }),
                    "late confirmation of {r}"
                ),
                Err(v) => assert_eq!(*result, Err(v), "confirmation of {r}"),
            }
        }

        /// Checks the result of `engine.handle_open_failure(msg)`.
        pub fn peer_fail(
            &mut self,
            msg: &ChannelOpenFailure<'_>,
            result: &Result<Event, Violation>,
        ) {
            let r = msg.recipient_channel;
            match self.reply_target(r) {
                Ok(ReplyTarget::Pending) => {
                    let p = self.pending_out.remove(&r).expect("pending");
                    self.live.remove(&p.handle);
                    let expected = Event::Refused {
                        handle: p.handle,
                        reason_code: msg.reason_code,
                        description: msg.description.to_vec(),
                        language_tag: msg.language_tag.to_vec(),
                    };
                    assert_eq!(*result, Ok(expected), "failure for {r}");
                }
                Ok(ReplyTarget::Tombstone) => assert_eq!(
                    *result,
                    Ok(Event::LateReply {
                        local_number: LocalNumber(r),
                        reply: LateReply::Refused {
                            reason_code: msg.reason_code,
                        },
                    }),
                    "late failure for {r}"
                ),
                Err(v) => assert_eq!(*result, Err(v), "failure for {r}"),
            }
        }

        // ----- outgoing queue and state comparison -----

        /// Checks one `engine.next_outgoing()` result against the expected
        /// queue (`None` means both must be empty) and the never-reissued
        /// rule for local numbers on the wire.
        pub fn check_outgoing(&mut self, actual: Option<&Outgoing>) {
            let expected = self.expected_outgoing.pop_front();
            assert_eq!(actual, expected.as_ref(), "outgoing message");
            let wire_local = match actual {
                Some(Outgoing::Open { sender_channel, .. })
                | Some(Outgoing::OpenConfirmation { sender_channel, .. }) => Some(sender_channel.0),
                _ => None,
            };
            if let Some(n) = wire_local {
                if let Some(last) = self.last_wire_local {
                    assert!(n > last, "local number {n} not above previous {last}");
                }
                assert!(self.wire_locals.insert(n), "local number {n} reissued");
                self.last_wire_local = Some(n);
            }
        }

        /// Compares the engine's counters and every issued handle's phase
        /// with the model.
        pub fn check_state(&self, engine: &OpeningEngine) {
            assert_eq!(engine.live_channels(), self.live_count(), "live_channels");
            assert_eq!(
                engine.pending_outgoing(),
                self.pending_out.len(),
                "pending_outgoing"
            );
            assert_eq!(
                engine.pending_incoming(),
                self.pending_in.len(),
                "pending_incoming"
            );
            for &h in &self.handles {
                assert_eq!(engine.phase(h), self.phase(h), "phase of {h:?}");
            }
        }
    }

    enum ReplyTarget {
        Pending,
        Tombstone,
    }

    /// Encodes `out` with the engine's codec and decodes it with the wire
    /// codecs, asserting every field round-trips and that an undersized
    /// buffer is reported rather than truncated.
    pub fn check_wire_roundtrip(out: &Outgoing) {
        let mut buf = [0u8; 2048];
        let n = out.encode(&mut buf).expect("encode into a large buffer");
        let expected_len = match out {
            Outgoing::Open {
                channel_type,
                type_specific,
                ..
            } => 1 + 4 + channel_type.len() + 12 + type_specific.len(),
            Outgoing::OpenConfirmation { type_specific, .. } => 1 + 16 + type_specific.len(),
            Outgoing::OpenFailure {
                description,
                language_tag,
                ..
            } => 1 + 8 + 4 + description.len() + 4 + language_tag.len(),
        };
        assert_eq!(n, expected_len, "encoded length of {out:?}");
        match out {
            Outgoing::Open {
                channel_type,
                sender_channel,
                local,
                type_specific,
            } => {
                let d = ChannelOpen::decode(&buf[..n]).expect("decode OPEN");
                assert_eq!(d.channel_type, &channel_type[..]);
                assert_eq!(d.sender_channel, sender_channel.0);
                assert_eq!(d.initial_window_size, local.initial_window_size);
                assert_eq!(d.maximum_packet_size, local.maximum_packet_size);
                assert_eq!(d.type_specific, &type_specific[..]);
            }
            Outgoing::OpenConfirmation {
                recipient_channel,
                sender_channel,
                local,
                type_specific,
            } => {
                let d = ChannelOpenConfirmation::decode(&buf[..n]).expect("decode CONFIRMATION");
                assert_eq!(d.recipient_channel, recipient_channel.0);
                assert_eq!(d.sender_channel, sender_channel.0);
                assert_eq!(d.initial_window_size, local.initial_window_size);
                assert_eq!(d.maximum_packet_size, local.maximum_packet_size);
                assert_eq!(d.type_specific, &type_specific[..]);
            }
            Outgoing::OpenFailure {
                recipient_channel,
                reason_code,
                description,
                language_tag,
            } => {
                let d = ChannelOpenFailure::decode(&buf[..n]).expect("decode FAILURE");
                assert_eq!(d.recipient_channel, recipient_channel.0);
                assert_eq!(d.reason_code, *reason_code);
                assert_eq!(d.description, &description[..]);
                assert_eq!(d.language_tag, &language_tag[..]);
            }
        }
        let mut short = vec![0u8; n - 1];
        assert!(
            matches!(
                out.encode(&mut short),
                Err(EncodeError::InsufficientCapacity { .. })
            ),
            "encoding into {} bytes must fail for {out:?}",
            n - 1
        );
    }
}

/// Independent RFC 8259 reference for `tatami::json` and `tatami::text`.
pub mod json_ref {
    /// Shadow of a `tatami::json::Value`, built by the harness alongside the
    /// production value.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Node {
        /// `null`
        Null,
        /// `true`/`false`
        Bool(bool),
        /// Unsigned integer.
        UInt(u64),
        /// Signed integer.
        Int(i64),
        /// String.
        Str(String),
        /// Array.
        Array(Vec<Node>),
        /// Object with insertion order (duplicates allowed).
        Object(Vec<(String, Node)>),
    }

    impl Node {
        /// Number of nodes in the tree (this one included).
        #[must_use]
        pub fn count(&self) -> usize {
            match self {
                Node::Array(items) => 1 + items.iter().map(Node::count).sum::<usize>(),
                Node::Object(fields) => 1 + fields.iter().map(|(_, v)| v.count()).sum::<usize>(),
                _ => 1,
            }
        }

        /// Maximum nesting depth (a scalar has depth 1).
        #[must_use]
        pub fn depth(&self) -> usize {
            match self {
                Node::Array(items) => 1 + items.iter().map(Node::depth).max().unwrap_or(0),
                Node::Object(fields) => {
                    1 + fields.iter().map(|(_, v)| v.depth()).max().unwrap_or(0)
                }
                _ => 1,
            }
        }
    }

    /// Compact serialization per RFC 8259: no whitespace, `"`/`\` and
    /// U+0000–U+001F escaped (short forms for `\b \f \n \r \t`, lowercase
    /// `\u00xx` otherwise), everything else raw UTF-8, integers in decimal.
    #[must_use]
    pub fn serialize(node: &Node) -> String {
        let mut out = String::new();
        write_node(node, &mut out);
        out
    }

    fn write_node(node: &Node, out: &mut String) {
        match node {
            Node::Null => out.push_str("null"),
            Node::Bool(true) => out.push_str("true"),
            Node::Bool(false) => out.push_str("false"),
            Node::UInt(n) => out.push_str(&n.to_string()),
            Node::Int(n) => out.push_str(&n.to_string()),
            Node::Str(s) => write_string(s, out),
            Node::Array(items) => {
                out.push('[');
                let mut first = true;
                for item in items {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    write_node(item, out);
                }
                out.push(']');
            }
            Node::Object(fields) => {
                out.push('{');
                let mut first = true;
                for (k, v) in fields {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    write_string(k, out);
                    out.push(':');
                    write_node(v, out);
                }
                out.push('}');
            }
        }
    }

    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

    /// Appends the JSON string literal for `s`.
    pub fn write_string(s: &str, out: &mut String) {
        out.push('"');
        let mut start = 0;
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            let esc: Option<&str> = match b {
                b'"' => Some("\\\""),
                b'\\' => Some("\\\\"),
                b'\n' => Some("\\n"),
                b'\r' => Some("\\r"),
                b'\t' => Some("\\t"),
                0x08 => Some("\\b"),
                0x0c => Some("\\f"),
                _ => None,
            };
            if esc.is_none() && b >= 0x20 {
                continue;
            }
            out.push_str(&s[start..i]);
            match esc {
                Some(e) => out.push_str(e),
                None => {
                    out.push_str("\\u00");
                    out.push(char::from(HEX_LOWER[usize::from(b >> 4)]));
                    out.push(char::from(HEX_LOWER[usize::from(b & 0x0f)]));
                }
            }
            start = i + 1;
        }
        out.push_str(&s[start..]);
        out.push('"');
    }

    /// Semantic conversion for comparison with what `serde_json` parsed.
    /// Duplicate keys resolve last-wins, as `serde_json::Map` does.
    #[must_use]
    pub fn to_serde(node: &Node) -> serde_json::Value {
        match node {
            Node::Null => serde_json::Value::Null,
            Node::Bool(b) => serde_json::Value::Bool(*b),
            Node::UInt(n) => serde_json::Value::from(*n),
            Node::Int(n) => serde_json::Value::from(*n),
            Node::Str(s) => serde_json::Value::String(s.clone()),
            Node::Array(items) => serde_json::Value::Array(items.iter().map(to_serde).collect()),
            Node::Object(fields) => {
                let mut map = serde_json::Map::new();
                for (k, v) in fields {
                    map.insert(k.clone(), to_serde(v));
                }
                serde_json::Value::Object(map)
            }
        }
    }

    /// Every string in the tree in serialization order: object keys
    /// immediately before their values, array items in order.
    pub fn collect_strings(node: &Node, out: &mut Vec<String>) {
        match node {
            Node::Str(s) => out.push(s.clone()),
            Node::Array(items) => items.iter().for_each(|i| collect_strings(i, out)),
            Node::Object(fields) => {
                for (k, v) in fields {
                    out.push(k.clone());
                    collect_strings(v, out);
                }
            }
            _ => {}
        }
    }

    fn hex_digit(b: u8) -> u32 {
        match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'f' => u32::from(b - b'a' + 10),
            b'A'..=b'F' => u32::from(b - b'A' + 10),
            _ => panic!("not a hex digit: {b:#04x}"),
        }
    }

    fn hex4(b: &[u8]) -> u32 {
        assert!(b.len() >= 4, "truncated \\u escape");
        b[..4].iter().fold(0, |acc, &d| (acc << 4) | hex_digit(d))
    }

    /// Tokenizes a compact JSON text and returns the unescaped content of
    /// every string literal in order. Panics on anything RFC 8259 forbids in
    /// the serializer's output: raw bytes below 0x20 anywhere, unknown
    /// escapes (including the terminal `\xNN` convention), truncated `\u`
    /// escapes, lone surrogates or an unterminated string.
    #[must_use]
    pub fn scan_strings(json: &str) -> Vec<String> {
        let b = json.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            assert!(
                c >= 0x20,
                "raw control byte {c:#04x} at {i} outside a string"
            );
            if c != b'"' {
                i += 1;
                continue;
            }
            i += 1;
            let mut s = String::new();
            loop {
                assert!(i < b.len(), "unterminated string literal");
                let c = b[i];
                match c {
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b'\\' => {
                        let e = *b.get(i + 1).expect("dangling backslash");
                        i += 2;
                        match e {
                            b'"' => s.push('"'),
                            b'\\' => s.push('\\'),
                            b'/' => s.push('/'),
                            b'b' => s.push('\u{8}'),
                            b'f' => s.push('\u{c}'),
                            b'n' => s.push('\n'),
                            b'r' => s.push('\r'),
                            b't' => s.push('\t'),
                            b'u' => {
                                let cp = hex4(&b[i..]);
                                i += 4;
                                if (0xD800..0xDC00).contains(&cp) {
                                    assert!(
                                        b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u'),
                                        "high surrogate without a low surrogate"
                                    );
                                    let lo = hex4(&b[i + 2..]);
                                    i += 6;
                                    assert!((0xDC00..0xE000).contains(&lo), "bad low surrogate");
                                    let cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    s.push(char::from_u32(cp).expect("valid scalar"));
                                } else {
                                    s.push(
                                        char::from_u32(cp)
                                            .unwrap_or_else(|| panic!("lone surrogate {cp:#06x}")),
                                    );
                                }
                            }
                            other => panic!(
                                "invalid JSON escape \\{} at {i} (terminal \\xNN escapes must never appear in JSON)",
                                char::from(other)
                            ),
                        }
                    }
                    c if c < 0x20 => panic!("raw control byte {c:#04x} at {i} inside a string"),
                    _ => {
                        let ch = json[i..].chars().next().expect("char boundary");
                        s.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            out.push(s);
        }
        out
    }

    /// Inverse of `tatami::text::escape_bytes` (`quotes_escaped == false`)
    /// and of the inside of `tatami::text::quoted` (`quotes_escaped == true`).
    /// Panics if the text is not printable ASCII or an escape is malformed.
    #[must_use]
    pub fn unescape_terminal(s: &str, quotes_escaped: bool) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            assert!(
                (0x20..=0x7e).contains(&c),
                "terminal escaping emitted non-printable byte {c:#04x}"
            );
            if c == b'"' && quotes_escaped {
                panic!("unescaped quote inside quoted() output at {i}");
            }
            if c != b'\\' {
                out.push(c);
                i += 1;
                continue;
            }
            let e = *b.get(i + 1).expect("dangling backslash");
            match e {
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'"' if quotes_escaped => {
                    out.push(b'"');
                    i += 2;
                }
                b'x' => {
                    let hi = *b.get(i + 2).expect("\\x needs two digits");
                    let lo = *b.get(i + 3).expect("\\x needs two digits");
                    out.push((hex_digit(hi) << 4 | hex_digit(lo)) as u8);
                    i += 4;
                }
                other => panic!("unknown terminal escape \\{}", char::from(other)),
            }
        }
        out
    }

    /// Decodes lowercase hex; panics on odd length or non-lowercase digits.
    #[must_use]
    pub fn decode_hex_lower(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        assert!(b.len().is_multiple_of(2), "hex has odd length {}", b.len());
        b.chunks(2)
            .map(|pair| {
                for &d in pair {
                    assert!(
                        d.is_ascii_digit() || (b'a'..=b'f').contains(&d),
                        "hex digit {d:#04x} is not lowercase hex"
                    );
                }
                (hex_digit(pair[0]) << 4 | hex_digit(pair[1])) as u8
            })
            .collect()
    }
}

/// Independent references for the observer's JSON records.
pub mod record_ref {
    use std::time::Duration;

    /// `event` values.
    pub const EVENT_NAMES: [&str; 4] = [
        "listener_started",
        "connection_observation",
        "overload",
        "listener_stopped",
    ];

    /// `stage` values.
    pub const STAGE_CODES: [&str; 3] = ["client_identification", "initial_packets", "finished"];

    /// `outcome` values.
    pub const OUTCOME_CODES: [&str; 10] = [
        "banner_only",
        "proposal",
        "proposal_with_anomalies",
        "disconnected",
        "unexpected_input",
        "eof",
        "protocol_error",
        "timeout",
        "shutdown",
        "io_error",
    ];

    /// Fixed `reason` values. The only non-fixed form is `disconnect_<u32>`.
    pub const FIXED_REASON_CODES: [&str; 24] = [
        "not_ssh_identification",
        "eof_at_boundary",
        "eof_truncated",
        "connection_deadline",
        "listener_stopping",
        "connection_reset",
        "connection_aborted",
        "broken_pipe",
        "timed_out",
        "io_other",
        "ident_prelude_line_too_long",
        "ident_too_many_prelude_lines",
        "ident_prelude_too_large",
        "ident_too_long",
        "ident_invalid",
        "ident_unsupported_version",
        "packet_framing",
        "packet_empty_payload",
        "message_malformed",
        "message_unexpected",
        "unsupported_transition",
        "packet_budget_exceeded",
        "byte_budget_exceeded",
        "input_overflow",
    ];

    /// `listener_stopped.reason` values.
    pub const STOP_REASON_CODES: [&str; 5] = [
        "run_duration_elapsed",
        "connection_limit_reached",
        "stop_requested",
        "sink_failed",
        "accept_failed",
    ];

    /// `client_identification.anomalies` values.
    pub const IDENT_ANOMALY_CODES: [&str; 2] = ["lf_only_terminator", "compatibility_version_1_99"];

    /// `proposal.anomalies` values.
    pub const PROPOSAL_ANOMALY_CODES: [&str; 2] =
        ["kexinit_nonzero_reserved", "kexinit_empty_algorithm_list"];

    /// `kex_markers[].kind` values with the names that produce them.
    pub const KEX_MARKERS: [(&str, &str); 4] = [
        ("ext-info-c", "ext_info_client"),
        ("ext-info-s", "ext_info_server"),
        ("kex-strict-c-v00@openssh.com", "strict_kex_client"),
        ("kex-strict-s-v00@openssh.com", "strict_kex_server"),
    ];

    /// Registered `SSH_MSG_DISCONNECT` reason names (RFC 4253 §11.1), index
    /// = code - 1.
    pub const DISCONNECT_NAMES: [&str; 15] = [
        "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
        "SSH_DISCONNECT_PROTOCOL_ERROR",
        "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
        "SSH_DISCONNECT_RESERVED",
        "SSH_DISCONNECT_MAC_ERROR",
        "SSH_DISCONNECT_COMPRESSION_ERROR",
        "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
        "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
        "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
        "SSH_DISCONNECT_CONNECTION_LOST",
        "SSH_DISCONNECT_BY_APPLICATION",
        "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
        "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
        "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
        "SSH_DISCONNECT_ILLEGAL_USER_NAME",
    ];

    /// Name for a disconnect reason code, if registered.
    #[must_use]
    pub fn disconnect_name(code: u32) -> Option<&'static str> {
        usize::try_from(code)
            .ok()
            .and_then(|c| c.checked_sub(1))
            .and_then(|i| DISCONNECT_NAMES.get(i).copied())
    }

    /// `true` if `reason` is a fixed code or a canonical `disconnect_<u32>`.
    #[must_use]
    pub fn reason_is_known(reason: &str) -> bool {
        if FIXED_REASON_CODES.contains(&reason) {
            return true;
        }
        reason
            .strip_prefix("disconnect_")
            .is_some_and(|n| n.parse::<u32>().is_ok_and(|v| v.to_string() == n))
    }

    /// RFC 3339 UTC with millisecond precision, from seconds since the Unix
    /// epoch, using the Fliegel–Van Flandern Julian-day conversion (an
    /// algorithm unrelated to the production `civil_from_days`).
    #[must_use]
    pub fn rfc3339(since_epoch: Duration) -> String {
        let secs = since_epoch.as_secs();
        let millis = since_epoch.subsec_millis();
        let days = i64::try_from(secs / 86_400).expect("u64 seconds / 86400 fits i64");
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }

    /// Fliegel & Van Flandern (1968) Julian Day Number to Gregorian date.
    /// `days` is the count since 1970-01-01 (JDN 2 440 588); valid for any
    /// non-negative JDN, which covers every `u64` seconds value.
    #[must_use]
    pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
        let jd = days + 2_440_588;
        assert!(jd >= 0, "algorithm is for non-negative Julian day numbers");
        let l = jd + 68_569;
        let n = 4 * l / 146_097;
        let l = l - (146_097 * n + 3) / 4;
        let i = 4000 * (l + 1) / 1_461_001;
        let l = l - 1461 * i / 4 + 31;
        let j = 80 * l / 2447;
        let d = l - 2447 * j / 80;
        let l = j / 11;
        let m = j + 2 - 12 * l;
        let y = 100 * (n - 49) + i + l;
        (y, m, d)
    }

    /// Shape check for the envelope's `time` (current wall clock, so only
    /// the format can be asserted): `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    #[must_use]
    pub fn looks_like_rfc3339(s: &str) -> bool {
        let b = s.as_bytes();
        if b.len() != 24 {
            return false;
        }
        let digit = |i: usize| b[i].is_ascii_digit();
        let lit = |i: usize, c: u8| b[i] == c;
        (0..4).all(digit)
            && lit(4, b'-')
            && digit(5)
            && digit(6)
            && lit(7, b'-')
            && digit(8)
            && digit(9)
            && lit(10, b'T')
            && digit(11)
            && digit(12)
            && lit(13, b':')
            && digit(14)
            && digit(15)
            && lit(16, b':')
            && digit(17)
            && digit(18)
            && lit(19, b'.')
            && digit(20)
            && digit(21)
            && digit(22)
            && lit(23, b'Z')
    }

    /// Worst-case JSON length of a string built from `raw_len` untrusted
    /// bytes via `lossy_text` (U+FFFD is 3 bytes; a control byte becomes
    /// the 6-byte `\u00xx`), or of a `String` of `raw_len` bytes.
    #[must_use]
    pub const fn json_text_bound(raw_len: usize) -> usize {
        6 * raw_len
    }

    /// Raw-field bounds a truncated observation record depends on. Only
    /// `line_hex` and the `diagnostics` text fields are bounded by
    /// `max_field`; `line`, `comments`, the version tokens and the server
    /// identification are emitted in full.
    #[derive(Clone, Copy, Debug)]
    pub struct FieldBounds {
        /// `Encoder::max_field_bytes`.
        pub max_field: usize,
        /// Raw bytes of `server_identification`.
        pub server_identification: usize,
        /// Raw bytes of the client identification line.
        pub line: usize,
        /// Bytes of `protocol_version`.
        pub protocol_version: usize,
        /// Bytes of `software_version`.
        pub software_version: usize,
        /// Raw bytes of the comments.
        pub comments: usize,
        /// JSON-escaped length of `detail`.
        pub detail_json: usize,
        /// Raw bytes, after clipping to `max_field`, of the `diagnostics`
        /// fields rendered as lossy text (disconnect `description` and
        /// `language_tag`, or the unexpected-input `sample`). At most
        /// `2 * max_field`.
        pub diagnostic_text: usize,
        /// Raw bytes, after clipping, of the `diagnostics` fields rendered
        /// as hex (the unexpected-input `sample_hex`). At most `max_field`.
        pub diagnostic_hex: usize,
    }

    impl FieldBounds {
        /// The bounds for a deployment: `max_field`, the largest raw client
        /// identification line (`max_identification_line - 2`), and our own
        /// identification line. The version tokens and comments partition
        /// the line; the diagnostics take the disconnect worst case.
        #[must_use]
        pub const fn deployment(
            max_field: usize,
            identification_line: usize,
            server_identification: usize,
        ) -> Self {
            FieldBounds {
                max_field,
                server_identification,
                line: identification_line,
                protocol_version: 0,
                software_version: 0,
                comments: identification_line,
                detail_json: 128,
                diagnostic_text: 2 * max_field,
                diagnostic_hex: 0,
            }
        }
    }

    /// Everything in a truncated record that does not depend on
    /// [`FieldBounds`], at its worst case: all 23 keys, the envelope with a
    /// 4-digit year, two IPv6 addresses with scope ids and 5-digit ports, a
    /// 12-digit year in `accepted_at`, 20-digit counters, the longest
    /// `stage`/`outcome`/`reason` codes, both identification anomalies, and
    /// the `disconnected` diagnostics object (the largest) minus its
    /// `max_field`-bounded text. Hand-counted 1071; rounded up.
    pub const TRUNCATED_FIXED_BOUND: usize = 1100;

    /// Upper bound on `to_json().len()` of a truncated observation record
    /// (`messages: []`, `proposal: null`). `Encoder::encode` output never
    /// exceeds `max_record_bytes` when `max_record_bytes >= this`.
    #[must_use]
    pub const fn truncated_record_bound(b: &FieldBounds) -> usize {
        TRUNCATED_FIXED_BOUND
            + json_text_bound(b.server_identification)
            + json_text_bound(b.line)
            + 2 * if b.line < b.max_field {
                b.line
            } else {
                b.max_field
            }
            + json_text_bound(b.protocol_version)
            + json_text_bound(b.software_version)
            + json_text_bound(b.comments)
            + b.detail_json
            + json_text_bound(b.diagnostic_text)
            + 2 * b.diagnostic_hex
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rfc3339_known_values() {
            assert_eq!(rfc3339(Duration::ZERO), "1970-01-01T00:00:00.000Z");
            assert_eq!(
                rfc3339(Duration::from_secs(951_868_800)),
                "2000-03-01T00:00:00.000Z"
            );
            assert_eq!(
                rfc3339(Duration::from_millis(1_789_907_696_789)),
                "2026-09-20T12:34:56.789Z"
            );
            assert_eq!(
                rfc3339(Duration::from_secs(1_709_251_199)),
                "2024-02-29T23:59:59.000Z"
            );
            assert_eq!(
                rfc3339(Duration::from_secs(u64::from(u32::MAX))),
                "2106-02-07T06:28:15.000Z"
            );
            assert_eq!(
                rfc3339(Duration::from_secs(253_402_300_799)),
                "9999-12-31T23:59:59.000Z"
            );
        }

        #[test]
        fn civil_from_days_matches_day_counting() {
            // Independent third opinion: count days month by month.
            let is_leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let mdays = |y: i64, m: i64| match m {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                _ => {
                    if is_leap(y) {
                        29
                    } else {
                        28
                    }
                }
            };
            let (mut y, mut m, mut d) = (1970, 1, 1);
            for day in 0..200_000i64 {
                assert_eq!(civil_from_days(day), (y, m, d), "day {day}");
                d += 1;
                if d > mdays(y, m) {
                    d = 1;
                    m += 1;
                    if m > 12 {
                        m = 1;
                        y += 1;
                    }
                }
            }
        }

        /// Builds the largest truncated record for a client identification
        /// line of `line_len` raw bytes and `Encoder::max_field_bytes == f`:
        /// worst-case fixed fields, control bytes (6x expansion) in every
        /// untrusted text, both identification anomalies, a disconnect with
        /// the longest registered name and `f`-byte description and tag.
        fn worst_truncated_record(f: usize, line_len: usize) -> (usize, usize) {
            use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
            use tatami::server::observe::observation_record;
            use tatami_tcp::ident::{LineTerminator, OwnedIdentification, VersionSupport};
            use tatami_tcp::initial::SkippedMessage;
            use tatami_tcp::io::{Observation, ObservationEnd};
            use tatami_tcp::observer::{ObservationOutcome, ObserverStage};

            let addr = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ),
                65535,
                0,
                u32::MAX,
            ));
            let prefix = b"SSH-2.0-\" ";
            let comments = vec![0x01u8; line_len.saturating_sub(prefix.len())];
            let mut line = prefix.to_vec();
            line.extend_from_slice(&comments);
            let o = Observation {
                id: u64::MAX,
                local: addr,
                peer: addr,
                accepted_unix: Duration::new(u64::MAX, 999_999_999),
                elapsed: Duration::new(u64::MAX, 999_999_999),
                bytes_read: u64::MAX,
                bytes_written: u64::MAX,
                server_identification: vec![0x01; 253],
                client_identification: Some(OwnedIdentification {
                    line: line.clone(),
                    terminator: LineTerminator::Lf,
                    protocol_version: String::from("2.0"),
                    software_version: String::from("\""),
                    comments: Some(comments.clone()),
                    support: VersionSupport::Ssh2Compatibility,
                }),
                messages: vec![
                    SkippedMessage::Debug {
                        always_display: true,
                        message: vec![0x01; 4096],
                        language_tag: vec![0x01; 64],
                    };
                    16
                ],
                proposal: None,
                stage: ObserverStage::ClientIdentification,
                end: ObservationEnd::Observer(ObservationOutcome::Disconnected {
                    reason_code: 14,
                    description: vec![0x01; f],
                    language_tag: vec![0x01; f],
                }),
            };
            let truncated = observation_record(&o, f, true).to_json().len();
            let bound = truncated_record_bound(&FieldBounds::deployment(f, line_len, 253));
            (truncated, bound)
        }

        #[test]
        fn truncated_record_sizes() {
            // (max_field_bytes, raw identification line length).
            let configs = [
                (512, 253),
                (512, 2000),
                (4096, 2000),
                (4096, 253),
                (8, 253),
                (0, 253),
                (0, 0),
            ];
            for (f, line) in configs {
                let (truncated, bound) = worst_truncated_record(f, line);
                println!(
                    "max_field={f:>5} line={line:>5}: truncated record {truncated:>6} bytes, deployment bound {bound:>6}"
                );
                assert!(truncated <= bound, "bound too small for f={f} line={line}");
            }
        }

        #[test]
        fn reason_pattern() {
            assert!(reason_is_known("disconnect_0"));
            assert!(reason_is_known("disconnect_4294967295"));
            assert!(!reason_is_known("disconnect_04"));
            assert!(!reason_is_known("disconnect_4294967296"));
            assert!(!reason_is_known("disconnect_"));
            assert!(reason_is_known("ident_invalid"));
            assert!(!reason_is_known("timeout"));
        }
    }
}
