//! In-memory pairing of a [`ServerCore`] and a [`ClientCore`]: datagrams
//! move through `Vec` queues under a virtual clock, so handshakes, failures
//! and deadlines can be tested without sockets or real time.
//!
//! Addresses are labels only; nothing is bound. Every payload that crosses
//! the "wire" is kept in [`Pair::wire`] so tests can assert on bytes (for
//! example, that no `SSH-` identification is ever sent).

use std::net::SocketAddr;
use std::string::{String, ToString as _};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{Connection, ConnectionHandle, DatagramEvent, Endpoint, Event};

use super::client::{ClientCore, ClientOutcome, DiagClientConfig};
use super::server::{DiagServerConfig, HandshakeObservation, ServerCore, connection_error_text};
use super::{ConfigError, Datagram, QUIC_VERSION_1, endpoint_config, transport_config};

/// Direction of a captured datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client to server.
    ToServer,
    /// Server to client.
    ToClient,
}

/// One captured datagram.
#[derive(Clone, Debug)]
pub struct Captured {
    /// Direction.
    pub direction: Direction,
    /// Virtual time of delivery.
    pub at: Instant,
    /// Payload.
    pub payload: Vec<u8>,
}

/// A server and a client exchanging datagrams in memory.
pub struct Pair {
    /// Server core.
    pub server: ServerCore,
    /// Client core.
    pub client: ClientCore,
    /// Virtual clock.
    pub now: Instant,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    to_server: Vec<Datagram>,
    to_client: Vec<Datagram>,
    /// Server observations decided so far.
    pub observations: Vec<HandshakeObservation>,
    /// Every datagram delivered, in order.
    pub wire: Vec<Captured>,
    /// When set, datagrams in this direction are dropped instead of
    /// delivered (still captured).
    pub drop: Option<Direction>,
}

impl Pair {
    /// Builds both cores. `client_config.remote` must equal
    /// `server_config.bind`; the client is given `client_addr`.
    pub fn new(
        server_config: &DiagServerConfig,
        client_config: &DiagClientConfig,
        client_addr: SocketAddr,
    ) -> Result<Self, ConfigError> {
        let now = Instant::now();
        let server = ServerCore::new(server_config, server_config.bind)?;
        let mut to_server = Vec::new();
        let client = ClientCore::new(client_config, now, &mut to_server)?;
        Ok(Pair {
            server,
            client,
            now,
            server_addr: server_config.bind,
            client_addr,
            to_server,
            to_client: Vec::new(),
            observations: Vec::new(),
            wire: Vec::new(),
            drop: None,
        })
    }

    /// Delivers queued datagrams in both directions, then, if nothing was
    /// pending, advances the virtual clock to the next timer and fires it.
    /// Returns `false` when the client is finished.
    pub fn step(&mut self) -> bool {
        if self.client.is_finished() {
            return false;
        }
        let mut moved = false;
        while !self.to_server.is_empty() || !self.to_client.is_empty() {
            moved = true;
            for d in core::mem::take(&mut self.to_server) {
                debug_assert_eq!(d.destination, self.server_addr);
                self.wire.push(Captured {
                    direction: Direction::ToServer,
                    at: self.now,
                    payload: d.payload.clone(),
                });
                if self.drop != Some(Direction::ToServer) {
                    self.server.handle_datagram(
                        self.now,
                        self.client_addr,
                        &d.payload,
                        &mut self.to_client,
                    );
                    self.observations.extend(self.server.drain_observations());
                }
            }
            for d in core::mem::take(&mut self.to_client) {
                debug_assert_eq!(d.destination, self.client_addr);
                self.wire.push(Captured {
                    direction: Direction::ToClient,
                    at: self.now,
                    payload: d.payload.clone(),
                });
                if self.drop != Some(Direction::ToClient) {
                    self.client.handle_datagram(
                        self.now,
                        self.server_addr,
                        &d.payload,
                        &mut self.to_server,
                    );
                }
            }
        }
        if !moved {
            let next = [self.server.next_timeout(), self.client.next_timeout()]
                .into_iter()
                .flatten()
                .min();
            self.now = match next {
                Some(t) if t > self.now => t,
                _ => self.now + Duration::from_millis(1),
            };
            self.server.handle_timeouts(self.now, &mut self.to_client);
            self.observations.extend(self.server.drain_observations());
            self.client.handle_timeouts(self.now, &mut self.to_server);
        }
        true
    }

    /// Steps until the client finishes or `max_steps` is reached. Returns
    /// `true` if the client finished.
    pub fn run(&mut self, max_steps: usize) -> bool {
        for _ in 0..max_steps {
            if !self.step() {
                return true;
            }
        }
        self.client.is_finished()
    }

    /// Advances the virtual clock by `d` and fires timers once.
    pub fn advance(&mut self, d: Duration) {
        self.now += d;
        self.server.handle_timeouts(self.now, &mut self.to_client);
        self.observations.extend(self.server.drain_observations());
        self.client.handle_timeouts(self.now, &mut self.to_server);
    }

    /// Finishes the client and returns its outcome.
    #[must_use]
    pub fn finish_client(self) -> (ClientOutcome, Vec<HandshakeObservation>, Vec<Captured>) {
        let Pair {
            client,
            now,
            client_addr,
            observations,
            wire,
            ..
        } = self;
        (client.finish(now, Some(client_addr)), observations, wire)
    }
}

/// Result of [`raw_handshake`]: both connections and how each side ended.
pub struct RawHandshake {
    /// Client connection (owned with its endpoint so it stays valid).
    pub client: Connection,
    /// Server connection, if `Endpoint::accept` succeeded.
    pub server: Option<Connection>,
    /// `Ok(())` if the client saw `Connected`, else the loss reason.
    pub client_result: Result<(), String>,
    /// `Ok(())` if the server saw `Connected`, else the accept or loss
    /// reason.
    pub server_result: Result<(), String>,
    /// Datagrams exchanged.
    pub datagrams: usize,
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
}

impl RawHandshake {
    /// `true` when both sides completed.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.client_result.is_ok() && self.server_result.is_ok()
    }

    /// Keeps the endpoints alive for the connections' lifetime.
    #[must_use]
    pub fn endpoints(&self) -> (&Endpoint, &Endpoint) {
        (&self.client_endpoint, &self.server_endpoint)
    }
}

struct RawSide {
    endpoint: Endpoint,
    conn: Option<(ConnectionHandle, Connection)>,
    connected: bool,
    lost: Option<String>,
    buf: Vec<u8>,
}

impl RawSide {
    fn drive(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        let Some((ch, conn)) = self.conn.as_mut() else {
            return;
        };
        while let Some(ev) = conn.poll_endpoint_events() {
            if let Some(ce) = self.endpoint.handle_event(*ch, ev) {
                conn.handle_event(ce);
            }
        }
        while let Some(ev) = conn.poll() {
            match ev {
                Event::Connected => self.connected = true,
                Event::ConnectionLost { reason } => {
                    self.lost
                        .get_or_insert_with(|| connection_error_text(&reason));
                }
                _ => {}
            }
        }
        loop {
            self.buf.clear();
            match conn.poll_transmit(now, 1, &mut self.buf) {
                Some(t) => out.push(self.buf[..t.size].to_vec()),
                None => break,
            }
        }
    }

    fn done(&self) -> bool {
        self.connected || self.lost.is_some()
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        self.conn.as_mut().and_then(|(_, c)| c.poll_timeout())
    }
}

/// Drives two raw `quinn-proto` endpoints built from the given crypto
/// configs through a handshake in memory. Stops when both sides have either
/// connected or been lost, or after `max_steps`.
pub fn raw_handshake(
    client_crypto: Arc<QuicClientConfig>,
    server_crypto: Arc<QuicServerConfig>,
    server_name: &str,
    handshake_timeout: Duration,
    max_steps: usize,
) -> Result<RawHandshake, ConfigError> {
    let s_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 4433));
    let c_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 50_000));
    let mut now = Instant::now();
    let transport = transport_config(handshake_timeout)?;

    let mut sc = quinn_proto::ServerConfig::with_crypto(server_crypto);
    sc.transport_config(transport.clone());
    let mut server = RawSide {
        endpoint: Endpoint::new(endpoint_config(), Some(Arc::new(sc)), false, None),
        conn: None,
        connected: false,
        lost: None,
        buf: Vec::new(),
    };

    let mut cc = quinn_proto::ClientConfig::new(client_crypto);
    cc.transport_config(transport);
    cc.version(QUIC_VERSION_1);
    let mut client_endpoint = Endpoint::new(endpoint_config(), None, false, None);
    let (ch, conn) = client_endpoint
        .connect(now, cc, s_addr, server_name)
        .map_err(|e| ConfigError::Quic(e.to_string()))?;
    let mut client = RawSide {
        endpoint: client_endpoint,
        conn: Some((ch, conn)),
        connected: false,
        lost: None,
        buf: Vec::new(),
    };

    let mut to_server: Vec<Vec<u8>> = Vec::new();
    let mut to_client: Vec<Vec<u8>> = Vec::new();
    let mut datagrams = 0;
    client.drive(now, &mut to_server);
    for _ in 0..max_steps {
        if client.done() && (server.done() || (client.lost.is_some() && server.conn.is_none())) {
            break;
        }
        if to_server.is_empty() && to_client.is_empty() {
            let next = [client.next_timeout(), server.next_timeout()]
                .into_iter()
                .flatten()
                .min();
            now = match next {
                Some(t) if t > now => t,
                _ => now + Duration::from_millis(1),
            };
            for side in [&mut client, &mut server] {
                if let Some((_, c)) = side.conn.as_mut() {
                    if c.poll_timeout().is_some_and(|t| t <= now) {
                        c.handle_timeout(now);
                    }
                }
            }
            client.drive(now, &mut to_server);
            server.drive(now, &mut to_client);
            continue;
        }
        for d in core::mem::take(&mut to_server) {
            datagrams += 1;
            server.buf.clear();
            match server.endpoint.handle(
                now,
                c_addr,
                Some(s_addr.ip()),
                None,
                d[..].into(),
                &mut server.buf,
            ) {
                Some(DatagramEvent::ConnectionEvent(_, ev)) => {
                    if let Some((_, c)) = server.conn.as_mut() {
                        c.handle_event(ev);
                    }
                }
                Some(DatagramEvent::NewConnection(incoming)) => {
                    server.buf.clear();
                    match server.endpoint.accept(incoming, now, &mut server.buf, None) {
                        Ok(pair) => server.conn = Some(pair),
                        Err(e) => {
                            if let Some(t) = e.response {
                                to_client.push(server.buf[..t.size].to_vec());
                            }
                            server.lost = Some(connection_error_text(&e.cause));
                        }
                    }
                }
                Some(DatagramEvent::Response(t)) => to_client.push(server.buf[..t.size].to_vec()),
                None => {}
            }
            server.drive(now, &mut to_client);
        }
        for d in core::mem::take(&mut to_client) {
            datagrams += 1;
            client.buf.clear();
            if let Some(DatagramEvent::ConnectionEvent(_, ev)) =
                client
                    .endpoint
                    .handle(now, s_addr, None, None, d[..].into(), &mut client.buf)
            {
                if let Some((_, c)) = client.conn.as_mut() {
                    c.handle_event(ev);
                }
            }
            client.drive(now, &mut to_server);
        }
    }
    let result = |side: &RawSide| -> Result<(), String> {
        if side.connected {
            Ok(())
        } else {
            Err(side
                .lost
                .clone()
                .unwrap_or_else(|| String::from("handshake did not finish within the step budget")))
        }
    };
    let client_result = result(&client);
    let server_result = result(&server);
    let (_, client_conn) = client
        .conn
        .take()
        .ok_or(ConfigError::Quic("client connection missing".to_string()))?;
    Ok(RawHandshake {
        client: client_conn,
        server: server.conn.take().map(|(_, c)| c),
        client_result,
        server_result,
        datagrams,
        client_endpoint: client.endpoint,
        server_endpoint: server.endpoint,
    })
}

/// Runs a client against nothing: every datagram is dropped. Returns the
/// outcome (expected `TimedOut`) and the virtual time consumed.
pub fn run_client_into_blackhole(
    config: &DiagClientConfig,
    max_steps: usize,
) -> Result<(ClientOutcome, Duration), ConfigError> {
    let start = Instant::now();
    let mut now = start;
    let mut out = Vec::new();
    let mut client = ClientCore::new(config, now, &mut out)?;
    for _ in 0..max_steps {
        out.clear();
        if client.is_finished() {
            break;
        }
        now = match client.next_timeout() {
            Some(t) if t > now => t,
            _ => now + Duration::from_millis(1),
        };
        client.handle_timeouts(now, &mut out);
    }
    Ok((
        client.finish(now, None),
        now.saturating_duration_since(start),
    ))
}
