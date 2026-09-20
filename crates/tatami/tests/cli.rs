//! End-to-end tests for the `tatami-client` and `tatami-server` binaries.
//!
//! Only compiled with `std,tcp`, which is when the binaries exist. The
//! probe tests use a loopback fixture peer; nothing external is contacted.

#![cfg(all(feature = "std", feature = "tcp"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::thread;

use tatami_tcp::packet::encode_initial_packet;
use tatami_tcp::wire::Writer;

const CLIENT: &str = env!("CARGO_BIN_EXE_tatami-client");
const SERVER: &str = env!("CARGO_BIN_EXE_tatami-server");

fn client(args: &[&str]) -> Output {
    Command::new(CLIENT).args(args).output().unwrap()
}

fn server(args: &[&str]) -> Output {
    Command::new(SERVER).args(args).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn kexinit_packet() -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf);
    w.write_u8(20).unwrap();
    w.write_bytes(&[1; 16]).unwrap();
    w.write_string(b"curve25519-sha256,ext-info-s").unwrap();
    w.write_string(b"ssh-ed25519").unwrap();
    w.write_string(b"aes128-ctr").unwrap();
    w.write_string(b"aes256-ctr").unwrap();
    w.write_string(b"hmac-sha2-256").unwrap();
    w.write_string(b"hmac-sha2-512").unwrap();
    w.write_string(b"none").unwrap();
    w.write_string(b"zlib").unwrap();
    w.write_string(b"").unwrap();
    w.write_string(b"").unwrap();
    w.write_bool(false).unwrap();
    w.write_u32(0).unwrap();
    let payload = w.written().to_vec();
    let mut out = vec![0u8; 600];
    let n = encode_initial_packet(&payload, 0, &mut out).unwrap();
    out.truncate(n);
    out
}

fn read_line(s: &mut TcpStream) {
    let mut b = [0u8; 1];
    let mut got = Vec::new();
    while !got.ends_with(b"\n") {
        s.read_exact(&mut b).unwrap();
        got.push(b[0]);
    }
}

fn fixture_peer<F: FnOnce(TcpStream) + Send + 'static>(script: F) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        script(s);
    });
    (port, h)
}

#[test]
fn client_help_and_version() {
    let o = client(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("tatami-client probe HOST"));

    let o = client(&["--version"]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o).trim(),
        format!("tatami-client {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn client_usage_errors_exit_2() {
    for args in [
        &[][..],
        &["probe"],
        &["probe", "h", "--port", "0"],
        &["probe", "h", "--port", "99999"],
        &["probe", "h", "--read-timeout", "0s"],
        &["probe", "h", "--connect-timeout", "soon"],
        &["probe", "h", "--nope"],
        &["frobnicate", "h"],
    ] {
        let o = client(args);
        assert_eq!(code(&o), 2, "args {args:?}: {}", stderr(&o));
        assert!(stdout(&o).is_empty(), "usage errors must not write stdout");
        assert!(stderr(&o).contains("Usage:"));
    }
}

#[test]
fn client_complete_observation_exits_0() {
    let (port, peer) = fixture_peer(|mut s| {
        read_line(&mut s);
        s.write_all(b"Banner \x1b[31mred\x1b[0m\r\nSSH-2.0-Fixture_2 c\"omment\r\n")
            .unwrap();
        s.write_all(&kexinit_packet()).unwrap();
    });
    let o = client(&[
        "probe",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--read-timeout",
        "5s",
    ]);
    peer.join().unwrap();
    let out = stdout(&o);
    assert_eq!(code(&o), 0, "stdout:\n{out}\nstderr:\n{}", stderr(&o));
    assert!(out.contains("Server identification: SSH-2.0-Fixture_2 c\"omment"));
    assert!(out.contains("comments: \"c\\\"omment\""));
    assert!(out.contains("pre-identification line: \"Banner \\x1b[31mred\\x1b[0m\""));
    assert!(
        !out.contains('\x1b'),
        "escape sequences must not reach stdout"
    );
    assert!(out.contains("Observation: complete"));
    assert!(out.contains("KEX algorithms, in advertised order: [curve25519-sha256, ext-info-s]"));
    assert!(out.contains("ext-info-s: server extension-negotiation marker"));
    assert!(out.contains("Ciphers client->server: [aes128-ctr]"));
    assert!(out.contains("Ciphers server->client: [aes256-ctr]"));
    assert!(out.contains("Compression server->client: [zlib]"));
    assert!(out.contains("Key exchange: not performed"));
    assert!(out.contains("Server public key / fingerprint: not obtained"));
    assert!(!out.to_lowercase().contains("negotiated"));
}

#[test]
fn client_partial_observation_exits_1() {
    let (port, peer) = fixture_peer(|mut s| {
        read_line(&mut s);
        s.write_all(b"SSH-2.0-OnlyIdent\r\n").unwrap();
        let mut sink = [0u8; 8];
        let _ = s.read(&mut sink); // wait for client to close
    });
    let o = client(&[
        "probe",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--read-timeout",
        "300ms",
    ]);
    peer.join().unwrap();
    let out = stdout(&o);
    assert_eq!(code(&o), 1, "{out}");
    assert!(out.contains("Server identification: SSH-2.0-OnlyIdent"));
    assert!(out.contains("Observation: incomplete; deadline passed while awaiting server KEXINIT"));
    assert!(!out.contains("Initial server proposal"));
    assert!(stderr(&o).contains("observation incomplete"));
}

#[test]
fn client_connect_failure_exits_1() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let o = client(&[
        "probe",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--connect-timeout",
        "2s",
    ]);
    assert_eq!(code(&o), 1);
    assert!(stdout(&o).contains("Connected to: (not connected)"));
    assert!(stdout(&o).contains("Observation: not connected"));
}

#[test]
fn client_disconnect_exits_1() {
    let (port, peer) = fixture_peer(|mut s| {
        read_line(&mut s);
        s.write_all(b"SSH-2.0-Refuser\r\n").unwrap();
        let payload = [
            1, 0, 0, 0, 12, 0, 0, 0, 4, b'b', b'u', b's', b'y', 0, 0, 0, 0,
        ];
        let mut out = [0u8; 64];
        let n = encode_initial_packet(&payload, 0, &mut out).unwrap();
        s.write_all(&out[..n]).unwrap();
    });
    let o = client(&["probe", "127.0.0.1", "--port", &port.to_string()]);
    peer.join().unwrap();
    assert_eq!(code(&o), 1);
    assert!(stdout(&o).contains(
        "Observation: server disconnected; reason 12 (SSH_DISCONNECT_TOO_MANY_CONNECTIONS): \"busy\""
    ));
}

#[test]
fn server_stub_behaviour() {
    let o = server(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("entry-point stub"));

    let o = server(&["--version"]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o).trim(),
        format!("tatami-server {}", env!("CARGO_PKG_VERSION"))
    );

    let o = server(&[]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("not implemented"));
    assert!(stdout(&o).is_empty());

    let o = server(&["--listen", "0.0.0.0:22"]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("unknown option"));
}
