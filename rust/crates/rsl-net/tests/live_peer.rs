//! Portable proxy interop: `rsl-linux-proxy --packet-peer` runs the ported packet
//! receive model over a TCP socket. Production Windows coverage lives in
//! `windows_network_oracle.rs`.
//!
//! The golden vectors prove the bytes agree; this proves the *conversation*
//! does — that a Rust sender's frames are accepted by the proxy receive loop,
//! that frames the proxy produces are accepted here, and that a corrupt frame
//! really does kill the connection rather than resynchronize.
//!
//! The peer binary needs cmake + g++, so these tests skip (with a message) when
//! it has not been built. CI builds it.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rsl_net::framing::{learn, packet};
use rsl_net::Limits;
use rsl_wire::messages::MSG_STATUS_QUERY;
use rsl_wire::{BallotNumber, Header, MemberId, Msg, MsgKind, ProtocolVersion};

/// A spawned peer, killed on drop so a failing assertion cannot leak it.
struct Peer {
    child: Child,
    port: u16,
}

impl Peer {
    /// Start the peer on an ephemeral port and wait for it to announce it.
    fn start(mode: &str) -> Option<Peer> {
        let binary = common::linux_proxy()?;
        let mut child = Command::new(binary)
            .args(["--packet-peer", "0", "--mode", mode])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn rsl-linux-proxy peer");

        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read PORT line");
        let port = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected peer greeting {line:?}"))
            .trim()
            .parse()
            .expect("port number");

        Some(Peer { child, port })
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect to peer");
        // Never let a peer bug hang CI.
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("read timeout");
        stream.set_nodelay(true).expect("nodelay");
        stream
    }

    /// Wait for the peer to exit and assert it did so cleanly.
    fn finish(mut self) {
        let status = self.child.wait().expect("wait for peer");
        assert!(status.success(), "peer exited with {status}");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn message(decree: u64) -> Msg {
    Msg::Base(Header::new(
        ProtocolVersion::V6,
        MSG_STATUS_QUERY,
        MemberId::from_str("101"),
        decree,
        7,
        BallotNumber::new(3, MemberId::from_str("202")),
        0,
    ))
}

/// Rust sends packets, the Linux proxy validates and echoes them, Rust validates the
/// echoes. Both directions of the framing in one round trip.
#[test]
fn packets_survive_a_round_trip_through_the_linux_proxy_peer() {
    let Some(peer) = Peer::start("echo") else {
        common::warn_no_peer("packets_survive_a_round_trip_through_the_linux_proxy_peer");
        return;
    };
    let mut stream = peer.connect();
    let limits = Limits::default();

    // A mix of sizes, including the degenerate bare-header packet.
    let payloads: Vec<Vec<u8>> = (0..8u64)
        .map(|i| match i {
            0 => Vec::new(),
            1 => vec![0xff],
            2 => (0..1024).map(|b| (b & 0xff) as u8).collect(),
            _ => packet_payload(i),
        })
        .collect();

    // Write them all up front: several packets land in one peer read, which is
    // exactly the multi-packet-per-buffer path in NetCxn::ReadReadyInternal.
    let mut out = Vec::new();
    for payload in &payloads {
        out.extend_from_slice(&packet::encode_packet(payload));
    }
    stream.write_all(&out).expect("write packets");
    stream.flush().expect("flush");

    let mut reader = stream.try_clone().expect("clone stream");
    for expected in &payloads {
        let (hdr, payload) = packet::read_packet(&mut reader, &limits)
            .expect("read echo")
            .expect("peer closed early");
        assert_eq!(hdr.size as usize, packet::HDR_LEN + expected.len());
        assert_eq!(&payload, expected);
    }

    drop(reader);
    drop(stream);
    peer.finish();
}

fn packet_payload(decree: u64) -> Vec<u8> {
    message(decree).marshal_with_checksum().expect("marshal")
}

/// A frame with a broken checksum must make the Linux proxy close the connection — not
/// skip the packet, not resynchronize. The proof is that the packet sent *after*
/// the corrupt one is never echoed.
#[test]
fn a_corrupt_packet_closes_the_linux_proxy_connection() {
    let Some(peer) = Peer::start("echo") else {
        common::warn_no_peer("a_corrupt_packet_closes_the_linux_proxy_connection");
        return;
    };
    let mut stream = peer.connect();
    let limits = Limits::default();

    let good = packet::encode_packet(&packet_payload(1));
    let mut corrupt = packet::encode_packet(&packet_payload(2));
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x01;
    let after = packet::encode_packet(&packet_payload(3));

    let mut out = Vec::new();
    out.extend_from_slice(&good);
    out.extend_from_slice(&corrupt);
    out.extend_from_slice(&after);
    // The peer may close mid-write; a broken pipe here is the expected outcome.
    let _ = stream.write_all(&out);
    let _ = stream.flush();

    let mut reader = stream.try_clone().expect("clone stream");
    // The packet before the corrupt one is delivered...
    let (_, echoed) = packet::read_packet(&mut reader, &limits)
        .expect("read echo")
        .expect("peer closed before echoing the good packet");
    assert_eq!(echoed, packet_payload(1));

    // ... and then the connection is gone.
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    assert!(
        rest.is_empty(),
        "peer kept talking after a corrupt packet: {rest:?}"
    );

    drop(reader);
    drop(stream);
    peer.finish();
}

/// A size field outside the cap is rejected on the header alone, before any
/// body is read — the peer must close without waiting for the announced bytes.
#[test]
fn an_out_of_range_size_closes_the_linux_proxy_connection() {
    let Some(peer) = Peer::start("echo") else {
        common::warn_no_peer("an_out_of_range_size_closes_the_linux_proxy_connection");
        return;
    };
    let mut stream = peer.connect();

    let mut frame = packet::encode_packet(&[]);
    frame[0..4].copy_from_slice(&(19u32).to_le_bytes()); // below the header size
    let _ = stream.write_all(&frame);
    let _ = stream.flush();

    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(rest.is_empty(), "peer responded to a bad header: {rest:?}");

    drop(stream);
    peer.finish();
}

/// Learn-model interop: Rust writes a bare marshaled message, and the Linux
/// proxy answers with a `StatusResponse` that
/// Rust parses back.
#[test]
fn the_learn_model_interoperates_with_the_linux_proxy_peer() {
    let Some(peer) = Peer::start("fetch-stub") else {
        common::warn_no_peer("the_learn_model_interoperates_with_the_linux_proxy_peer");
        return;
    };
    let mut stream = peer.connect();

    let request = message(0x1234_5678_9abc_def0);
    let bytes = learn::encode_message(&request).expect("marshal request");
    stream.write_all(&bytes).expect("write request");
    stream.flush().expect("flush");

    let mut reader = stream.try_clone().expect("clone stream");
    let response = learn::read_message(&mut reader, MsgKind::StatusResponse, 1024 * 1024)
        .expect("read response")
        .expect("peer closed without responding");

    let Msg::StatusResponse(status) = response else {
        panic!("expected a StatusResponse");
    };
    // The stub echoes the request's decree and ballot back.
    assert_eq!(status.header.version, ProtocolVersion::V6);
    assert_eq!(status.query_decree, 0x1234_5678_9abc_def0);
    assert_eq!(status.header.decree, 0x1234_5678_9abc_def0);

    drop(reader);
    drop(stream);
    peer.finish();
}

/// A learn-port message the Linux proxy rejects (bad version) must close the connection
/// with no reply.
#[test]
fn a_bad_learn_version_closes_the_linux_proxy_connection() {
    let Some(peer) = Peer::start("fetch-stub") else {
        common::warn_no_peer("a_bad_learn_version_closes_the_linux_proxy_connection");
        return;
    };
    let mut stream = peer.connect();

    let mut bytes = learn::encode_message(&message(1)).expect("marshal");
    bytes[0..2].copy_from_slice(&7u16.to_le_bytes()); // one past the last version
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();

    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(rest.is_empty(), "peer replied to a bad version: {rest:?}");

    drop(stream);
    peer.finish();
}
