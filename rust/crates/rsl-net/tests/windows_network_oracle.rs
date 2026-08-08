//! Authoritative packet interop through production Windows NetPacketSvc/IOCP.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rsl_net::framing::packet;
use rsl_net::svc::{Packet, PacketSvc, SvcConfig, TxRxStatus};

mod harness;
use harness::Recorder;

const TIMEOUT: Duration = Duration::from_secs(30);

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start(mode: &str, count: usize, wait_disconnect: bool) -> Option<Server> {
        let oracle = common::windows_oracle()?;
        let mut child = Command::new(oracle)
            .args([
                "--net-server",
                "0",
                "--mode",
                mode,
                "--count",
                &count.to_string(),
                "--wait-disconnect",
                if wait_disconnect { "yes" } else { "no" },
            ])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn production network server");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read PORT line");
        let port = line
            .strip_prefix("PORT ")
            .unwrap_or_else(|| panic!("unexpected greeting {line:?}"))
            .trim()
            .parse()
            .expect("port");
        Some(Server { child, port })
    }

    fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
    }

    fn finish(mut self) {
        let status = self.child.wait().expect("wait for production server");
        assert!(status.success(), "production server exited {status}");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_packet_service_round_trips_through_production_iocp() {
    let Some(server) = Server::start("echo", 24, false) else {
        eprintln!("production network oracle not requested");
        return;
    };
    let (recorder, mut events) = Recorder::new();
    let svc = PacketSvc::start_as_client(recorder, SvcConfig::default());
    let payloads: Vec<Vec<u8>> = (0..24u32)
        .map(|i| {
            let len = match i % 4 {
                0 => 0,
                1 => 1,
                2 => 1024,
                _ => 64 * 1024,
            };
            let mut payload = vec![i as u8; len];
            if len >= 4 {
                payload[..4].copy_from_slice(&i.to_le_bytes());
            }
            payload
        })
        .collect();

    for payload in &payloads {
        assert_eq!(
            svc.send(
                Arc::new(Packet::to_server(server.addr(), payload.clone())),
                TIMEOUT
            ),
            TxRxStatus::Success
        );
    }
    for _ in &payloads {
        assert_eq!(events.next_send().await.1, TxRxStatus::Success);
    }
    for expected in &payloads {
        assert_eq!(&events.next_receive().await.payload, expected);
    }
    drop(svc);
    server.finish();
}

#[test]
fn fragmented_and_coalesced_frames_reach_production_receive_callbacks() {
    let Some(server) = Server::start("echo", 3, false) else {
        eprintln!("production network oracle not requested");
        return;
    };
    let mut stream = TcpStream::connect(server.addr()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");

    let first = packet::encode_packet(b"fragmented");
    for chunk in first.chunks(3) {
        stream.write_all(chunk).expect("fragment write");
    }
    let second = packet::encode_packet(b"coalesced-a");
    let third = packet::encode_packet(b"coalesced-b");
    stream
        .write_all(&[second, third].concat())
        .expect("coalesced write");

    let limits = rsl_net::Limits::default();
    for expected in [b"fragmented".as_slice(), b"coalesced-a", b"coalesced-b"] {
        let (_, payload) = packet::read_packet(&mut stream, &limits)
            .expect("read echo")
            .expect("closed");
        assert_eq!(payload, expected);
    }
    drop(stream);
    server.finish();
}

#[test]
fn corrupt_checksum_and_truncated_close_are_not_delivered() {
    let Some(server) = Server::start("log", 0, true) else {
        eprintln!("production network oracle not requested");
        return;
    };
    let mut stream = TcpStream::connect(server.addr()).expect("connect");
    let mut corrupt = packet::encode_packet(b"corrupt");
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let _ = stream.write_all(&corrupt);
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    assert!(rest.is_empty());
    drop(stream);
    server.finish();

    let Some(server) = Server::start("log", 0, true) else {
        unreachable!()
    };
    let mut stream = TcpStream::connect(server.addr()).expect("connect");
    let frame = packet::encode_packet(&vec![0x5a; 4096]);
    stream.write_all(&frame[..100]).expect("partial write");
    drop(stream);
    server.finish();
}

#[test]
fn production_client_reuses_and_reconnects_to_rust_server() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production network oracle not requested");
        return;
    };
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept");
            let (_, payload) = packet::read_packet(&mut stream, &rsl_net::Limits::default())
                .expect("read")
                .expect("closed");
            stream
                .write_all(&packet::encode_packet(&payload))
                .expect("echo");
        }
    });
    let output = Command::new(oracle)
        .args([
            "--net-client",
            "127.0.0.1",
            &port.to_string(),
            "--payload",
            "001122ff",
            "--count",
            "3",
            "--expect",
            "echo",
            "--reconnect-each",
            "yes",
        ])
        .output()
        .expect("run production client");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    server.join().expect("join server");
}

#[test]
fn production_client_accepts_fragmented_and_coalesced_rust_frames() {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production network oracle not requested");
        return;
    };
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut echoes = Vec::new();
        for _ in 0..3 {
            let (_, payload) = packet::read_packet(&mut stream, &rsl_net::Limits::default())
                .expect("read")
                .expect("closed");
            echoes.extend_from_slice(&packet::encode_packet(&payload));
        }
        for chunk in echoes.chunks(7) {
            stream.write_all(chunk).expect("fragmented echoes");
        }
    });
    let output = Command::new(oracle)
        .args([
            "--net-client",
            "127.0.0.1",
            &port.to_string(),
            "--payload",
            "deadbeef00",
            "--count",
            "3",
            "--expect",
            "echo",
        ])
        .output()
        .expect("run production client");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    server.join().expect("join server");
}

fn production_client_rejects_rust_response(kind: &str) {
    let Some(oracle) = common::windows_oracle() else {
        eprintln!("production network oracle not requested");
        return;
    };
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().unwrap().port();
    let kind = kind.to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = packet::read_packet(&mut stream, &rsl_net::Limits::default())
            .expect("read")
            .expect("closed");
        let mut response = packet::encode_packet(b"response");
        if kind == "corrupt" {
            let last = response.len() - 1;
            response[last] ^= 1;
            stream.write_all(&response).expect("write corrupt");
        } else {
            stream
                .write_all(&response[..response.len() / 2])
                .expect("write truncated");
        }
    });
    let output = Command::new(oracle)
        .args([
            "--net-client",
            "127.0.0.1",
            &port.to_string(),
            "--payload",
            "010203",
            "--count",
            "1",
            "--expect",
            "disconnect",
        ])
        .output()
        .expect("run production client");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().expect("join server");
}

#[test]
fn production_client_rejects_corrupt_and_truncated_rust_frames() {
    production_client_rejects_rust_response("corrupt");
    production_client_rejects_rust_response("truncated");
}
