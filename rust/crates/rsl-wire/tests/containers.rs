//! Golden container vectors (Phase-2 gap closure, item 4a).
//!
//! The `StartContainer`/`CloseContainer` back-patch rule (a caller-chosen
//! 1-byte or 4-byte length field, filled in on close) has no message-level
//! corpus coverage until checkpoint headers arrive in Phase 3, so rsl-linux-proxy
//! emits raw `MarshalData` CONTAINER vectors directly. This harness rebuilds
//! each scenario, keyed by its corpus `DESC`, with the Rust [`Writer`] and
//! requires byte-identical output.

mod common;

use rsl_wire::marshal::Writer;

/// Rebuild the proxy reference scenario named `desc` (see `GenerateContainers` in
/// `tools/linux-proxy/src/main.cpp` — the two must stay in sync).
fn build(desc: &str) -> Writer {
    let mut w = Writer::new();
    match desc {
        "short-empty" => {
            let ph = w.start_container(true);
            w.close_container(ph);
        }
        "short-hello" => {
            let ph = w.start_container(true);
            w.write_data(b"hello");
            w.close_container(ph);
        }
        "short-max-255" => {
            let ramp: Vec<u8> = (0..255).map(|i| i as u8).collect();
            let ph = w.start_container(true);
            w.write_data(&ramp);
            w.close_container(ph);
        }
        "long-empty" => {
            let ph = w.start_container(false);
            w.close_container(ph);
        }
        "long-hello" => {
            let ph = w.start_container(false);
            w.write_data(b"hello");
            w.close_container(ph);
        }
        "long-300" => {
            let ramp: Vec<u8> = (0..300).map(|i| (i & 0xff) as u8).collect();
            let ph = w.start_container(false);
            w.write_data(&ramp);
            w.close_container(ph);
        }
        "nested-long-short" => {
            let outer = w.start_container(false);
            w.write_u32(0xdead_beef);
            let inner = w.start_container(true);
            w.write_data(b"abc");
            w.close_container(inner);
            w.write_u16(0xbeef);
            w.close_container(outer);
        }
        other => panic!("unknown CONTAINER scenario {other:?} — extend build()"),
    }
    w
}

#[test]
fn container_vectors_match_cpp_backpatch() {
    let containers = common::load_containers();
    assert_eq!(containers.len(), 7, "unexpected CONTAINER vector count");
    for c in &containers {
        assert_eq!(c.bytes.len(), c.len, "{}: LEN vs BYTES", c.desc);
        let w = build(&c.desc);
        assert_eq!(
            w.as_bytes(),
            &c.bytes[..],
            "{}: Rust container bytes differ from the proxy reference",
            c.desc
        );
    }
}
