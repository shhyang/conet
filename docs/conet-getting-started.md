<!--
Designated User Guide
Copyright (c) 2026 Shenghao Yang
License (this file only): You may copy and redistribute this guide with
attribution and this notice retained. AI/ML training on this guide is not
permitted. Review that restriction for your jurisdiction / use case if you
rely on it.
-->

# Conet getting started

This guide covers the Conet crates: how to build them, what they do, and short
examples. For layering and how paths are formed, see
[`conet-design-overview.md`](conet-design-overview.md).

**Version target:** workspace `0.1.1` (research MVP; APIs may change).
Software: AGPL-3.0-only (see root `LICENSE`). Doc terms: notice above.

---

## What you get

| Crate | Role |
| --- | --- |
| `conet_core` | Packets, queues, clocks, link traits, wire helpers, reliability core, `TxController` / `RxController`, `FixedRateController` |
| `conet_udp` | UDP-LI endpoints: association, pacing, queues, sim and loopback transports |
| `conet_fountain` | Raptor-10 `BlockCodec` for file blocks |
| `conet_transfer` | Reference one-block file transfer (CLI + library) |
| `conet_cc` | CC hook re-exports + **CUBIC-style** and **BBR-style** controllers and ACK feedback (`AckReceiver`) |
| `conet_mux` | Simple end-host multiplexer (several users on one lower hop) |
| `conet_sim` | Deterministic path model (rate, delay, drop-tail, loss) for `LinkEndpoint` tests |

**Default pacing:** endpoints use a fixed byte rate unless you install another
`TxController` (for example CUBIC or BBR from `conet_cc`).

---

## Build

From the repository root (or your extracted public workspace):

```bash
cargo build -p conet_transfer --release
cargo test -p conet_core -p conet_udp -p conet_fountain -p conet_transfer -p conet_cc -p conet_mux -p conet_sim
```

Binary:

```bash
cargo run -p conet_transfer -- --help
```

---

## Two-host LAN and public↔NAT

Operator details for `send` / `recv`, open-loop vs closed-loop, and the
retained NAT path (NAT sends first; public host learns the observed source)
are in [user/conet-transfer.md](user/conet-transfer.md).

## Quick start: file transfer CLI

`conet_transfer` moves one file as a single reliability block. Default policy is
**one-way / open-loop** (sender stops after a symbol budget). Use
`--closed-loop` for reverse ACK/NACK feedback.

### Simulated path (deterministic, in-process)

```bash
# Write a small input
echo 'hello conet' > /tmp/hello.txt

cargo run -p conet_transfer -- simulate /tmp/hello.txt --output /tmp/hello.out

# Optional: drop every Nth forward data datagram; opt into ACK/NACK
cargo run -p conet_transfer -- simulate /tmp/hello.txt \
  --loss-every 5 --budget 200 --closed-loop --output /tmp/hello.out
```

### Loopback UDP (127.0.0.1 only)

```bash
cargo run -p conet_transfer -- loopback /tmp/hello.txt --output /tmp/hello.out
cargo run -p conet_transfer -- loopback /tmp/hello.txt --closed-loop --output /tmp/hello.out
```

Successful runs print a one-line report (`recovered=true`, sizes, symbol counts).

### Library entry points

```rust
use conet_transfer::{FileTransferConfig, SimulatorImpairment, run_simulated_transfer};

let config = FileTransferConfig {
    closed_loop: false,           // default
    one_way_symbol_budget: None,  // auto budget if None
    target_rate: 1_000_000,       // bytes/s for FixedRateController
    ..FileTransferConfig::default()
};
let impairment = SimulatorImpairment {
    forward_loss_every: Some(10),
    ..SimulatorImpairment::default()
};
let report = run_simulated_transfer("hello.txt", b"hello conet", config, impairment)?;
assert_eq!(report.recovered_file, b"hello conet");
```

Loopback:

```rust
use conet_transfer::{FileTransferConfig, run_loopback_transfer};

let report = run_loopback_transfer("hello.txt", b"hello conet", FileTransferConfig::default())?;
assert!(report.recovered_file == b"hello conet");
```

---

## Basic building blocks

### Time and drive

Tests and the simulator advance **logical** time. Call `drive(now)` (or the
endpoint’s drive helper) with a `MonoNs` timestamp; do not rely on wall-clock
sleeps for correctness.

```rust
use conet_core::MonoNs;

let now = MonoNs::new(0);
let later = MonoNs::new(10_000_000); // 10 ms
```

### Packets

Build a payload handle, then enqueue it on a link or UDP-LI endpoint:

```rust
use conet_udp::payload_packet;

let pkt = payload_packet(b"user-bytes");
```

### Fixed-rate controller

```rust
use conet_core::FixedRateController;

let tx = FixedRateController::new(1_000_000); // bytes per second
```

### UDP-LI endpoint (simulator)

```rust
use conet_core::FixedRateController;
use conet_udp::{EndpointConfig, Role, SimNetwork, UdpLiEndpoint, payload_packet};

let network = SimNetwork::new();
network.set_authenticated(true); // test / sim convenience

let mut a = UdpLiEndpoint::with_controllers(
    network.transport(0),
    EndpointConfig::new(Role::Initiator, 1_000_000),
    Box::new(FixedRateController::new(1_000_000)),
    None,
);
let mut b = UdpLiEndpoint::with_controllers(
    network.transport(1),
    EndpointConfig::new(Role::Responder, u64::MAX),
    Box::new(FixedRateController::new(u64::MAX)),
    None,
);

a.establish_for_test(0x1111, 1).unwrap();
b.establish_for_test(0x1111, 1).unwrap();

a.enqueue_file_data(payload_packet(b"ping")).unwrap();
a.drive(conet_core::MonoNs::ZERO);
b.drive(conet_core::MonoNs::new(1_000_000));
let got = b.take_received();
assert_eq!(got[0].packet.payload_bytes(), b"ping");
```

`establish_for_test` is for harnesses. Production-shaped code should run the
OPEN/ACCEPT handshake over the transport instead.

### Fountain codec (optional direct use)

```rust
use conet_core::{BlockId, PayloadCopyCounter};
use conet_fountain::{FountainBlockCodec, FountainCodecConfig};

let mut codec = FountainBlockCodec::new(
    FountainCodecConfig {
        symbol_len: 256,
        minimum_source_symbols: 4,
    },
    PayloadCopyCounter::new(),
)
.unwrap();
codec.add_block(BlockId::new(1), b"file-bytes".to_vec()).unwrap();
```

Most apps use this through `conet_transfer` or `ReliabilitySender` rather than
calling the codec alone.

---

## Using CUBIC or BBR (public CC)

Install a sender controller and an ACK feedback receiver on the peer. Feedback
is opaque to the link; `AckReceiver` produces CCV1-style bodies that CUBIC/BBR
consume.

```rust
use conet_cc::{AckReceiver, CubicController, MonoNs};
use conet_core::FixedRateController;
use conet_udp::{EndpointConfig, Role, SimNetwork, UdpLiEndpoint, payload_packet};

let network = SimNetwork::new();
network.set_authenticated(true);

let mut sender = UdpLiEndpoint::with_controllers(
    network.transport(0),
    EndpointConfig::new(Role::Initiator, u64::MAX),
    Box::new(CubicController::new(MonoNs::ZERO)),
    None,
);
let mut receiver = UdpLiEndpoint::with_controllers(
    network.transport(1),
    EndpointConfig::new(Role::Responder, u64::MAX),
    Box::new(FixedRateController::new(u64::MAX)),
    Some(Box::new(AckReceiver::new())),
);

sender.establish_for_test(0x2222, 1).unwrap();
receiver.establish_for_test(0x2222, 1).unwrap();

for i in 0..3_u8 {
    sender.enqueue_file_data(payload_packet([i; 500])).unwrap();
}
for step in 0..8 {
    let now = MonoNs::new(step * 1_000_000);
    sender.drive(now);
    receiver.drive(now);
}
```

Swap `CubicController` for `BbrController` the same way:

```rust
use conet_cc::BbrController;
Box::new(BbrController::new(MonoNs::ZERO))
```

They are intentionally simplified versus Linux TCP CUBIC/BBR.

**Custom controllers:** implement `conet_core::TxController` and/or
`RxController`, then pass `Box<dyn …>` into `UdpLiEndpoint::with_controllers`.
The endpoint applies `pace()` (rate and/or inflight cap) and carries opaque CC
bytes without parsing them.

---

## Multiplexing (optional)

`conet_mux` attaches several local user endpoints to one lower hop. Each user
gets a small network header inside the body; the lower UDP-LI header is
unchanged. See `crates/conet_mux/tests/s12_mux.rs` for attach / drive patterns
(`Mux::with_scheduler`, `TreeScheduler`, Unix-socket program attach).

---

## Path simulator (optional)

`conet_sim` provides duplex paths with capacity, delay, buffer, and loss for
in-process `LinkEndpoint` graphs (separate from `conet_udp::SimNetwork`). Use it
when you want a bottleneck model under core link traits; see
`crates/conet_sim/tests/path_contract.rs`.

---

## Practical limits (v0.1)

- One reliability attachment per UDP-LI endpoint in the reference transfer.
- Security profiles and general Internet exposure are out of scope; loopback is
  restricted to `127.0.0.1`.
- Wire layout and APIs are a research MVP—pin versions and expect churn.

---

## Where to look next

- Design / layering / how paths form → [`conet-design-overview.md`](conet-design-overview.md)
- Two-host / NAT transfer → [`user/conet-transfer.md`](user/conet-transfer.md)
- CLI flags → `crates/conet_transfer/src/main.rs`
- Transfer API → `crates/conet_transfer/src/lib.rs`

Commercial licensing: see `COMMERCIAL-LICENSE.md` / contact in `NOTICE`.
