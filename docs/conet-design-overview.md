<!--
Designated User Guide
Copyright (c) 2026 Shenghao Yang
License (this file only): You may copy and redistribute this guide with
attribution and this notice retained. AI/ML training on this guide is not
permitted. Review that restriction for your jurisdiction / use case if you
rely on it.
-->

# Conet design overview

This guide introduces the design ideas behind Conet and how the public crates
compose into paths and small networks. For build steps and CLI recipes, see
[`conet-getting-started.md`](conet-getting-started.md).

**Version target:** workspace `0.1.1` (research MVP; APIs may change).
Software: AGPL-3.0-only (see root `LICENSE`). Doc terms: notice above.

Conet implements a set of **building blocks** for erasure coding–based network
communication—not one fixed end-to-end protocol. The same blocks can support
point-to-point transfer today and, over time, richer constructions. This public
tree ships the research MVP of those blocks in Rust.

---

## Network model

Logically, a Conet network is made of **devices** and **links** (this is not
tied to physical topology):

- A **device** is a node that can send and receive packets and run the
  protocol modules.
- A **link** is a *directed* channel between two devices. Links may lose
  packets, vary in latency and rate, and may share underlying resources.

A **user** is an ordered pair of devices: a source that has data and a
destination that should receive it. Communication for one user is
**unidirectional**. Bidirectional traffic is two users (one each way).

For a user, the source encodes a data block into coded packets and sends them
toward the destination over available links. Packets may traverse intermediate
devices; intermediates forward coded packets and need not recover the original
block. The destination collects enough coded packets to decode.

---

## Three layers (data plane)

Conet organizes the data plane into three layers that share the same lossy
links (erasures, not bit corruption—integrity is a separate concern):

```text
  Reliability  — end-to-end encode / decode for one user
        │
  Network      — schedule / demux users and (later) multi-hop / recode
        │
  Link         — pace and time datagrams on one hop
        │
     lossy directed links
```

### Reliability layer

Guarantees end-to-end delivery of a user’s data block. An encoder at the source
and a decoder at the destination sit over a lossy path; the layer does **not**
run on intermediate devices. It is intentionally **timing-unaware**: it does
not by itself promise throughput or latency.

Optional reverse feedback (on the duplex association’s other direction):

- **ACK** — the block is recovered.
- **NACK** — more coded packets are still needed (may carry hints).

On the wire, ACK/NACK are ordinary **user** payload on the reverse path, not
link-control. That reverse path has no nested “ACK of ACK.”

In software: `conet_core` reliability core + policy (`OneWayBudget`,
`BidirectionalAck`) and `conet_fountain` as the `BlockCodec`.

### Link layer

Handles **rate and timing** on one hop: a sender on one device and a receiver
on the other. It does **not** provide reliability. It paces and schedules
datagrams (and may coordinate with peers that share capacity) using latency,
throughput, and loss observations, optionally with opaque controller feedback.

In software: `conet_core` link traits, queues, pacers, `TxController` /
`RxController`; `conet_udp` as the UDP Link Interface (UDP-LI) profile;
`conet_cc` for research CUBIC/BBR-style controllers.

### Network layer

Sits between reliability and link. It coordinates how coded packets use one or
more links, and how **several users** share a hop. In the fuller design it can
also recode; the public MVP focuses on end-host multiplexing.

In software: `conet_mux` is the “many users on one lower hop” network adapter.
Multi-path egress and intermediate forwarders are design targets, not the
center of `v0.1.1`.

---

## Control plane

Each layer also needs **signaling** outside the fountain-coded user block:

| Layer | Examples of control |
| --- | --- |
| Reliability | Session progress: ACK / NACK |
| Network | Coordination among network modules (future / research) |
| Link | Association lifecycle; pacing / congestion-control bodies |

Control may be **in-band** (header fields on a coded datagram) or **standalone**
(a datagram whose payload is only control). Standalone control shares the same
unreliable link and is **not** fountain-protected; the design does not assume
reliable control delivery and must tolerate loss.

A higher layer’s control is **opaque** to layers below: the lower data plane
schedules and forwards it without interpreting semantics (though it may prefer
it via a QoS / scheduling class).

---

## Datagram link interface

Packet-forwarding modules share one contract so they can be stacked:

- `LinkSender` / `LinkReceiver` — one directed attachment.
- `LinkEndpoint` — on one device, outgoing sender + incoming receiver of the
  reverse direction (a duplex association endpoint of the *link*, not of an
  end-to-end user).

The same interface is used between devices (UDP, etc.) and **in-process**
between modules on one host. Ownership of a `PacketHandle` (shared immutable
payload + per-send header) is how backpressure works: if enqueue fails, the
caller keeps the handle.

Several end-to-end users that share one hop do so through a **network adapter**
(`conet_mux`), not by turning the link endpoint into a multi-user API. The lower
link stays one attachment with one shared pacer.

---

## How Conet crates map to the design

```text
  reliability + fountain     (conet_core reliability, conet_fountain)
           │
  network adapter (optional) (conet_mux)
           │
  link / UDP-LI              (conet_core contracts, conet_udp, conet_cc)
           │
  transport or harness
    · SimNetwork / loopback UDP
    · conet_sim path model (core-link tests)
    · identity / paced identity links
           │
  apps                         (conet_transfer, …)
```

| Design piece | Public crate(s) |
| --- | --- |
| Devices / links / users (model) | Composed in apps and tests |
| Reliability core + policies | `conet_core` |
| Fountain block codec | `conet_fountain` |
| Link contracts, pacing, wire helpers | `conet_core` |
| UDP-LI profile (association, queues, scheduler) | `conet_udp` |
| Adaptive / research CC | `conet_cc` |
| Many users on one hop | `conet_mux` |
| Bottleneck path under link traits | `conet_sim` |
| Reference file transfer | `conet_transfer` |

---

## Forming a network in practice (v0.1)

The MVP does not ship a global routing plane. You **compose** a path from the
blocks above.

### Point-to-point over UDP-LI

The usual research path:

1. Provide a `DatagramTransport` — `SimNetwork` (two logical hosts) or
   `LoopbackUdpTransport` (`127.0.0.1` only).
2. Build a `UdpLiEndpoint` on each side (default `FixedRateController`, or
   CUBIC/BBR from `conet_cc`).
3. Run association (`OPEN` / `ACCEPT`) by driving both ends until established.
4. Attach reliability + fountain above the user-body path; drive until the block
   recovers (one-way budget or closed-loop ACK/NACK).

That is what `conet_transfer simulate` / `loopback` do.

### In-process harness links

For unit tests without sockets: `identity_link`, `paced_identity_link`, and
`device_stub_link` implement the same sender/receiver surface. `conet_sim`’s
`duplex_path` adds a deterministic bottleneck (rate, delay, drop-tail, loss)
under core `LinkEndpoint` traits—distinct from `conet_udp::SimNetwork`.

### Several users on one hop

`Mux` sits above one lower `LinkEndpoint`, attaches per-user upper endpoints,
tags/demuxes by user id, and schedules the aggregate onto the lower pacer.
Reliability still runs end-to-end per user; the mux does not decode blocks.

### What “network” means here

| Construction | What you get |
| --- | --- |
| Two UDP-LI endpoints + transport | One duplex association (two unidirectional users if both send) |
| Reliability + fountain on that association | End-to-end coded block delivery |
| Mux over a lower hop | Several users sharing one paced link |
| Chained adapters / multi-hop | Design target; only small pieces in the public MVP |

---

## Out of scope (public v0.1)

- Production security (link auth, self-encryption keys, Internet exposure).
- Production congestion control (CUBIC/BBR here are research simplifications).
- Full multi-hop network coding / recoding and network-layer control protocols.
- Multi-block transfer and multiple reliability attachments in the reference app.
- A frozen public wire standard (tag-5 layouts are illustrative / profile-local).
- Validated Linux offload behavior.

---

## Where to look next

| Topic | Place |
| --- | --- |
| Getting started | [`conet-getting-started.md`](conet-getting-started.md) |
| Core contracts | `crates/conet_core/src/lib.rs` |
| Reliability | `crates/conet_core/src/reliability.rs` |
| Fountain | `crates/conet_fountain/src/lib.rs` |
| UDP-LI endpoint | `crates/conet_udp/src/endpoint.rs` |
| Association | `crates/conet_udp/src/association.rs` |
| Sim / loopback | `crates/conet_udp/src/{sim,transport}.rs` |
| CC | `crates/conet_cc/src/{cubic,bbr,feedback}.rs` |
| Mux | `crates/conet_mux/src/lib.rs` |
| Path model | `crates/conet_sim/src/path.rs` |
| Transfer | `crates/conet_transfer/src/lib.rs` |
