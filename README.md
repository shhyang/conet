# conet

Conet is an experimental Rust transport stack built over UDP for networking and congestion-control research. It provides modular components for link transport, pluggable congestion control, fountain coding, multiplexing, transfer, and simulation.

`v0.1.1` — Experimental research release. APIs and wire formats may change; not intended for production deployment.

Copyright © 2024–2026 Shenghao Yang.

## Crates

| Crate | Description |
| --- | --- |
| `conet_core` | Packets, queues, clocks, link traits, reliability core, CC ports |
| `conet_udp` | UDP-LI endpoints (association, pacing, sim / loopback) |
| `conet_fountain` | Raptor-10 block codec |
| `conet_transfer` | Reference one-block file transfer (CLI + library) |
| `conet_cc` | CC hook + CUBIC-style / BBR-style controllers and ACK feedback |
| `conet_mux` | Simple end-host user multiplexer |
| `conet_sim` | Deterministic path model for link tests |

## Quick start

```bash
cargo build -p conet_transfer --release
cargo run -p conet_transfer -- simulate /path/to/file.txt --output /tmp/out.bin
```

See [docs/conet-getting-started.md](docs/conet-getting-started.md) (build / CLI),
[docs/conet-design-overview.md](docs/conet-design-overview.md) (structure / how
paths are formed), and
[docs/user/conet-transfer.md](docs/user/conet-transfer.md) for two-host / NAT
transfer.

## Release limitations

- APIs and wire formats are unstable and may change without notice.
- CUBIC and BBR are simplified research models, not production congestion-control implementations.
- Linux offloads are present but lack runtime validation; Linux runtime testing remains outstanding.
- This is not production-secure software; do not use it where security or reliability matter.

## License

**Software** is dual-licensed ([`LICENSE-SOFTWARE`](LICENSE-SOFTWARE)):

1. **[AGPL-3.0-only](LICENSE-AGPL-3.0)** — free use/modification/distribution;
   distributing the software or offering a modified version as a network
   service requires offering complete corresponding source under AGPL-3.0-only.
2. **Commercial** — separate written grant when AGPL terms do not fit; see
   [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md).

Without a signed commercial agreement, AGPL-3.0-only applies.

**Docs** under [`docs/`](docs/): each Designated User Guide’s in-file notice
(see [`docs/LICENSE`](docs/LICENSE)).

Index: [`LICENSE`](LICENSE).

## Maintenance

This is a research codebase maintained on a **best-effort** basis. There is no
support SLA, no guaranteed response time, and no commitment to backward
compatibility within `0.x`. Issues and questions may be answered when time
allows; outside code pull requests are not accepted at this time.

## Citation

If you use Conet in coursework or research, please cite this software (not
only a fork or mirror), including the version:

> Shenghao Yang. *conet*: an experimental Rust transport stack for coded
> networking and congestion-control research, version 0.1.1, 2026.
> https://github.com/shhyang/conet

```bibtex
@software{yang2026conet,
  author  = {Yang, Shenghao},
  title   = {conet: an experimental Rust transport stack for coded networking
             and congestion-control research},
  version = {0.1.1},
  year    = {2026},
  url     = {https://github.com/shhyang/conet}
}
```
