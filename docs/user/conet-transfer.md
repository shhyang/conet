Designated User Guide  
Copyright (c) 2026 Shenghao Yang  
License: Redistribution of this file alone is permitted for use with the Software; other rights reserved.  
AI training: not permitted  

# Using `conet_transfer`

Fountain file transfer over Conet’s UDP Internet link (UDP-LI). One process
talks to **one explicit peer**. Default reliability policy is **open-loop**
(one-way); **closed-loop** ACK/NACK is opt-in.

Build:

```bash
cargo build -p conet_transfer --release
./target/release/conet_transfer --help
```

## Modes

| Mode | Role |
| --- | --- |
| `simulate` | In-process sim (optional loss) |
| `loopback` | Two endpoints on `127.0.0.1` |
| `send` / `recv` | Real UDP between two processes or hosts |
| `reflexive-probe` / `reflexive-helper` | Optional same-socket UDP egress discovery (lab) |

## Open-loop vs closed-loop

| | **Open-loop** (default) | **Closed-loop** (`--closed-loop`) |
| --- | --- | --- |
| Feedback | None | Receiver sends **ACK** when the block is recovered; **NACK** when more symbols are needed |
| Sender stop | After the **symbol budget** (or time budget) | Prefer **Delivered** on ACK; may still stop on budget |
| Return path | Not required for success | Required: ACK/NACK must reach the sender |
| Typical use | Lossy one-way / first connectivity check | Confirm delivery and stop early when the path works |

Both sides must agree: pass `--closed-loop` on **send and recv**, or on neither.

ACK/NACK are reverse-direction **user** payload on the same association (not
link-control). Fountain coding still owns reliability; this flag only chooses
the stop / feedback policy.

## Two hosts on a LAN

Start **recv first**, then **send**. `--peer` is the other host’s LAN IP and port.

```bash
# host B
conet_transfer recv --listen 0.0.0.0:19001 --peer A_LAN_IP:19002 \
  --output /tmp/out.bin --budget 512

# host A
conet_transfer send /path/to/file --listen 0.0.0.0:19002 --peer B_LAN_IP:19001 \
  --budget 512
```

Add `--closed-loop` on both for ACK/NACK. Compare checksums of input and output.

## One public host + one host behind NAT (retained path)

This is the supported WAN shape. It does **not** use STUN, ICE, hole punching,
relays, or general roaming.

1. **Public host** is reachable at a known UDP address (e.g. a VPS).
2. **NAT-side host sends first** toward that address (opens the mapping).
3. **Public host learns the observed source IP/port** and replies there.
4. Traffic then works in both directions on that mapping.

Start **recv on the public host first**, then **send from the NAT host**.

```bash
# public host — learn the NAT egress from the first Conet datagram
conet_transfer recv --listen 0.0.0.0:19001 \
  --peer 0.0.0.0:0 --lab-observe-ip \
  --output /tmp/out.bin --budget 512 [--closed-loop]

# NAT host — send first; --peer is the public UDP address
conet_transfer send /path/to/file --listen 0.0.0.0:19002 \
  --peer PUBLIC_IP:19001 --budget 512 [--closed-loop]
```

`--lab-observe-ip` is the lab bridge that admits the first Conet source IP when
it disagrees with `--peer`. Once learned, replies go to that observed address.

**Do not** fill `--peer` from an HTTP “what is my IP” lookup: HTTP and UDP
egress can differ.

Closed-loop behind NAT still needs the return path; that is why the NAT side
must send first (or early).

Keepalives (idle mapping refresh) and path challenges are **optional** and off
by default—they are not required for short transfers on this path.

### Optional: discover UDP egress before filling a filter

If you must pre-fill the public host’s `--peer` instead of using
`--lab-observe-ip`, use the same-socket reflexive helper (lab only, not ICE):

```bash
# on the public host
conet_transfer reflexive-helper --listen 0.0.0.0:19099 --duration-ms 20000

# on the NAT host (prefer the same --listen port you will use for send)
conet_transfer reflexive-probe --listen 0.0.0.0:19002 \
  --helper PUBLIC_IP:19099 --timeout-ms 5000
# prints: reflexive=A.B.C.D:PORT  (candidate only)
```

Then set the public recv `--peer` to that reflexive address (without relying on
HTTP). Prefer `--lab-observe-ip` when you can.

## Useful flags

| Flag | Meaning |
| --- | --- |
| `--budget N` | Max fountain symbols to generate / accept bound |
| `--closed-loop` | Enable ACK/NACK policy (both ends) |
| `--lab-observe-ip` | Admit first observed Conet source IP (lab; retained WAN path) |
| `--timeout-ms` / `--duration-ms` | Reflexive probe / helper timing |

## What this is not

- Not ICE/STUN/TURN, hole punching, or relays  
- Not multi-peer demux on one socket (one peer per process)  
- Not a substitute for authenticated remaps on the public Internet  

For CLI synopsis only, run `conet_transfer --help`.
