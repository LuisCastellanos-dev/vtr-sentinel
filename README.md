# vtr-sentinel

Lightweight security sentinel for FreeBSD — byte-level event monitoring
with forensic chain of custody. Built for low-power x86/ARM hardware.

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-green.svg)](LICENSE)
[![Target: FreeBSD](https://img.shields.io/badge/Target-FreeBSD_14.x-red.svg)](https://www.freebsd.org)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org)

---

## Philosophy

> Every byte counts. Every event is evidence. No implicit contracts.

`vtr-sentinel` applies the discipline of 8-bit programming to modern
security monitoring: fixed-size data structures, no heap allocation in
the hot path, O(1) operations, and a forensic chain of custody that
is an architectural invariant — not an optional feature.

Designed to run on a Pentium Silver with 4GB RAM.
Tested on FreeBSD 14.4-RELEASE-p8.
No Linux. No Debian. No Arch.

---

## Design Constraints

| Constraint | Value | Reason |
|------------|-------|--------|
| `EventRecord` size | 16 bytes | Fits 2048 events in L1 cache (32KB) |
| `RingBuffer` size | 32KB | L1 cache of Pentium Silver J5005 |
| Binary size | < 2MB | Verified in CI |
| RAM at runtime | < 8MB | Ring buffer + chain + stack |
| Heap after `main()` | Zero | All memory reserved at startup |
| Panic in production | Forbidden | `clippy::panic` = error |

---

## Architecture

```
vtr-sentinel/
├── src/
│   ├── main.rs              — entry point, kqueue event loop
│   ├── error.rs             — VtrError: exhaustive enum, no String
│   ├── ring/
│   │   └── buffer.rs        — RingBuffer<T, const N> — compile-time size
│   ├── event/
│   │   ├── kind.rs          — EventKind: 46 variants, repr(u8)
│   │   └── record.rs        — EventRecord: 16 bytes, CRC-32 verified
│   ├── probe/
│   │   ├── entropy.rs       — Shannon entropy, O(256) fixed, no alloc
│   │   ├── dnp3.rs          — CRC-16 IEEE 1815-2012
│   │   └── syscall.rs       — kqueue + /proc polling
│   └── custody/
│       └── chain.rs         — SHA-256 hash chain, append-only
```

---

## Event Families

Events derived from real audit findings:

| Family | Source | Examples |
|--------|--------|---------|
| Memory | VTR-RPi-001, D58754 | `AllocWithoutRelease`, `BoundaryViolation` |
| Contract | GHI-A-001, VTR-RPi-002 | `ImplicitContractBreach`, `ExportSymbolImplicit` |
| State | GHI-R-001 | `StateContamination`, `SingletonReuse` |
| DoS | GHI-R-002 | `AlgorithmicDoS`, `UnboundedLoop` |
| Provenance | GHI-F-001, CVE-2021-42574 | `HashMismatch`, `TrojanSourceCandidate` |
| Network | vtr-shield dns/dnp3/tls probes | `HighEntropyPayload`, `Dnp3CrcInvalid` |
| System | Internal | `SentinelStarted`, `CustodySequenceJump` |

---

## Building

```bash
# Target: FreeBSD x86_64 static binary
cargo build --release --target x86_64-unknown-freebsd

# Verify binary size < 2MB
size target/x86_64-unknown-freebsd/release/vtr-sentinel

# Run tests
cargo test
cargo clippy -- -D warnings
```

---

## Forensic Chain of Custody

Every `EventRecord` carries a CRC-32 checksum over its 12 data bytes.
Records that require immediate custody (tampering indicators, hash
mismatches, pledge violations) bypass the ring buffer and go directly
to the append-only custody file.

The custody file is a SHA-256 hash chain — each block includes the SHA-256
of the previous block. A sequence jump in the monotonic counter is
itself an `EventKind::CustodySequenceJump` event.

---

## Methodology

Design and event taxonomy derived from VTR-METH-001 v5.1.
DOI: [10.5281/zenodo.22073043](https://doi.org/10.5281/zenodo.22073043)

Real audit findings that shaped this project:
- VTR-RPi-001 / VTR-RPi-002 — vc04_services kernel drivers
- GHI-A-001 / GHI-R-001 / GHI-R-002 — Ghidra 11.3.2 audit
- D58754 — FreeBSD if_ovpn.c resource leak

---

## License

BSD 2-Clause — see [LICENSE](LICENSE)

Vector Telemetry Research © 2026 — Tampico, Tamaulipas
SIGNAL. VECTOR. INTELLIGENCE.
