# vtr-sentinel

Lightweight security sentinel for FreeBSD — byte-level event monitoring
with forensic chain of custody. Built for low-power x86/ARM hardware.

**Status:** Phase 3 complete. End-to-end pipeline verified on FreeBSD 14.4-RELEASE-p8.

## Phase Status

| Phase | Description | State |
|-------|-------------|-------|
| Phase 1 | Ring buffer, event primitives, CRC-32 | REPRODUCED |
| Phase 2 | FreeBSD hooks (fork/exec/exit), /dev/vtr0 | REPRODUCED |
| Phase 3 | Rust daemon + cross-language contract | REPRODUCED |

## Key Commits

| Commit | Description |
|--------|-------------|
| 2e55638 | EventRecord::from_bytes() + 5 cross-language tests pass |
| ca99e97 | fix: EVFILT_READ replaced with select(2) for cdev polling |
| 9e90047 | Phase 3 end-to-end CONFIRMED — 180 real kernel events |
| f35e2f9 | fix: VS-004 — map EIO to ChecksumInvalid, not PayloadOverflow |
| 8771425 | test: kernel_userspace_semantic_isolation — 4/4 pass |

## Wire Contract (C <-> Rust)

The vtr_event wire format (16 bytes, little-endian) is verified byte-for-byte
between the C kernel module and the Rust EventRecord:

| Bytes | Field | Type | Semantics |
|-------|-------|------|-----------|
| 0 | kind | u8 | event type (VTR_KIND_*) |
| 1 | severity | u8 | VTR_SEV_OBSERVED / ALERT |
| 2-3 | source_id | u16 LE | probe origin |
| 4-7 | pid | u32 LE | process identifier |
| 8-11 | seq_delta | u32 LE | monotonic sequence counter |
| 12-15 | checksum | u32 LE | CRC-32 over bytes [0..11] |

CRC-32 parameters: poly=0xEDB88320, init=0xFFFFFFFF, xorout=0xFFFFFFFF,
RefIn=true, RefOut=true. Verification vector: 0xCBF43926.

## Semantic Isolation Tests

Four tests verify the kernel/userspace boundary (src/tests/):

| Test | Assertion |
|------|-----------|
| test_kernel_primitive_immutable_in_custody_block | Kernel fields preserved unmodified |
| test_semantic_reclassification_produces_new_block | Reclassification requires new block |
| test_severity_elevation_without_new_block_is_detectable | CRC protects severity field |
| test_misclassification_detectable_from_chain | kind/source_id mismatch visible in chain |

All 4 pass on Linux (rustc 1.96.0) and FreeBSD 14.4 (rustc 1.98.1).

## Build

    cargo build --release
    cargo test

Target: FreeBSD x86_64 (Pentium Silver). Static binary, no dynamic dependencies.

Kernel module: see vtr-sentinel-kmod (separate repository).

## VS-010 — Pending

The daemon currently writes custody chain to stdout only.
The file path argument is not used for persistent output.
Fix pending — classified as CANDIDATE VS-010.

## License

BSD 2-Clause

## About

Vector Telemetry Research (VTR) -- OT/ICS Security
Tampico, Tamaulipas, Mexico
SIGNAL. VECTOR. INTELLIGENCE.
