// src/tests/kernel_userspace_semantic_isolation.rs
// Test harness for kernel_userspace_semantic_isolation.json
// Experiment: VTR — 2026-09-05
//
// Hypothesis: a userspace parser consuming vtr_event primitives cannot
// reinterpret an observation primitive as a semantic diagnosis without
// producing a detectable artifact in the evidence chain.
//
// This test suite exercises the boundary by injecting synthetic vtr_event
// blobs directly into EventRecord::from_bytes() and CustodyChain::seal(),
// bypassing /dev/vtr0.

use crate::custody::chain::{CustodyChain, GENESIS_HASH};
use crate::event::kind::{EventKind, EventSeverity};
use crate::event::record::{Crc32, EventRecord, SourceId, TsDelta};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a valid 16-byte vtr_event blob from known field values.
/// Mirrors vtr_event_build() in C — little-endian, CRC over bytes [0..12].
fn build_blob(
    kind: u8,
    severity: u8,
    source_id: u16,
    pid: u32,
    ts_delta: u32,
) -> [u8; 16] {
    let mut blob = [0u8; 16];
    blob[0] = kind;
    blob[1] = severity;
    blob[2..4].copy_from_slice(&source_id.to_le_bytes());
    blob[4..8].copy_from_slice(&pid.to_le_bytes());
    blob[8..12].copy_from_slice(&ts_delta.to_le_bytes());
    let crc = Crc32::compute(&blob[0..12]).value();
    blob[12..16].copy_from_slice(&crc.to_le_bytes());
    blob
}

// ── Test 1: Kernel primitive is preserved unmodified in custody block ─────────
//
// Assertion: CustodyBlock.record contains exactly the same bytes as the
// injected blob. No field is modified by the custody layer.

#[test]
fn test_kernel_primitive_immutable_in_custody_block() {
    let blob = build_blob(
        0x60, // VTR_KIND_SENTINEL_STARTED
        0x00, // VTR_SEV_OBSERVED
        0x0000,
        0,
        0,
    );
    let record = EventRecord::from_bytes(&blob).expect("blob must parse");
    let mut chain = CustodyChain::new();
    let block = chain.seal(&record).expect("seal must not fail");

    // The block must preserve the original kernel primitive byte-for-byte
    assert_eq!(block.record.kind_raw(),      blob[0],  "kind modified");
    assert_eq!(block.record.severity_raw(),  blob[1],  "severity modified");
    assert_eq!(block.record.source_id_raw(), u16::from_le_bytes([blob[2], blob[3]]), "source_id modified");
    assert_eq!(block.record.pid(),           u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]), "pid modified");
    assert_eq!(block.record.ts_delta_raw(),  u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]), "ts_delta modified");
    assert_eq!(block.record.checksum(),      u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]), "checksum modified");
}

// ── Test 2: Semantic reclassification produces a NEW block ────────────────────
//
// Falsifier from JSON: "A userspace parser assigns EventKind::Dnp3CrcInvalid
// to a vtr_event whose kernel-produced fields are consistent with a benign
// process lifecycle event — and the custody chain does not record the
// reclassification as a separate event."
//
// This test verifies that if userspace adds a classification, it must
// produce a new EventRecord (new blob) which is sealed as a separate block.
// The chain seq advances — the reclassification is detectable.

#[test]
fn test_semantic_reclassification_produces_new_block() {
    // Inject a benign process lifecycle event (fork)
    let kernel_blob = build_blob(
        0x20, // VTR_KIND_STATE_CONTAMINATION (fork observation)
        0x00, // VTR_SEV_OBSERVED
        0x0007, // VTR_SRC_SYSCALL
        2370,
        1,
    );
    let kernel_record = EventRecord::from_bytes(&kernel_blob).expect("kernel blob must parse");

    let mut chain = CustodyChain::new();
    let kernel_block = chain.seal(&kernel_record).expect("kernel seal");
    assert_eq!(kernel_block.seq, 0);

    // Userspace adds a semantic classification — must produce a NEW record
    // with a different kind (e.g., a protocol-level finding derived from
    // the observation). This new record is sealed as a separate block.
    let classification_record = EventRecord::new(
        EventKind::Dnp3CrcInvalid,
        EventSeverity::Probable,
        SourceId::CUSTODY,  // classification originates in userspace, not kernel
        0,
        TsDelta::new(1),
    );
    let classification_block = chain.seal(&classification_record).expect("classification seal");

    // The classification is a separate block — seq advances
    assert_eq!(classification_block.seq, 1);
    // The kernel primitive block is NOT modified — it still has seq=0
    assert_eq!(kernel_block.seq, 0);
    // The classification block links to the kernel block
    assert_eq!(classification_block.prev_hash, kernel_block.hash);
    // The two blocks have different hashes — chain is append-only
    assert_ne!(kernel_block.hash, classification_block.hash);
}

// ── Test 3: Severity elevation without new block is detectable ────────────────
//
// Falsifier from JSON: "A userspace component elevates EventSeverity from
// Observed to Confirmed without producing a new EventRecord with a distinct
// sequence number and updated CRC-32 — making the elevation invisible."
//
// This test verifies that attempting to pass a severity-elevated version
// of a kernel blob without creating a new CustodyBlock is detectable:
// the chain seq does not advance, and the tampered record has a different
// checksum than the original.

#[test]
fn test_severity_elevation_without_new_block_is_detectable() {
    let kernel_blob = build_blob(
        0x20, // VTR_KIND_STATE_CONTAMINATION
        0x00, // VTR_SEV_OBSERVED
        0x0007,
        2370,
        1,
    );
    let kernel_record = EventRecord::from_bytes(&kernel_blob).expect("kernel blob must parse");

    // Attempt to build a "severity-elevated" blob by changing byte[1]
    // without recomputing CRC — this simulates tampering
    let mut tampered_blob = kernel_blob;
    tampered_blob[1] = 0x02; // elevate to VTR_SEV_CONFIRMED without new CRC

    // The tampered blob must be rejected by from_bytes() — CRC is invalid
    let result = EventRecord::from_bytes(&tampered_blob);
    assert!(result.is_err(), "tampered blob must be rejected — CRC protects severity field");

    // The only valid way to record a severity elevation is a new EventRecord
    // with a recomputed CRC — which produces a new blob detectable in the chain
    let elevated_blob = build_blob(
        0x20,
        0x02, // VTR_SEV_CONFIRMED — with correct CRC
        0x0006, // VTR_SRC_CUSTODY — userspace origin
        2370,
        1,
    );
    let elevated_record = EventRecord::from_bytes(&elevated_blob).expect("elevated blob must parse");

    // The elevated blob has a different checksum than the original
    assert_ne!(
        elevated_record.checksum(),
        kernel_record.checksum(),
        "elevated record must have different checksum"
    );

    // Seal both — chain advances, both are traceable
    let mut chain = CustodyChain::new();
    let b0 = chain.seal(&kernel_record).expect("kernel seal");
    let b1 = chain.seal(&elevated_record).expect("elevation seal");
    assert_eq!(b0.seq, 0);
    assert_eq!(b1.seq, 1);
    // The elevation is visible in the chain — seq difference is the artifact
}

// ── Test 4: Misclassification is detectable from chain alone ──────────────────
//
// Verifies the proposed_experiment step 4: "Attempt to inject a blob that
// userspace would misclassify — verify the misclassification is detectable
// from the chain alone without author context."
//
// A benign process event (fork/exec) and a protocol event (DNP3 CRC invalid)
// have different source_id values. A misclassification would assign a protocol
// kind to a syscall source — the mismatch is readable from the sealed block.

#[test]
fn test_misclassification_detectable_from_chain() {
    // A benign fork event from syscall hook (source_id = VTR_SRC_SYSCALL = 0x0007)
    let fork_blob = build_blob(0x20, 0x00, 0x0007, 2370, 1);
    let fork_record = EventRecord::from_bytes(&fork_blob).expect("fork blob");

    // A misclassification: userspace labels this as DNP3 CRC invalid
    // without changing source_id — the mismatch is visible in the block
    let misclassified_blob = build_blob(
        0x51, // VTR_KIND_DNP3_CRC_INVALID — protocol event
        0x00,
        0x0007, // VTR_SRC_SYSCALL — syscall source, not DNP3
        2370,
        1,
    );
    let misclassified_record = EventRecord::from_bytes(&misclassified_blob).expect("misclassified blob");

    let mut chain = CustodyChain::new();
    let original_block = chain.seal(&fork_record).expect("original seal");
    let misclassified_block = chain.seal(&misclassified_record).expect("misclassified seal");

    // From the chain alone, without author context:
    // block 0: kind=0x20 (STATE_CONTAMINATION), source=0x0007 (SYSCALL) — consistent
    // block 1: kind=0x51 (DNP3_CRC_INVALID),    source=0x0007 (SYSCALL) — inconsistent
    // DNP3 events should originate from source=0x0002 (VTR_SRC_DNP3), not SYSCALL
    // The mismatch is detectable by reading source_id_raw() vs kind_raw()
    assert_eq!(original_block.record.kind_raw(),      0x20);
    assert_eq!(original_block.record.source_id_raw(), 0x0007);
    assert_eq!(misclassified_block.record.kind_raw(),      0x51);
    assert_eq!(misclassified_block.record.source_id_raw(), 0x0007); // detectable mismatch
    // A verifier can detect: DNP3 kind with SYSCALL source is inconsistent
}
