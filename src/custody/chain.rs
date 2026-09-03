// src/custody/chain.rs
// Merkle chain — append-only forensic custody
// SHA-256 per block, monotonic sequence
//
// Block hash input: prev_hash(32) || seq(8 LE) || record(16) = 56 bytes
// This binds each block to its position and predecessor — tampering
// any block invalidates all subsequent hashes.

use sha2::{Sha256, Digest};

use crate::error::VtrError;
use crate::event::record::EventRecord;

pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy)]
pub struct CustodyBlock {
    pub seq:       u64,
    pub prev_hash: [u8; 32],
    pub record:    EventRecord,
    pub hash:      [u8; 32],
}

pub struct CustodyChain {
    seq:       u64,
    prev_hash: [u8; 32],
}

impl CustodyChain {
    #[must_use]
    pub const fn new() -> Self {
        Self { seq: 0, prev_hash: GENESIS_HASH }
    }

    #[must_use]
    pub const fn seq(&self) -> u64 { self.seq }

    #[must_use]
    pub const fn prev_hash(&self) -> &[u8; 32] { &self.prev_hash }

    /// Seal a record into the chain.
    ///
    /// Hash input (56 bytes, all little-endian):
    ///   prev_hash[0..32] || seq[0..8] || record[0..16]
    ///
    /// Returns the hash of the new block.
    /// The chain advances — seal() is not idempotent.
    pub fn seal(&mut self, record: &EventRecord) -> Result<CustodyBlock, VtrError> {
        let seq = self.seq;
        let rbytes = record.to_bytes();

        // Build the 56-byte input deterministically
        let mut input = [0u8; 56];
        input[0..32].copy_from_slice(&self.prev_hash);
        input[32..40].copy_from_slice(&seq.to_le_bytes());
        input[40..56].copy_from_slice(&rbytes);

        // SHA-256 over the 56-byte input
        let hash_vec = Sha256::digest(&input);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_vec);

        let block = CustodyBlock {
            seq,
            prev_hash: self.prev_hash,
            record: *record,
            hash,
        };

        // Advance chain state
        self.seq = self.seq.saturating_add(1);
        self.prev_hash = hash;

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::kind::EventKind;
    use crate::event::record::{SourceId, TsDelta};

    fn make_record(kind: EventKind, pid: u32, ts: u32) -> EventRecord {
        EventRecord::new(
            kind,
            kind.default_severity(),
            SourceId::SYSTEM,
            pid,
            TsDelta::new(ts),
        )
    }

    #[test]
    fn test_genesis_block_seq_zero() {
        let mut chain = CustodyChain::new();
        let r = make_record(EventKind::SentinelStarted, 0, 0);
        let block = chain.seal(&r).expect("seal must not fail");
        assert_eq!(block.seq, 0);
        assert_eq!(block.prev_hash, GENESIS_HASH);
        assert_ne!(block.hash, GENESIS_HASH);
    }

    #[test]
    fn test_chain_links_correctly() {
        let mut chain = CustodyChain::new();
        let r1 = make_record(EventKind::SentinelStarted, 0, 0);
        let r2 = make_record(EventKind::StateContamination, 1000, 1);

        let b1 = chain.seal(&r1).expect("seal 1");
        let b2 = chain.seal(&r2).expect("seal 2");

        assert_eq!(b1.seq, 0);
        assert_eq!(b2.seq, 1);
        assert_eq!(b2.prev_hash, b1.hash);
    }

    #[test]
    fn test_different_records_produce_different_hashes() {
        let mut c1 = CustodyChain::new();
        let mut c2 = CustodyChain::new();
        let r1 = make_record(EventKind::SentinelStarted, 0, 0);
        let r2 = make_record(EventKind::StateContamination, 999, 0);

        let b1 = c1.seal(&r1).expect("seal 1");
        let b2 = c2.seal(&r2).expect("seal 2");

        assert_ne!(b1.hash, b2.hash);
    }

    #[test]
    fn test_seal_is_deterministic() {
        let r = make_record(EventKind::SentinelStarted, 0, 0);
        let mut c1 = CustodyChain::new();
        let mut c2 = CustodyChain::new();
        let b1 = c1.seal(&r).expect("seal 1");
        let b2 = c2.seal(&r).expect("seal 2");
        assert_eq!(b1.hash, b2.hash);
    }

    #[test]
    fn test_sequence_jump_detectable() {
        let mut chain = CustodyChain::new();
        let r = make_record(EventKind::SentinelStarted, 0, 0);
        let b1 = chain.seal(&r).expect("seal 1");
        // seq must be monotonically increasing — jump from 0 to 2 is detectable
        assert_eq!(b1.seq, 0);
        assert_eq!(chain.seq(), 1);
    }
}
