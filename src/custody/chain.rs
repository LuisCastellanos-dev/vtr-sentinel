// src/custody/chain.rs
// Merkle chain — append-only forensic custody
// SHA-256 per block, monotonic sequence

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

    pub fn seal(&mut self, record: &EventRecord) -> Result<[u8; 32], VtrError> {
        // TODO: integrate sha2 crate for actual SHA-256
        let rbytes = record.to_bytes();
        let mut hash = self.prev_hash;
        for (i, &b) in rbytes.iter().enumerate() { hash[i % 32] ^= b; }
        self.seq = self.seq.saturating_add(1);
        self.prev_hash = hash;
        Ok(hash)
    }
}
