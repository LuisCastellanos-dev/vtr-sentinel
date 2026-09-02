// src/probe/entropy.rs
// Shannon entropy — O(256) fixed, no alloc
// Ported from vtr-shield dns_probe.py

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyResult {
    pub bits:       f32,
    pub buckets:    u8,
    pub confidence: u8,
}

impl EntropyResult {
    pub const MIN_BYTES: usize = 8;
    pub const HIGH_ENTROPY_THRESHOLD: f32 = 7.0;

    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.confidence > 0 && self.bits >= Self::HIGH_ENTROPY_THRESHOLD
    }
}

#[must_use]
pub fn compute(data: &[u8]) -> EntropyResult {
    if data.len() < EntropyResult::MIN_BYTES {
        return EntropyResult { bits: 0.0, buckets: 0, confidence: 0 };
    }
    let mut freq = [0u32; 256];
    for &byte in data { freq[byte as usize] += 1; }
    let len = data.len() as f32;
    let mut entropy = 0.0f32;
    let mut buckets = 0u8;
    for &count in &freq {
        if count > 0 {
            buckets += 1;
            let p = count as f32 / len;
            entropy -= p * p.ln() / core::f32::consts::LN_2;
        }
    }
    let confidence = (data.len().min(255)) as u8;
    EntropyResult { bits: entropy, buckets, confidence }
}
