// src/event/record.rs — see full implementation in conversation
// Placeholder for initial commit — full implementation follows
pub use crate::event::kind::{EventKind, EventSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Crc32(u32);

impl Crc32 {
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        const TABLE: [u32; 256] = {
            let mut t = [0u32; 256];
            let mut i = 0usize;
            while i < 256 {
                let mut c = i as u32;
                let mut j = 0;
                while j < 8 {
                    if c & 1 != 0 { c = 0xEDB8_8320 ^ (c >> 1); } else { c >>= 1; }
                    j += 1;
                }
                t[i] = c;
                i += 1;
            }
            t
        };
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data { let idx = ((crc ^ byte as u32) & 0xFF) as usize; crc = TABLE[idx] ^ (crc >> 8); }
        Self(crc ^ 0xFFFF_FFFF)
    }
    #[must_use] pub const fn value(&self) -> u32 { self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SourceId(u16);
impl SourceId {
    pub const SYSTEM:  Self = Self(0x0000);
    pub const KQUEUE:  Self = Self(0x0001);
    pub const DNP3:    Self = Self(0x0002);
    pub const DNS:     Self = Self(0x0003);
    pub const TLS:     Self = Self(0x0004);
    pub const HTTP:    Self = Self(0x0005);
    pub const CUSTODY: Self = Self(0x0006);
    #[must_use] pub const fn new(id: u16) -> Self { Self(id) }
    #[must_use] pub const fn value(&self) -> u16 { self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TsDelta(u32);
impl TsDelta {
    pub const GENESIS: Self = Self(0);
    #[must_use] pub const fn new(ms: u32) -> Self { Self(ms) }
    #[must_use] pub const fn millis(&self) -> u32 { self.0 }
    #[must_use] pub const fn is_genesis(&self) -> bool { self.0 == 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct EventRecord {
    kind:      u8,
    severity:  u8,
    source_id: u16,
    pid:       u32,
    ts_delta:  u32,
    checksum:  u32,
}

const _ASSERT_SIZE: () = { assert!(core::mem::size_of::<EventRecord>() == 16, "EventRecord must be 16 bytes"); };

impl EventRecord {
    #[must_use]
    pub fn new(kind: EventKind, severity: EventSeverity, source_id: SourceId, pid: u32, ts_delta: TsDelta) -> Self {
        let kb = kind as u8;
        let sb = severity as u8;
        let ss = source_id.value().to_le_bytes();
        let pb = pid.to_le_bytes();
        let tb = ts_delta.millis().to_le_bytes();
        let data: [u8; 12] = [kb, sb, ss[0], ss[1], pb[0], pb[1], pb[2], pb[3], tb[0], tb[1], tb[2], tb[3]];
        let checksum = Crc32::compute(&data).value();
        Self { kind: kb, severity: sb, source_id: source_id.value(), pid, ts_delta: ts_delta.millis(), checksum }
    }

    #[must_use]
    pub fn system_event(kind: EventKind, ts_delta: TsDelta) -> Self {
        Self::new(kind, kind.default_severity(), SourceId::SYSTEM, 0, ts_delta)
    }

    pub fn verify(&self) -> Result<(), crate::error::VtrError> {
        // Use to_bytes() to get the canonical byte representation —
        // avoids any divergence between field extraction and wire layout.
        let raw = self.to_bytes();
        let computed = Crc32::compute(&raw[0..12]).value();
        let stored   = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        if computed == stored { Ok(()) }
        else { Err(crate::error::VtrError::new(
            crate::error::ErrorKind::ChecksumInvalid,
            crate::error::ErrorLayer::Protocol,
            crate::error::ErrorSeverity::DaemonFatal, 0)) }
    }


    /// Deserialize from 16 raw bytes read from /dev/vtr0.
    /// This is the cross-language contract entry point: bytes produced
    /// by vtr_event_build() in C must parse correctly here.
    ///
    /// Returns Err if CRC-32 verification fails.
    pub fn from_bytes(raw: &[u8; 16]) -> Result<Self, crate::error::VtrError> {
        let kind      = raw[0];
        let severity  = raw[1];
        let source_id = u16::from_le_bytes([raw[2], raw[3]]);
        let pid       = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let ts_delta  = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let checksum  = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);

        let record = Self { kind, severity, source_id, pid, ts_delta, checksum };
        record.verify()?;
        Ok(record)
    }

    #[must_use]
    pub fn kind_raw(&self)      -> u8  { self.kind }
    #[must_use]
    pub fn severity_raw(&self)  -> u8  { self.severity }
    #[must_use]
    pub fn source_id_raw(&self) -> u16 { self.source_id }
    #[must_use]
    pub fn pid(&self)           -> u32 { self.pid }
    #[must_use]
    pub fn ts_delta_raw(&self)  -> u32 { self.ts_delta }
    #[must_use]
    pub fn checksum(&self)      -> u32 { self.checksum }

    pub fn requires_immediate_custody(&self) -> bool {
        EventKind::from_u8(self.kind).map(|k| k.requires_immediate_custody()).unwrap_or(true)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 16] {
        [self.kind, self.severity,
         (self.source_id & 0xFF) as u8, (self.source_id >> 8) as u8,
         (self.pid & 0xFF) as u8, ((self.pid >> 8) & 0xFF) as u8,
         ((self.pid >> 16) & 0xFF) as u8, ((self.pid >> 24) & 0xFF) as u8,
         (self.ts_delta & 0xFF) as u8, ((self.ts_delta >> 8) & 0xFF) as u8,
         ((self.ts_delta >> 16) & 0xFF) as u8, ((self.ts_delta >> 24) & 0xFF) as u8,
         (self.checksum & 0xFF) as u8, ((self.checksum >> 8) & 0xFF) as u8,
         ((self.checksum >> 16) & 0xFF) as u8, ((self.checksum >> 24) & 0xFF) as u8]
    }
}

#[cfg(test)]
mod cross_language_tests {
    use super::*;

    #[test]
    fn test_diagnose_crc() {
        let genesis_data: [u8; 12] = [
            0x61, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let genesis_crc = Crc32::compute(&genesis_data).value();
        let genesis_stored = u32::from_le_bytes([0x71, 0x08, 0x86, 0x90]);
        eprintln!("genesis computed=0x{:08X} stored=0x{:08X}", genesis_crc, genesis_stored);

        let fork_data: [u8; 12] = [
            0x20, 0x00, 0x07, 0x00, 0x2d, 0x0a,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let fork_crc = Crc32::compute(&fork_data).value();
        let fork_stored = u32::from_le_bytes([0x50, 0xfd, 0xc7, 0xdb]);
        eprintln!("fork    computed=0x{:08X} stored=0x{:08X}", fork_crc, fork_stored);
    }

    #[test]
    fn test_genesis_event_from_c_bytes() {
        // Bytes from FreeBSD 14.4-RELEASE-p8 hexdump after CRC table fix
        // kind=0x60 SENTINEL_STARTED, severity=0, src=0x0000, pid=0, ts=0
        // CRC: 0x5387AA67 (little-endian: 67 aa 87 53)
        let raw: [u8; 16] = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x67, 0xaa, 0x87, 0x53,
        ];
        let record = EventRecord::from_bytes(&raw).expect("genesis must parse");
        assert_eq!(record.kind_raw(),      0x60);
        assert_eq!(record.severity_raw(),  0x00);
        assert_eq!(record.source_id_raw(), 0x0000);
        assert_eq!(record.pid(),           0);
        assert_eq!(record.ts_delta_raw(),  0);
    }

    #[test]
    fn test_fork_event_from_c_bytes() {
        // Bytes from FreeBSD 14.4-RELEASE-p8 hexdump after CRC table fix
        // kind=0x20 STATE_CONTAMINATION, severity=0, src=0x0007, pid=0x0942=2370, ts=1
        // CRC: 0xC7A4E1C8 (little-endian: c8 e1 a4 c7)
        let raw: [u8; 16] = [
            0x20, 0x00, 0x07, 0x00, 0x42, 0x09, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0xc8, 0xe1, 0xa4, 0xc7,
        ];
        let record = EventRecord::from_bytes(&raw).expect("fork must parse");
        assert_eq!(record.kind_raw(),      0x20);
        assert_eq!(record.severity_raw(),  0x00);
        assert_eq!(record.source_id_raw(), 0x0007);
        assert_eq!(record.pid(),           0x0942);
        assert_eq!(record.ts_delta_raw(),  1);
    }

    #[test]
    fn test_exec_event_from_c_bytes() {
        let raw: [u8; 16] = [
            0x45, 0x00, 0x07, 0x00, 0x2d, 0x0a, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0xb4, 0xfd, 0xc3, 0x5d,
        ];
        let record = EventRecord::from_bytes(&raw).expect("exec must parse");
        assert_eq!(record.kind_raw(),      0x45);
        assert_eq!(record.severity_raw(),  0x00);
        assert_eq!(record.source_id_raw(), 0x0007);
        assert_eq!(record.pid(),           2605);
        assert_eq!(record.ts_delta_raw(),  2);
    }

    #[test]
    fn test_invalid_crc_rejected() {
        let mut raw: [u8; 16] = [
            0x20, 0x00, 0x07, 0x00, 0x2d, 0x0a, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x50, 0xfd, 0xc7, 0xdb,
        ];
        raw[15] ^= 0xFF;
        assert!(EventRecord::from_bytes(&raw).is_err());
    }
}

