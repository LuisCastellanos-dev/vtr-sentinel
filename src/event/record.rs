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
        let data: [u8; 12] = [
            self.kind, self.severity,
            (self.source_id & 0xFF) as u8, (self.source_id >> 8) as u8,
            (self.pid & 0xFF) as u8, ((self.pid >> 8) & 0xFF) as u8,
            ((self.pid >> 16) & 0xFF) as u8, ((self.pid >> 24) & 0xFF) as u8,
            (self.ts_delta & 0xFF) as u8, ((self.ts_delta >> 8) & 0xFF) as u8,
            ((self.ts_delta >> 16) & 0xFF) as u8, ((self.ts_delta >> 24) & 0xFF) as u8,
        ];
        if Crc32::compute(&data).value() == self.checksum { Ok(()) }
        else { Err(crate::error::VtrError::new(
            crate::error::ErrorKind::ChecksumInvalid,
            crate::error::ErrorLayer::Protocol,
            crate::error::ErrorSeverity::DaemonFatal, 0)) }
    }

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
