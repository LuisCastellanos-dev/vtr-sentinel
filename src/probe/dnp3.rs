// src/probe/dnp3.rs
// DNP3 frame parsing — CRC-16 IEEE 1815-2012
// Ported from vtr-shield sentinel.py
// Polynomial: 0xA6BC (IEEE 1815-2012 Annex B)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionCode {
    Confirm       = 0x00,
    Read          = 0x01,
    Write         = 0x02,
    DirectOperate = 0x03,
    FreezeNoAck   = 0x08,
    ColdRestart   = 0x0D,
    WarmRestart   = 0x0E,
    InitData      = 0x0F,
    Response      = 0x81,
}

impl FunctionCode {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Confirm),
            0x01 => Some(Self::Read),
            0x02 => Some(Self::Write),
            0x03 => Some(Self::DirectOperate),
            0x08 => Some(Self::FreezeNoAck),
            0x0D => Some(Self::ColdRestart),
            0x0E => Some(Self::WarmRestart),
            0x0F => Some(Self::InitData),
            0x81 => Some(Self::Response),
            _    => None,
        }
    }
}

#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0x0000u16;
    for &byte in data {
        let mut b = byte;
        for _ in 0..8 {
            let mix = (crc ^ b as u16) & 0x01;
            crc >>= 1;
            if mix != 0 { crc ^= 0xA6BC; }
            b >>= 1;
        }
    }
    !crc
}

pub const MIN_FRAME_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnp3ParseResult {
    pub crc_valid:     bool,
    pub function_code: Option<FunctionCode>,
    pub master_addr:   u16,
    pub outstation:    u16,
    pub payload_len:   u8,
}

pub fn parse(frame: &[u8]) -> Result<Dnp3ParseResult, ()> {
    if frame.len() < MIN_FRAME_LEN { return Err(()); }
    let payload_len = frame[2];
    let master_addr = u16::from_le_bytes([frame[4], frame[5]]);
    let outstation  = u16::from_le_bytes([frame[6], frame[7]]);
    let func_byte   = frame[8];
    let expected_crc = crc16(&frame[0..8]);
    let frame_crc    = u16::from_le_bytes([frame[8], frame[9]]);
    let crc_valid    = expected_crc == frame_crc;
    Ok(Dnp3ParseResult { crc_valid, function_code: FunctionCode::from_u8(func_byte), master_addr, outstation, payload_len })
}
