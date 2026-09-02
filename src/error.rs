// src/error.rs
// VTR-METH-001 v5.1 — ZIC en sistema de tipos
// Sin panic, sin unwrap, sin From<String>
// Cada variante tiene causa explícita y capa de origen

use core::fmt;

/// Capa de origen del error — para trazabilidad forense
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorLayer {
    Hardware     = 0,
    Protocol     = 1,
    Logic        = 2,
    Init         = 3,
}

/// Severidad — decisión de continuación del daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ErrorSeverity {
    Recoverable  = 0,
    ModuleFatal  = 1,
    DaemonFatal  = 2,
}

/// Error con contexto forense — sin heap, sin String
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtrError {
    pub kind:     ErrorKind,
    pub layer:    ErrorLayer,
    pub severity: ErrorSeverity,
    pub os_code:  i32,
}

impl VtrError {
    #[must_use]
    pub const fn new(
        kind:     ErrorKind,
        layer:    ErrorLayer,
        severity: ErrorSeverity,
        os_code:  i32,
    ) -> Self {
        Self { kind, layer, severity, os_code }
    }

    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self.severity, ErrorSeverity::Recoverable)
    }

    #[must_use]
    pub const fn is_forensic_evidence(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::SequenceJump
            | ErrorKind::CustodyHashMismatch
            | ErrorKind::ChecksumInvalid
            | ErrorKind::PledgeViolation
        )
    }

    #[must_use]
    pub const fn kqueue_init(os_code: i32) -> Self {
        Self::new(ErrorKind::KqueueInit, ErrorLayer::Hardware,
                  ErrorSeverity::DaemonFatal, os_code)
    }

    #[must_use]
    pub const fn dnp3_crc(os_code: i32) -> Self {
        Self::new(ErrorKind::Dnp3CrcInvalid, ErrorLayer::Protocol,
                  ErrorSeverity::Recoverable, os_code)
    }

    #[must_use]
    pub const fn custody_mismatch() -> Self {
        Self::new(ErrorKind::CustodyHashMismatch, ErrorLayer::Logic,
                  ErrorSeverity::DaemonFatal, 0)
    }

    #[must_use]
    pub const fn sequence_jump() -> Self {
        Self::new(ErrorKind::SequenceJump, ErrorLayer::Logic,
                  ErrorSeverity::ModuleFatal, 0)
    }

    #[must_use]
    pub const fn ring_full() -> Self {
        Self::new(ErrorKind::RingBufferFull, ErrorLayer::Logic,
                  ErrorSeverity::Recoverable, 0)
    }

    #[must_use]
    pub const fn entropy_insufficient() -> Self {
        Self::new(ErrorKind::EntropyInsufficient, ErrorLayer::Protocol,
                  ErrorSeverity::Recoverable, 0)
    }

    #[must_use]
    pub const fn pledge_violation(os_code: i32) -> Self {
        Self::new(ErrorKind::PledgeViolation, ErrorLayer::Init,
                  ErrorSeverity::DaemonFatal, os_code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorKind {
    // Capa 0 — Hardware/OS
    KqueueInit          = 0,
    KqueueEvent         = 1,
    CustodyWriteFailed  = 2,
    ProcUnavailable     = 3,

    // Capa 1 — Protocolo/Parsing
    Dnp3CrcInvalid      = 10,
    Dnp3UnknownFunction = 11,
    EntropyInsufficient = 12,
    ChecksumInvalid     = 13,
    PayloadOverflow     = 14,

    // Capa 2 — Lógica interna
    RingBufferFull      = 20,
    CustodyHashMismatch = 21,
    SequenceJump        = 22,
    CustodyNoGenesis    = 23,

    // Capa 3 — Inicialización
    PledgeViolation     = 30,
    UnveilViolation     = 31,
    ConfigMissing       = 32,
    CliInvalid          = 33,
}

impl fmt::Display for VtrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VTR-ERR layer={:?} kind={:?} severity={:?} os={}",
            self.layer, self.kind, self.severity, self.os_code
        )
    }
}
