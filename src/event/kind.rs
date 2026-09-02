// src/event/kind.rs
// VTR-METH-001 v5.1 — EventKind exhaustivo
// Derivado de findings reales: VTR-RPi-001/002, GHI-A/R/F-001/002,
// D58754 FreeBSD, vtr-shield dns_probe.py
// Sin catch-all. Sin Other. Sin variantes genéricas.
// repr(u8) — 1 byte en EventRecord.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventFamily {
    Memory     = 0,
    Contract   = 1,
    State      = 2,
    DoS        = 3,
    Provenance = 4,
    Network    = 5,
    System     = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EventSeverity {
    Observed   = 0,
    Probable   = 1,
    Confirmed  = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exploitability {
    DirectUserspace   = 0,
    LatentApi         = 1,
    PrivilegedOnly    = 2,
    Undetermined      = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    // Memory (0x00–0x0F) — VTR-RPi-001, D58754
    AllocWithoutRelease   = 0x00,
    IoctlRollbackMissing  = 0x01,
    BoundaryViolation     = 0x02,
    RefcountLeak          = 0x03,
    UseAfterError         = 0x04,
    StackLayoutViolation  = 0x05,

    // Contract (0x10–0x1F) — GHI-A-001, VTR-RPi-002
    ImplicitContractBreach   = 0x10,
    UntrustedInputPropagated = 0x11,
    ExportSymbolImplicit     = 0x12,
    UndocumentedDelegation   = 0x13,
    StatefulApiImplicit      = 0x14,

    // State (0x20–0x2F) — GHI-R-001/002
    StateContamination     = 0x20,
    SingletonReuse         = 0x21,
    MutableLimitExposed    = 0x22,
    InvalidStateTransition = 0x23,
    StateRaceCondition     = 0x24,
    GlobalStateResidual    = 0x25,

    // DoS (0x30–0x3F) — GHI-R-002
    AlgorithmicDoS        = 0x30,
    UnboundedLoop         = 0x31,
    UnboundedRecursion    = 0x32,
    EventRateAnomaly      = 0x33,
    MemoryGrowthAnomaly   = 0x34,

    // Provenance (0x40–0x4F) — GHI-F-001, CVE-2021-42574
    ProvenanceBroken      = 0x40,
    UnsealedDependency    = 0x41,
    HashMismatch          = 0x42,
    NonReproducibleBuild  = 0x43,
    TrojanSourceCandidate = 0x44,
    UnsignedExecution     = 0x45,
    PostSealModification  = 0x46,

    // Network (0x50–0x5F) — vtr-shield probes
    HighEntropyPayload     = 0x50,
    Dnp3CrcInvalid         = 0x51,
    Dnp3UnknownFunction    = 0x52,
    Dnp3UnauthorizedMaster = 0x53,
    TlsObsoleteVersion     = 0x54,
    TlsWeakCipher          = 0x55,
    TlsMissingSni          = 0x56,
    DnsRateAnomaly         = 0x57,
    DnsLabelAnomaly        = 0x58,
    HttpAnomalousRequest   = 0x59,

    // System (0x60–0x6F) — internal
    SentinelStarted       = 0x60,
    SentinelStopped       = 0x61,
    ProbeRestarted        = 0x62,
    RingBufferOverflow    = 0x63,
    CustodySequenceJump   = 0x64,
    PledgeViolation       = 0x65,
    ConfigReloaded        = 0x66,
}

impl EventKind {
    #[must_use]
    pub const fn family(&self) -> EventFamily {
        match self {
            Self::AllocWithoutRelease
            | Self::IoctlRollbackMissing
            | Self::BoundaryViolation
            | Self::RefcountLeak
            | Self::UseAfterError
            | Self::StackLayoutViolation
                => EventFamily::Memory,

            Self::ImplicitContractBreach
            | Self::UntrustedInputPropagated
            | Self::ExportSymbolImplicit
            | Self::UndocumentedDelegation
            | Self::StatefulApiImplicit
                => EventFamily::Contract,

            Self::StateContamination
            | Self::SingletonReuse
            | Self::MutableLimitExposed
            | Self::InvalidStateTransition
            | Self::StateRaceCondition
            | Self::GlobalStateResidual
                => EventFamily::State,

            Self::AlgorithmicDoS
            | Self::UnboundedLoop
            | Self::UnboundedRecursion
            | Self::EventRateAnomaly
            | Self::MemoryGrowthAnomaly
                => EventFamily::DoS,

            Self::ProvenanceBroken
            | Self::UnsealedDependency
            | Self::HashMismatch
            | Self::NonReproducibleBuild
            | Self::TrojanSourceCandidate
            | Self::UnsignedExecution
            | Self::PostSealModification
                => EventFamily::Provenance,

            Self::HighEntropyPayload
            | Self::Dnp3CrcInvalid
            | Self::Dnp3UnknownFunction
            | Self::Dnp3UnauthorizedMaster
            | Self::TlsObsoleteVersion
            | Self::TlsWeakCipher
            | Self::TlsMissingSni
            | Self::DnsRateAnomaly
            | Self::DnsLabelAnomaly
            | Self::HttpAnomalousRequest
                => EventFamily::Network,

            Self::SentinelStarted
            | Self::SentinelStopped
            | Self::ProbeRestarted
            | Self::RingBufferOverflow
            | Self::CustodySequenceJump
            | Self::PledgeViolation
            | Self::ConfigReloaded
                => EventFamily::System,
        }
    }

    #[must_use]
    pub const fn default_severity(&self) -> EventSeverity {
        match self {
            Self::AllocWithoutRelease    => EventSeverity::Confirmed,
            Self::IoctlRollbackMissing   => EventSeverity::Probable,
            Self::BoundaryViolation      => EventSeverity::Confirmed,
            Self::RefcountLeak           => EventSeverity::Confirmed,
            Self::UseAfterError          => EventSeverity::Probable,
            Self::StackLayoutViolation   => EventSeverity::Confirmed,
            Self::ImplicitContractBreach    => EventSeverity::Probable,
            Self::UntrustedInputPropagated  => EventSeverity::Probable,
            Self::ExportSymbolImplicit      => EventSeverity::Observed,
            Self::UndocumentedDelegation    => EventSeverity::Observed,
            Self::StatefulApiImplicit       => EventSeverity::Observed,
            Self::StateContamination      => EventSeverity::Confirmed,
            Self::SingletonReuse          => EventSeverity::Probable,
            Self::MutableLimitExposed     => EventSeverity::Probable,
            Self::InvalidStateTransition  => EventSeverity::Confirmed,
            Self::StateRaceCondition      => EventSeverity::Probable,
            Self::GlobalStateResidual     => EventSeverity::Observed,
            Self::AlgorithmicDoS          => EventSeverity::Probable,
            Self::UnboundedLoop           => EventSeverity::Probable,
            Self::UnboundedRecursion      => EventSeverity::Probable,
            Self::EventRateAnomaly        => EventSeverity::Observed,
            Self::MemoryGrowthAnomaly     => EventSeverity::Observed,
            Self::ProvenanceBroken        => EventSeverity::Confirmed,
            Self::UnsealedDependency      => EventSeverity::Confirmed,
            Self::HashMismatch            => EventSeverity::Confirmed,
            Self::NonReproducibleBuild    => EventSeverity::Confirmed,
            Self::TrojanSourceCandidate   => EventSeverity::Confirmed,
            Self::UnsignedExecution       => EventSeverity::Probable,
            Self::PostSealModification    => EventSeverity::Confirmed,
            Self::HighEntropyPayload      => EventSeverity::Observed,
            Self::Dnp3CrcInvalid          => EventSeverity::Confirmed,
            Self::Dnp3UnknownFunction     => EventSeverity::Probable,
            Self::Dnp3UnauthorizedMaster  => EventSeverity::Confirmed,
            Self::TlsObsoleteVersion      => EventSeverity::Confirmed,
            Self::TlsWeakCipher           => EventSeverity::Confirmed,
            Self::TlsMissingSni           => EventSeverity::Observed,
            Self::DnsRateAnomaly          => EventSeverity::Observed,
            Self::DnsLabelAnomaly         => EventSeverity::Observed,
            Self::HttpAnomalousRequest    => EventSeverity::Observed,
            Self::SentinelStarted         => EventSeverity::Observed,
            Self::SentinelStopped         => EventSeverity::Observed,
            Self::ProbeRestarted          => EventSeverity::Observed,
            Self::RingBufferOverflow      => EventSeverity::Observed,
            Self::CustodySequenceJump     => EventSeverity::Confirmed,
            Self::PledgeViolation         => EventSeverity::Confirmed,
            Self::ConfigReloaded          => EventSeverity::Observed,
        }
    }

    #[must_use]
    pub const fn requires_immediate_custody(&self) -> bool {
        matches!(
            self,
            Self::HashMismatch
            | Self::PostSealModification
            | Self::CustodySequenceJump
            | Self::TrojanSourceCandidate
            | Self::PledgeViolation
            | Self::Dnp3UnauthorizedMaster
            | Self::BoundaryViolation
        )
    }

    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::AllocWithoutRelease),
            0x01 => Some(Self::IoctlRollbackMissing),
            0x02 => Some(Self::BoundaryViolation),
            0x03 => Some(Self::RefcountLeak),
            0x04 => Some(Self::UseAfterError),
            0x05 => Some(Self::StackLayoutViolation),
            0x10 => Some(Self::ImplicitContractBreach),
            0x11 => Some(Self::UntrustedInputPropagated),
            0x12 => Some(Self::ExportSymbolImplicit),
            0x13 => Some(Self::UndocumentedDelegation),
            0x14 => Some(Self::StatefulApiImplicit),
            0x20 => Some(Self::StateContamination),
            0x21 => Some(Self::SingletonReuse),
            0x22 => Some(Self::MutableLimitExposed),
            0x23 => Some(Self::InvalidStateTransition),
            0x24 => Some(Self::StateRaceCondition),
            0x25 => Some(Self::GlobalStateResidual),
            0x30 => Some(Self::AlgorithmicDoS),
            0x31 => Some(Self::UnboundedLoop),
            0x32 => Some(Self::UnboundedRecursion),
            0x33 => Some(Self::EventRateAnomaly),
            0x34 => Some(Self::MemoryGrowthAnomaly),
            0x40 => Some(Self::ProvenanceBroken),
            0x41 => Some(Self::UnsealedDependency),
            0x42 => Some(Self::HashMismatch),
            0x43 => Some(Self::NonReproducibleBuild),
            0x44 => Some(Self::TrojanSourceCandidate),
            0x45 => Some(Self::UnsignedExecution),
            0x46 => Some(Self::PostSealModification),
            0x50 => Some(Self::HighEntropyPayload),
            0x51 => Some(Self::Dnp3CrcInvalid),
            0x52 => Some(Self::Dnp3UnknownFunction),
            0x53 => Some(Self::Dnp3UnauthorizedMaster),
            0x54 => Some(Self::TlsObsoleteVersion),
            0x55 => Some(Self::TlsWeakCipher),
            0x56 => Some(Self::TlsMissingSni),
            0x57 => Some(Self::DnsRateAnomaly),
            0x58 => Some(Self::DnsLabelAnomaly),
            0x59 => Some(Self::HttpAnomalousRequest),
            0x60 => Some(Self::SentinelStarted),
            0x61 => Some(Self::SentinelStopped),
            0x62 => Some(Self::ProbeRestarted),
            0x63 => Some(Self::RingBufferOverflow),
            0x64 => Some(Self::CustodySequenceJump),
            0x65 => Some(Self::PledgeViolation),
            0x66 => Some(Self::ConfigReloaded),
            _    => None,
        }
    }
}

impl EventSeverity {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Observed),
            1 => Some(Self::Probable),
            2 => Some(Self::Confirmed),
            _ => None,
        }
    }
}
