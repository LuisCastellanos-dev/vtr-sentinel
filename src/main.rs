// vtr-sentinel — main.rs
// VTR-METH-001 v5.1
// Target: FreeBSD 14.x x86_64, Pentium Silver
// No panic. No unwrap. No heap after init.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(unused_must_use)]
#![warn(clippy::pedantic)]

mod error;
mod event {
    pub mod kind;
    pub mod record;
}
mod ring {
    pub mod buffer;
}
mod probe {
    pub mod entropy;
    pub mod dnp3;
}
mod custody {
    pub mod chain;
}

use error::VtrError;
use event::kind::EventKind;
use event::record::{EventRecord, SourceId, TsDelta};
use ring::buffer::EventRingBuffer;

fn main() {
    // Fase 0 — inicialización antes de cualquier operación
    // Todo el heap se reserva aquí — ninguna alloc después de este punto
    let mut ring = EventRingBuffer::for_sentinel();

    // Evento de génesis — primer registro de la cadena
    let genesis = EventRecord::system_event(
        EventKind::SentinelStarted,
        TsDelta::GENESIS,
    );

    match ring.push(genesis) {
        ring::buffer::PushResult::Stored => {}
        ring::buffer::PushResult::OldestDiscarded => {
            // No puede ocurrir en el primer push — ring vacío
            // Si ocurriera, es evidencia de corrupción de memoria
        }
    }

    // TODO: Fase 1 — pledge(2) / unveil(2) en FreeBSD
    // TODO: Fase 2 — kqueue event loop
    // TODO: Fase 3 — probe initialization
    // TODO: Fase 4 — custody chain init
}
