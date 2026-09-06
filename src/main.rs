// vtr-sentinel - main.rs
// VTR-METH-001 v5.1
// Target: FreeBSD 14.x x86_64, Pentium Silver

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(unused_must_use)]
#![warn(clippy::pedantic)]

mod error;
mod event { pub mod kind; pub mod record; }
mod ring { pub mod buffer; }
mod probe { pub mod entropy; pub mod dnp3; }
mod custody { pub mod chain; }
#[cfg(test)]
mod tests;
mod device { pub mod reader; }

use error::{VtrError, ErrorSeverity};
use event::kind::EventKind;
use event::record::{EventRecord, TsDelta};
use ring::buffer::{EventRingBuffer, PushResult};
use custody::chain::{CustodyChain, CustodyBlock};
use device::reader::DeviceReader;

fn main() {
    let mut ring  = EventRingBuffer::for_sentinel();
    let mut chain = CustodyChain::new();

    let genesis = EventRecord::system_event(EventKind::SentinelStarted, TsDelta::GENESIS);
    match ring.push(genesis) {
        PushResult::Stored => {}
        PushResult::OldestDiscarded => {}
    }
    match chain.seal(&genesis) {
        Ok(block) => print_block("GENESIS", &block),
        Err(e)    => { print_error("custody seal genesis", &e); return; }
    }

    let reader = match DeviceReader::open(b"/dev/vtr0\0") {
        Ok(r)  => r,
        Err(e) => { print_error("open /dev/vtr0", &e); return; }
    };

    eprintln!("VTR-SENTINEL: /dev/vtr0 open - event loop starting");

    loop {
        let record = match reader.read_event() {
            Ok(Some(r)) => r,
            Ok(None)    => continue,
            Err(e)      => {
                print_error("read_event", &e);
                if e.severity == ErrorSeverity::DaemonFatal { break; }
                continue;
            }
        };

        match ring.push(record) {
            PushResult::Stored => {}
            PushResult::OldestDiscarded => {
                let overflow = EventRecord::system_event(EventKind::RingBufferOverflow, TsDelta::new(0));
                let _ = ring.push(overflow);
            }
        }

        match chain.seal(&record) {
            Ok(block) => print_block("EVENT", &block),
            Err(e) => {
                print_error("custody seal", &e);
                if e.severity == ErrorSeverity::DaemonFatal { break; }
            }
        }
    }

    eprintln!("VTR-SENTINEL: event loop exited");
}

fn print_block(label: &str, block: &CustodyBlock) {
    eprintln!(
        "VTR-BLOCK [{}] seq={} kind=0x{:02X} pid={} hash={:02x}{:02x}{:02x}{:02x}",
        label, block.seq, block.record.kind_raw(), block.record.pid(),
        block.hash[0], block.hash[1], block.hash[2], block.hash[3],
    );
}

fn print_error(ctx: &str, e: &error::VtrError) {
    eprintln!("VTR-ERR [{}] kind={:?} layer={:?} severity={:?} os={}", ctx, e.kind, e.layer, e.severity, e.os_code);
}
