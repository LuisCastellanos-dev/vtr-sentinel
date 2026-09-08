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
    // VS-010 fix: accept optional file path argument for custody chain output
    let chain_path: Option<std::path::PathBuf> = std::env::args().nth(1).map(Into::into);
    let mut chain_file: Option<std::fs::File> = if let Some(ref path) = chain_path {
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => {
                eprintln!("VTR-SENTINEL: custody chain -> {}", path.display());
                Some(f)
            }
            Err(e) => {
                eprintln!("VTR-SENTINEL: cannot open chain file {}: {}", path.display(), e);
                return;
            }
        }
    } else {
        eprintln!("VTR-SENTINEL: no chain file specified, stdout only");
        None
    };

    let mut ring  = EventRingBuffer::for_sentinel();
    let mut chain = CustodyChain::new();

    let genesis = EventRecord::system_event(EventKind::SentinelStarted, TsDelta::GENESIS);
    match ring.push(genesis) {
        PushResult::Stored => {}
        PushResult::OldestDiscarded => {}
    }
    match chain.seal(&genesis) {
        Ok(block) => { print_block("GENESIS", &block, &mut chain_file); }
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
            Ok(block) => { print_block("EVENT", &block, &mut chain_file); }
            Err(e) => {
                print_error("custody seal", &e);
                if e.severity == ErrorSeverity::DaemonFatal { break; }
            }
        }
    }

    eprintln!("VTR-SENTINEL: event loop exited");
}

fn print_block(label: &str, block: &CustodyBlock, chain_file: &mut Option<std::fs::File>) {
    let line = format!(
        "VTR-BLOCK [{}] seq={} kind=0x{:02X} pid={} hash={:02x}{:02x}{:02x}{:02x}\n",
        label, block.seq, block.record.kind_raw(), block.record.pid(),
        block.hash[0], block.hash[1], block.hash[2], block.hash[3],
    );
    eprint!("{}", line);
    if let Some(ref mut f) = chain_file {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}

fn print_error(ctx: &str, e: &error::VtrError) {
    eprintln!("VTR-ERR [{}] kind={:?} layer={:?} severity={:?} os={}", ctx, e.kind, e.layer, e.severity, e.os_code);
}
