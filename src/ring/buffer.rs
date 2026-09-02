// src/ring/buffer.rs — RingBuffer<T, const N: usize>
// Fixed size at compile-time. No heap. O(1) all operations.
// N must be power of 2. Single-threaded by kqueue design.

use crate::error::VtrError;
use crate::event::record::EventRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult { Stored, OldestDiscarded }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopResult { Record(EventRecord), Empty }

pub struct RingBuffer<T, const N: usize> where T: Copy {
    buf:   [T; N],
    head:  usize,
    tail:  usize,
    count: usize,
}

impl<T, const N: usize> RingBuffer<T, N> where T: Copy {
    #[must_use]
    pub const fn new(initial: T) -> Self {
        Self { buf: [initial; N], head: 0, tail: 0, count: 0 }
    }
    #[must_use] pub const fn capacity(&self) -> usize { N - 1 }
    #[must_use] pub const fn len(&self) -> usize { self.count }
    #[must_use] pub const fn is_empty(&self) -> bool { self.count == 0 }
    #[must_use] pub const fn is_full(&self) -> bool { self.count == N - 1 }

    #[must_use]
    pub fn usage_pct(&self) -> u8 {
        if N == 1 { return 100; }
        ((self.count * 100) / (N - 1)).min(100) as u8
    }

    pub fn push(&mut self, item: T) -> PushResult {
        if self.is_full() {
            self.head = (self.head + 1) & (N - 1);
            self.count -= 1;
            self.buf[self.tail] = item;
            self.tail = (self.tail + 1) & (N - 1);
            self.count += 1;
            PushResult::OldestDiscarded
        } else {
            self.buf[self.tail] = item;
            self.tail = (self.tail + 1) & (N - 1);
            self.count += 1;
            PushResult::Stored
        }
    }

    pub fn pop(&mut self) -> PopResult {
        if self.is_empty() { return PopResult::Empty; }
        let item = self.buf[self.head];
        self.head = (self.head + 1) & (N - 1);
        self.count -= 1;
        PopResult::Record(item)
    }

    pub fn drain_into(&mut self, dst: &mut [T]) -> usize {
        let to_copy = self.count.min(dst.len());
        for i in 0..to_copy { dst[i] = self.buf[(self.head + i) & (N - 1)]; }
        self.head = (self.head + to_copy) & (N - 1);
        self.count -= to_copy;
        to_copy
    }

    pub fn reset(&mut self, initial: T) {
        self.buf = [initial; N];
        self.head = 0; self.tail = 0; self.count = 0;
    }
}

const _ASSERT_L1_FIT: () = {
    assert!(
        core::mem::size_of::<EventRecord>() * 2048 <= 32 * 1024,
        "RingBuffer<EventRecord, 2048> must fit in L1 cache (32KB)"
    );
};

pub type EventRingBuffer = RingBuffer<EventRecord, 2048>;

impl EventRingBuffer {
    #[must_use]
    pub fn for_sentinel() -> Self {
        use crate::event::kind::EventKind;
        use crate::event::record::{SourceId, TsDelta};
        let genesis = EventRecord::new(
            EventKind::SentinelStarted,
            EventKind::SentinelStarted.default_severity(),
            SourceId::SYSTEM, 0, TsDelta::GENESIS,
        );
        Self::new(genesis)
    }

    pub fn push_verified(&mut self, record: EventRecord) -> Result<PushResult, VtrError> {
        record.verify()?;
        Ok(self.push(record))
    }
}
