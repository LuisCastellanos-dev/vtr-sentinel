// src/device/reader.rs
// /dev/vtr0 reader — kqueue-based event loop
// FreeBSD 14.x only in production.
// Linux: stub that always returns error (for cargo test/build).

use crate::error::{VtrError, ErrorKind, ErrorLayer, ErrorSeverity};
use crate::event::record::EventRecord;

#[cfg(target_os = "freebsd")]
pub struct DeviceReader { fd: i32, kq: i32 }

#[cfg(not(target_os = "freebsd"))]
pub struct DeviceReader { _stub: () }

#[cfg(target_os = "freebsd")]
impl DeviceReader {
    pub fn open(path: &[u8]) -> Result<Self, VtrError> {
        use libc::{O_RDONLY, O_NONBLOCK};

        // FINDING [2026-09-02]: EVFILT_READ is not supported for cdevs in FreeBSD.
        // kevent(EVFILT_READ) works for sockets/pipes but returns ENODEV for /dev/vtr0.
        // Decision: use select(2) with timeout loop instead of kqueue for cdev polling.
        // kq field removed — only fd is needed.
        let fd = unsafe {
            libc::open(path.as_ptr() as *const libc::c_char, O_RDONLY | O_NONBLOCK)
        };
        if fd < 0 {
            return Err(VtrError::new(
                ErrorKind::KqueueInit, ErrorLayer::Hardware,
                ErrorSeverity::DaemonFatal,
                unsafe { *libc::__error() },
            ));
        }

        Ok(Self { fd, kq: -1 })
    }

    pub fn read_event(&self) -> Result<Option<EventRecord>, VtrError> {
        // Poll with select(2) — 100ms timeout to allow clean shutdown
        let mut readfds: libc::fd_set = unsafe { core::mem::zeroed() };
        unsafe { libc::FD_SET(self.fd, &mut readfds) };
        let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 100_000 };

        let n = unsafe {
            libc::select(self.fd + 1, &mut readfds, core::ptr::null_mut(),
                         core::ptr::null_mut(), &mut timeout)
        };
        if n < 0 {
            return Err(VtrError::new(
                ErrorKind::KqueueEvent, ErrorLayer::Hardware,
                ErrorSeverity::DaemonFatal,
                unsafe { *libc::__error() },
            ));
        }
        if n == 0 { return Ok(None); } // timeout — no data

        let mut buf = [0u8; 16];
        let bytes_read = unsafe {
            libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, 16)
        };
        if bytes_read == 0 { return Ok(None); }
        if bytes_read != 16 {
            return Err(VtrError::new(
                ErrorKind::PayloadOverflow, ErrorLayer::Protocol,
                ErrorSeverity::DaemonFatal, bytes_read as i32,
            ));
        }
        EventRecord::from_bytes(&buf).map(Some)
    }
}

#[cfg(target_os = "freebsd")]
impl Drop for DeviceReader {
    fn drop(&mut self) {
        unsafe { libc::close(self.kq); libc::close(self.fd); }
    }
}

#[cfg(not(target_os = "freebsd"))]
impl DeviceReader {
    pub fn open(_path: &[u8]) -> Result<Self, VtrError> {
        Err(VtrError::new(
            ErrorKind::KqueueInit, ErrorLayer::Hardware,
            ErrorSeverity::DaemonFatal, -1,
        ))
    }

    pub fn read_event(&self) -> Result<Option<EventRecord>, VtrError> {
        Err(VtrError::new(
            ErrorKind::KqueueEvent, ErrorLayer::Hardware,
            ErrorSeverity::DaemonFatal, -1,
        ))
    }
}
