// src/device/reader.rs
// /dev/vtr0 reader — kqueue-based event loop
// Production: FreeBSD 14.x only.
// Development: stub implementation for cargo test on Linux.

use crate::error::{VtrError, ErrorKind, ErrorLayer, ErrorSeverity};
use crate::event::record::EventRecord;

pub struct DeviceReader {
    #[cfg(target_os = "freebsd")]
    fd: i32,
    #[cfg(target_os = "freebsd")]
    kq: i32,
    #[cfg(not(target_os = "freebsd"))]
    _stub: (),
}

impl DeviceReader {
    /// Open /dev/vtr0 and register with kqueue.
    pub fn open(_path: &[u8]) -> Result<Self, VtrError> {
        #[cfg(target_os = "freebsd")]
        {
            use libc::{O_RDONLY, O_NONBLOCK, EVFILT_READ, EV_ADD, EV_ENABLE};
            use core::mem::MaybeUninit;

            let fd = unsafe {
                libc::open(_path.as_ptr() as *const libc::c_char, O_RDONLY | O_NONBLOCK)
            };
            if fd < 0 {
                return Err(VtrError::new(
                    ErrorKind::KqueueInit, ErrorLayer::Hardware,
                    ErrorSeverity::DaemonFatal,
                    unsafe { *libc::__error() },
                ));
            }

            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                unsafe { libc::close(fd) };
                return Err(VtrError::kqueue_init(unsafe { *libc::__error() }));
            }

            let mut change: libc::kevent = unsafe { MaybeUninit::zeroed().assume_init() };
            change.ident  = fd as libc::uintptr_t;
            change.filter = EVFILT_READ as libc::int16_t;
            change.flags  = (EV_ADD | EV_ENABLE) as libc::uint16_t;

            let ret = unsafe {
                libc::kevent(kq, &change, 1, core::ptr::null_mut(), 0, core::ptr::null())
            };
            if ret < 0 {
                unsafe { libc::close(fd); libc::close(kq); }
                return Err(VtrError::kqueue_init(unsafe { *libc::__error() }));
            }

            return Ok(Self { fd, kq });
        }

        #[cfg(not(target_os = "freebsd"))]
        Err(VtrError::new(
            ErrorKind::KqueueInit, ErrorLayer::Hardware,
            ErrorSeverity::DaemonFatal, -1,
        ))
    }

    /// Wait for data and read one EventRecord.
    pub fn read_event(&self) -> Result<Option<EventRecord>, VtrError> {
        #[cfg(target_os = "freebsd")]
        {
            use core::mem::MaybeUninit;

            let mut event: libc::kevent = unsafe { MaybeUninit::zeroed().assume_init() };
            let n = unsafe {
                libc::kevent(self.kq, core::ptr::null(), 0,
                             &mut event, 1, core::ptr::null())
            };
            if n < 0 {
                return Err(VtrError::new(
                    ErrorKind::KqueueEvent, ErrorLayer::Hardware,
                    ErrorSeverity::DaemonFatal,
                    unsafe { *libc::__error() },
                ));
            }
            if n == 0 { return Ok(None); }

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
            return EventRecord::from_bytes(&buf).map(Some);
        }

        #[cfg(not(target_os = "freebsd"))]
        Err(VtrError::new(
            ErrorKind::KqueueEvent, ErrorLayer::Hardware,
            ErrorSeverity::DaemonFatal, -1,
        ))
    }
}

#[cfg(target_os = "freebsd")]
impl Drop for DeviceReader {
    fn drop(&mut self) {
        unsafe { libc::close(self.kq); libc::close(self.fd); }
    }
}
