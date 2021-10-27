use crate::sys::{solid::abi, Selector};
use crate::{Interest, Token};

use std::io;

/// Waker backed by `eventfd`.
///
/// `eventfd` is effectively an 64 bit counter. All writes must be of 8
/// bytes (64 bits) and are converted (native endian) into an 64 bit
/// unsigned integer and added to the count. Reads must also be 8 bytes and
/// reset the count to 0, returning the count.
#[derive(Debug)]
pub struct Waker {
    fd: abi::c_int,
}

impl Waker {
    pub fn new(selector: &Selector, token: Token) -> io::Result<Waker> {
        syscall!(eventfd(0, abi::EFD_NONBLOCK)).and_then(|fd| {
            // Turn the file descriptor into a `Self` first so we're ensured
            // it's closed when dropped, e.g. when register below fails.
            let this = Waker { fd };
            selector
                .register(fd, token, Interest::READABLE)
                .map(|()| this)
        })
    }

    pub fn wake(&self) -> io::Result<()> {
        let buf: [u8; 8] = 1u64.to_ne_bytes();
        match syscall!(write(self.fd, buf.as_ptr() as _, buf.len())) {
            Ok(_) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                // Writing only blocks if the counter is going to overflow.
                // So we'll reset the counter to 0 and wake it again.
                self.reset()?;
                self.wake()
            }
            Err(err) => Err(err),
        }
    }

    /// Reset the eventfd object, only need to call this if `wake` fails.
    fn reset(&self) -> io::Result<()> {
        let mut buf: [u8; 8] = 0u64.to_ne_bytes();
        match syscall!(read(self.fd, buf.as_mut_ptr() as _, buf.len())) {
            Ok(_) => Ok(()),
            // If the `Waker` hasn't been awoken yet this will return a
            // `WouldBlock` error which we can safely ignore.
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        syscall!(close(self.fd)).unwrap();
    }
}
