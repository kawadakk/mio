use crate::{
    sys::solid::abi::{self, EPOLLET, EPOLLIN, EPOLLOUT},
    Interest, Token,
};

use std::os::solid::io::{AsRawFd, RawFd};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::{cmp, i32, io};

/// Unique id for use as `SelectorId`.
#[cfg(debug_assertions)]
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug)]
pub struct Selector {
    #[cfg(debug_assertions)]
    id: usize,
    ep: RawFd,
    #[cfg(debug_assertions)]
    has_waker: AtomicBool,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        syscall!(epoll_create(0)).map(|ep| Selector {
            #[cfg(debug_assertions)]
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            ep,
            #[cfg(debug_assertions)]
            has_waker: AtomicBool::new(false),
        })
    }

    pub fn try_clone(&self) -> io::Result<Selector> {
        syscall!(dup(self.ep)).map(|ep| Selector {
            // It's the same selector, so we use the same id.
            #[cfg(debug_assertions)]
            id: self.id,
            ep,
            #[cfg(debug_assertions)]
            has_waker: AtomicBool::new(self.has_waker.load(Ordering::Acquire)),
        })
    }

    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let timeout = timeout
            .map(|to| {
                // `Duration::as_millis` truncates, so round up. This avoids
                // turning sub-millisecond timeouts into a zero timeout, unless
                // the caller explicitly requests that by specifying a zero
                // timeout.
                let to_ms = to
                    .checked_add(Duration::from_nanos(999_999))
                    .unwrap_or(to)
                    .as_millis();
                cmp::min(to_ms, abi::c_int::MAX as u128) as abi::c_int
            })
            .unwrap_or(-1);

        events.clear();
        syscall!(epoll_wait(
            self.ep,
            events.as_mut_ptr(),
            events.capacity() as i32,
            timeout,
        ))
        .map(|n_events| {
            // This is safe because `epoll_wait` ensures that `n_events` are
            // assigned.
            unsafe { events.set_len(n_events as usize) };
        })
    }

    pub fn register(&self, fd: RawFd, token: Token, interests: Interest) -> io::Result<()> {
        let mut event = abi::epoll_event {
            events: interests_to_epoll(interests),
            flags: EPOLLET,
            u64: usize::from(token) as u64,
        };

        syscall!(epoll_ctl(self.ep, abi::EPOLL_CTL_ADD, fd, &mut event)).map(|_| ())
    }

    #[cfg(debug_assertions)]
    pub fn register_waker(&self) -> bool {
        self.has_waker.swap(true, Ordering::AcqRel)
    }
}

cfg_io_source! {
    use std::ptr;

    impl Selector {
        pub fn reregister(&self, fd: RawFd, token: Token, interests: Interest) -> io::Result<()> {
            let mut event = abi::epoll_event {
                events: interests_to_epoll(interests),
                flags: EPOLLET,
                u64: usize::from(token) as u64,
            };

            syscall!(epoll_ctl(self.ep, abi::EPOLL_CTL_MOD, fd, &mut event)).map(|_| ())
        }

        pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
            syscall!(epoll_ctl(self.ep, abi::EPOLL_CTL_DEL, fd, ptr::null_mut())).map(|_| ())
        }

        #[cfg(debug_assertions)]
        pub fn id(&self) -> usize {
            self.id
        }
    }
}

impl AsRawFd for Selector {
    fn as_raw_fd(&self) -> RawFd {
        self.ep
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        if let Err(err) = syscall!(close(self.ep)) {
            error!("error closing epoll: {}", err);
        }
    }
}

fn interests_to_epoll(interests: Interest) -> abi::PollMask {
    let mut kind = 0;

    if interests.is_readable() {
        kind = EPOLLIN /* | EPOLLRDHUP*/;
    }

    if interests.is_writable() {
        kind |= EPOLLOUT;
    }

    kind
}

pub type Event = abi::epoll_event;
pub type Events = Vec<Event>;

pub mod event {
    use std::fmt;

    use crate::sys::{solid::abi, Event};
    use crate::Token;

    pub fn token(event: &Event) -> Token {
        Token(event.u64 as usize)
    }

    pub fn is_readable(event: &Event) -> bool {
        (event.events & abi::EPOLLIN) != 0 || (event.events & abi::EPOLLPRI) != 0
    }

    pub fn is_writable(event: &Event) -> bool {
        (event.events & abi::EPOLLOUT) != 0
    }

    pub fn is_error(event: &Event) -> bool {
        (event.events & abi::EPOLLERR) != 0
    }

    pub fn is_read_closed(event: &Event) -> bool {
        // Both halves of the socket have closed
        event.events & abi::EPOLLHUP != 0
    }

    pub fn is_write_closed(event: &Event) -> bool {
        // Both halves of the socket have closed
        event.events  & abi::EPOLLHUP != 0
            // Unix pipe write end has closed
            || (event.events  & abi::EPOLLOUT != 0
                && event.events  & abi::EPOLLERR != 0)
            // The other side (read end) of a Unix pipe has closed.
            || event.events  == abi::EPOLLERR
    }

    pub fn is_priority(event: &Event) -> bool {
        (event.events & abi::EPOLLPRI) != 0
    }

    pub fn is_aio(_: &Event) -> bool {
        // Not supported in the kernel, only in abi.
        false
    }

    pub fn is_lio(_: &Event) -> bool {
        // Not supported.
        false
    }

    pub fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn check_events(got: &abi::PollMask, want: &abi::PollMask) -> bool {
            *got & want != 0
        }
        debug_detail!(
            EventsDetails(abi::PollMask),
            check_events,
            abi::EPOLLIN,
            abi::EPOLLPRI,
            abi::EPOLLOUT,
            abi::EPOLLRDNORM,
            abi::EPOLLRDBAND,
            abi::EPOLLWRNORM,
            abi::EPOLLWRBAND,
            abi::EPOLLERR,
            abi::EPOLLHUP,
        );

        #[allow(clippy::trivially_copy_pass_by_ref)]
        fn check_flags(got: &abi::EPollFdFlags, want: &abi::EPollFdFlags) -> bool {
            *got & want != 0
        }
        debug_detail!(
            FlagsDetails(abi::EPollFdFlags),
            check_flags,
            abi::EPOLLET,
            abi::EPOLLONESHOT,
        );

        let e_u64 = event.u64;
        f.debug_struct("epoll_event")
            .field("events", &EventsDetails(event.events))
            .field("flags", &FlagsDetails(event.flags))
            .field("u64", &e_u64)
            .finish()
    }
}
