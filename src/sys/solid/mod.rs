/// Helper macro to execute a system call that returns an `io::Result`.
//
// Macro must be defined before any modules that uses them.
#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        let res = unsafe { crate::sys::solid::abi::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::from_raw_os_error(unsafe { crate::sys::solid::abi::SOLID_NET_GetLastError() }))
        } else {
            Ok(res)
        }
    }};
}

cfg_os_poll! {
    mod abi;

    mod selector;
    pub(crate) use self::selector::{event, Event, Events, Selector};

    mod waker;
    pub(crate) use self::waker::Waker;

    cfg_net! {
        mod net;
        pub(crate) mod tcp;
        pub(crate) mod udp;
    }

    cfg_io_source! {
        use std::io;

        pub(crate) struct IoSourceState;

        impl IoSourceState {
            pub fn new() -> IoSourceState {
                IoSourceState
            }

            pub fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
            where
                F: FnOnce(&T) -> io::Result<R>,
            {
                // We don't hold state, so we can just call the function and
                // return.
                f(io)
            }
        }
    }
}

cfg_not_os_poll! {
    cfg_any_os_ext! {
        mod sourcefd;
        pub use self::sourcefd::SourceFd;
    }
}
