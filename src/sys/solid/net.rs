use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::sys::solid::abi;

pub(crate) fn new_ip_socket(addr: SocketAddr, socket_type: abi::c_int) -> io::Result<abi::c_int> {
    let domain = match addr {
        SocketAddr::V4(..) => abi::AF_INET,
        SocketAddr::V6(..) => abi::AF_INET6,
    };

    new_socket(domain, socket_type)
}

/// Create a new non-blocking socket.
pub(crate) fn new_socket(domain: abi::c_int, socket_type: abi::c_int) -> io::Result<abi::c_int> {
    let socket = syscall!(socket(domain, socket_type, 0));

    let socket = socket.and_then(|socket| {
        syscall!(fcntl(socket, abi::F_SETFL, abi::O_NONBLOCK))
            .map(|_| socket)
            .map_err(|e| {
                // If either of the `fcntl` calls failed, ensure the socket is
                // closed and return the error.
                let _ = syscall!(close(socket));
                e
            })
    });

    socket
}

/// A type with the same memory layout as `abi::sockaddr`. Used in converting Rust level
/// SocketAddr* types into their system representation. The benefit of this specific
/// type over using `abi::sockaddr_storage` is that this type is exactly as large as it
/// needs to be and not a lot larger. And it can be initialized cleaner from Rust.
#[repr(C)]
pub(crate) union SocketAddrCRepr {
    v4: abi::sockaddr_in,
    v6: abi::sockaddr_in6,
}

impl SocketAddrCRepr {
    pub(crate) fn as_ptr(&self) -> *const abi::sockaddr {
        self as *const _ as *const abi::sockaddr
    }
}

/// Converts a Rust `SocketAddr` into the system representation.
pub(crate) fn socket_addr(addr: &SocketAddr) -> (SocketAddrCRepr, abi::socklen_t) {
    match addr {
        SocketAddr::V4(ref addr) => {
            // `s_addr` is stored as BE on all machine and the array is in BE order.
            // So the native endian conversion method is used so that it's never swapped.
            let sin_addr = abi::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };

            let sockaddr_in = abi::sockaddr_in {
                sin_family: abi::AF_INET as abi::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr,
                sin_zero: [0; 8],
                sin_len: 0,
            };

            let sockaddr = SocketAddrCRepr { v4: sockaddr_in };
            let socklen = size_of::<abi::sockaddr_in>() as abi::socklen_t;
            (sockaddr, socklen)
        }
        SocketAddr::V6(ref addr) => {
            let sockaddr_in6 = abi::sockaddr_in6 {
                sin6_family: abi::AF_INET6 as abi::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_addr: abi::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_flowinfo: addr.flowinfo(),
                sin6_scope_id: addr.scope_id(),
                sin6_len: 0,
            };

            let sockaddr = SocketAddrCRepr { v6: sockaddr_in6 };
            let socklen = size_of::<abi::sockaddr_in6>() as abi::socklen_t;
            (sockaddr, socklen)
        }
    }
}

/// Converts a `abi::sockaddr` compatible struct into a native Rust `SocketAddr`.
///
/// # Safety
///
/// `storage` must have the `ss_family` field correctly initialized.
/// `storage` must be initialised to a `sockaddr_in` or `sockaddr_in6`.
pub(crate) unsafe fn to_socket_addr(
    storage: *const abi::sockaddr_storage,
) -> io::Result<SocketAddr> {
    match (*storage).ss_family as abi::c_int {
        abi::AF_INET => {
            // Safety: if the ss_family field is AF_INET then storage must be a sockaddr_in.
            let addr: &abi::sockaddr_in = &*(storage as *const abi::sockaddr_in);
            let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        abi::AF_INET6 => {
            // Safety: if the ss_family field is AF_INET6 then storage must be a sockaddr_in6.
            let addr: &abi::sockaddr_in6 = &*(storage as *const abi::sockaddr_in6);
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}
