use std::io;
use std::mem;
use std::net::{self, SocketAddr};
use std::os::solid::io::{AsRawFd, FromRawFd};

use crate::sys::solid::{
    abi,
    net::{new_ip_socket, socket_addr},
};

pub fn bind(addr: SocketAddr) -> io::Result<net::UdpSocket> {
    // Gives a warning for non Apple platforms.
    #[allow(clippy::let_and_return)]
    let socket = new_ip_socket(addr, abi::SOCK_DGRAM);

    socket.and_then(|socket| {
        let (raw_addr, raw_addr_length) = socket_addr(&addr);
        syscall!(bind(socket, raw_addr.as_ptr(), raw_addr_length))
            .map_err(|err| {
                // Close the socket if we hit an error, ignoring the error
                // from closing since we can't pass back two errors.
                let _ = unsafe { abi::close(socket) };
                err
            })
            .map(|_| unsafe { net::UdpSocket::from_raw_fd(socket) })
    })
}

pub(crate) fn only_v6(socket: &net::UdpSocket) -> io::Result<bool> {
    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;

    syscall!(getsockopt(
        socket.as_raw_fd(),
        abi::IPPROTO_IPV6,
        abi::IPV6_V6ONLY,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(optval != 0)
}
