use std::convert::TryInto;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::net::{self, SocketAddr};
use std::os::solid::io::{AsRawFd, FromRawFd};

use crate::sys::solid::{
    abi,
    net::{new_socket, socket_addr, to_socket_addr},
};

pub(crate) fn new_for_addr(address: SocketAddr) -> io::Result<libc::c_int> {
    let domain = match address {
        SocketAddr::V4(_) => abi::AF_INET,
        SocketAddr::V6(_) => abi::AF_INET6,
    };
    new_socket(domain, abi::SOCK_STREAM)
}

pub(crate) fn bind(socket: &net::TcpListener, addr: SocketAddr) -> io::Result<()> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);
    syscall!(bind(socket.as_raw_fd(), raw_addr.as_ptr(), raw_addr_length))?;
    Ok(())
}

pub(crate) fn connect(socket: &net::TcpStream, addr: SocketAddr) -> io::Result<()> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);

    match syscall!(connect(
        socket.as_raw_fd(),
        raw_addr.as_ptr(),
        raw_addr_length
    )) {
        Err(err) if err.raw_os_error() != Some(abi::EINPROGRESS) => Err(err),
        _ => Ok(()),
    }
}

pub(crate) fn listen(socket: &net::TcpListener, backlog: u32) -> io::Result<()> {
    let backlog = backlog.try_into().unwrap_or(i32::max_value());
    syscall!(listen(socket.as_raw_fd(), backlog))?;
    Ok(())
}

pub(crate) fn set_reuseaddr(socket: &net::TcpListener, reuseaddr: bool) -> io::Result<()> {
    let val: abi::c_int = if reuseaddr { 1 } else { 0 };
    syscall!(setsockopt(
        socket.as_raw_fd(),
        abi::SOL_SOCKET,
        abi::SO_REUSEADDR,
        &val as *const abi::c_int as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t,
    ))?;
    Ok(())
}

pub(crate) fn accept(listener: &net::TcpListener) -> io::Result<(net::TcpStream, SocketAddr)> {
    let mut addr: MaybeUninit<abi::sockaddr_storage> = MaybeUninit::uninit();
    let mut length = size_of::<abi::sockaddr_storage>() as abi::socklen_t;

    let stream = {
        syscall!(accept(
            listener.as_raw_fd(),
            addr.as_mut_ptr() as *mut _,
            &mut length
        ))
        .map(|socket| unsafe { net::TcpStream::from_raw_fd(socket) })
        .and_then(|s| {
            syscall!(ioctl(s.as_raw_fd(), abi::FIONBIO, (&1u32) as *const _ as _))?;

            Ok(s)
        })
    }?;

    // This is safe because `accept` calls above ensures the address
    // initialised.
    unsafe { to_socket_addr(addr.as_ptr()) }.map(|addr| (stream, addr))
}
