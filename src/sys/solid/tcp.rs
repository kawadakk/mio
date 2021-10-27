use std::convert::TryInto;
use std::io;
use std::mem;
use std::mem::{size_of, MaybeUninit};
use std::net::{self, SocketAddr};
use std::os::solid::io::{AsRawFd, FromRawFd};
use std::time::Duration;

use crate::net::TcpKeepalive;
use crate::sys::solid::{
    abi,
    net::{new_socket, socket_addr, to_socket_addr},
};

use abi::SO_KEEPALIVE as KEEPALIVE_TIME;
pub type TcpSocket = abi::c_int;

pub(crate) fn new_v4_socket() -> io::Result<TcpSocket> {
    new_socket(abi::AF_INET, abi::SOCK_STREAM)
}

pub(crate) fn new_v6_socket() -> io::Result<TcpSocket> {
    new_socket(abi::AF_INET6, abi::SOCK_STREAM)
}

pub(crate) fn bind(socket: TcpSocket, addr: SocketAddr) -> io::Result<()> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);
    syscall!(bind(socket, raw_addr.as_ptr(), raw_addr_length))?;
    Ok(())
}

pub(crate) fn connect(socket: TcpSocket, addr: SocketAddr) -> io::Result<net::TcpStream> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);

    match syscall!(connect(socket, raw_addr.as_ptr(), raw_addr_length)) {
        Err(err) if err.raw_os_error() != Some(abi::EINPROGRESS) => Err(err),
        _ => Ok(unsafe { net::TcpStream::from_raw_fd(socket) }),
    }
}

pub(crate) fn listen(socket: TcpSocket, backlog: u32) -> io::Result<net::TcpListener> {
    let backlog = backlog.try_into().unwrap_or(i32::max_value());
    syscall!(listen(socket, backlog))?;
    Ok(unsafe { net::TcpListener::from_raw_fd(socket) })
}

pub(crate) fn close(socket: TcpSocket) {
    let _ = unsafe { net::TcpStream::from_raw_fd(socket) };
}

pub(crate) fn set_reuseaddr(socket: TcpSocket, reuseaddr: bool) -> io::Result<()> {
    let val: abi::c_int = if reuseaddr { 1 } else { 0 };
    syscall!(setsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_REUSEADDR,
        &val as *const abi::c_int as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) fn get_reuseaddr(socket: TcpSocket) -> io::Result<bool> {
    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;

    syscall!(getsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_REUSEADDR,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(optval != 0)
}

pub(crate) fn get_localaddr(socket: TcpSocket) -> io::Result<SocketAddr> {
    let mut addr: abi::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = size_of::<abi::sockaddr_storage>() as abi::socklen_t;

    syscall!(getsockname(
        socket,
        &mut addr as *mut _ as *mut _,
        &mut length
    ))?;

    unsafe { to_socket_addr(&addr) }
}

pub(crate) fn set_linger(socket: TcpSocket, dur: Option<Duration>) -> io::Result<()> {
    let val: abi::linger = abi::linger {
        l_onoff: if dur.is_some() { 1 } else { 0 },
        l_linger: dur
            .map(|dur| dur.as_secs() as abi::c_int)
            .unwrap_or_default(),
    };
    syscall!(setsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_LINGER,
        &val as *const abi::linger as *const abi::c_void,
        size_of::<abi::linger>() as abi::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) fn get_linger(socket: TcpSocket) -> io::Result<Option<Duration>> {
    let mut val: abi::linger = unsafe { std::mem::zeroed() };
    let mut len = mem::size_of::<abi::linger>() as abi::socklen_t;

    syscall!(getsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_LINGER,
        &mut val as *mut _ as *mut _,
        &mut len,
    ))?;

    if val.l_onoff == 0 {
        Ok(None)
    } else {
        Ok(Some(Duration::from_secs(val.l_linger as u64)))
    }
}

pub(crate) fn set_recv_buffer_size(socket: TcpSocket, size: u32) -> io::Result<()> {
    let size = size.try_into().ok().unwrap_or_else(i32::max_value);
    syscall!(setsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_RCVBUF,
        &size as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_recv_buffer_size(socket: TcpSocket) -> io::Result<u32> {
    let mut optval: abi::c_int = 0;
    let mut optlen = size_of::<abi::c_int>() as abi::socklen_t;
    syscall!(getsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_RCVBUF,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(optval as u32)
}

pub(crate) fn set_send_buffer_size(socket: TcpSocket, size: u32) -> io::Result<()> {
    let size = size.try_into().ok().unwrap_or_else(i32::max_value);
    syscall!(setsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_SNDBUF,
        &size as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_send_buffer_size(socket: TcpSocket) -> io::Result<u32> {
    let mut optval: abi::c_int = 0;
    let mut optlen = size_of::<abi::c_int>() as abi::socklen_t;

    syscall!(getsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_SNDBUF,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(optval as u32)
}

pub(crate) fn set_keepalive(socket: TcpSocket, keepalive: bool) -> io::Result<()> {
    let val: abi::c_int = if keepalive { 1 } else { 0 };
    syscall!(setsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_KEEPALIVE,
        &val as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_keepalive(socket: TcpSocket) -> io::Result<bool> {
    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;

    syscall!(getsockopt(
        socket,
        abi::SOL_SOCKET,
        abi::SO_KEEPALIVE,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(optval != 0)
}

pub(crate) fn set_keepalive_params(socket: TcpSocket, keepalive: TcpKeepalive) -> io::Result<()> {
    if let Some(dur) = keepalive.time {
        set_keepalive_time(socket, dur)?;
    }

    if let Some(dur) = keepalive.interval {
        set_keepalive_interval(socket, dur)?;
    }

    if let Some(retries) = keepalive.retries {
        set_keepalive_retries(socket, retries)?;
    }

    Ok(())
}

fn set_keepalive_time(socket: TcpSocket, time: Duration) -> io::Result<()> {
    let time_secs = time
        .as_secs()
        .try_into()
        .ok()
        .unwrap_or_else(i32::max_value);
    syscall!(setsockopt(
        socket,
        abi::IPPROTO_TCP,
        KEEPALIVE_TIME,
        &(time_secs as abi::c_int) as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_keepalive_time(socket: TcpSocket) -> io::Result<Option<Duration>> {
    if !get_keepalive(socket)? {
        return Ok(None);
    }

    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;
    syscall!(getsockopt(
        socket,
        abi::IPPROTO_TCP,
        KEEPALIVE_TIME,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(Some(Duration::from_secs(optval as u64)))
}

fn set_keepalive_interval(socket: TcpSocket, interval: Duration) -> io::Result<()> {
    let interval_secs = interval
        .as_secs()
        .try_into()
        .ok()
        .unwrap_or_else(i32::max_value);
    syscall!(setsockopt(
        socket,
        abi::IPPROTO_TCP,
        abi::TCP_KEEPINTVL,
        &(interval_secs as abi::c_int) as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_keepalive_interval(socket: TcpSocket) -> io::Result<Option<Duration>> {
    if !get_keepalive(socket)? {
        return Ok(None);
    }

    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;
    syscall!(getsockopt(
        socket,
        abi::IPPROTO_TCP,
        abi::TCP_KEEPINTVL,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(Some(Duration::from_secs(optval as u64)))
}

fn set_keepalive_retries(socket: TcpSocket, retries: u32) -> io::Result<()> {
    let retries = retries.try_into().ok().unwrap_or_else(i32::max_value);
    syscall!(setsockopt(
        socket,
        abi::IPPROTO_TCP,
        abi::TCP_KEEPCNT,
        &(retries as abi::c_int) as *const _ as *const abi::c_void,
        size_of::<abi::c_int>() as abi::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn get_keepalive_retries(socket: TcpSocket) -> io::Result<Option<u32>> {
    if !get_keepalive(socket)? {
        return Ok(None);
    }

    let mut optval: abi::c_int = 0;
    let mut optlen = mem::size_of::<abi::c_int>() as abi::socklen_t;
    syscall!(getsockopt(
        socket,
        abi::IPPROTO_TCP,
        abi::TCP_KEEPCNT,
        &mut optval as *mut _ as *mut _,
        &mut optlen,
    ))?;

    Ok(Some(optval as u32))
}

pub fn accept(listener: &net::TcpListener) -> io::Result<(net::TcpStream, SocketAddr)> {
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
