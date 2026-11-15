//! Linux-only socket batching and optional datagram-offload primitives.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::ptr;

use crate::transport::WireBuf;

const CONTROL_WORDS: usize = 16;
const IPV6_RECVTCLASS: libc::c_int = 66;
const IPV6_RECVPKTINFO: libc::c_int = 49;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CapabilityProbe {
    pub(crate) gso: bool,
    pub(crate) gro: bool,
    pub(crate) ecn: bool,
    pub(crate) pktinfo: bool,
    pub(crate) txtime: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReceivedInfo {
    pub(crate) len: usize,
    pub(crate) ecn: Option<u8>,
    pub(crate) gso_size: Option<usize>,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) interface_index: Option<u32>,
}

pub(crate) fn probe(fd: RawFd, ipv4: bool) -> CapabilityProbe {
    let gso = set_int_option(fd, libc::IPPROTO_UDP, libc::UDP_SEGMENT, 0).is_ok();
    let gro = set_int_option(fd, libc::IPPROTO_UDP, libc::UDP_GRO, 0).is_ok();
    let ecn = if ipv4 {
        set_int_option(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, 1).is_ok()
    } else {
        set_int_option(fd, libc::IPPROTO_IPV6, IPV6_RECVTCLASS, 1).is_ok()
    };
    let pktinfo = if ipv4 {
        set_int_option(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1).is_ok()
    } else {
        set_int_option(fd, libc::IPPROTO_IPV6, IPV6_RECVPKTINFO, 1).is_ok()
    };
    CapabilityProbe {
        gso,
        gro,
        ecn,
        pktinfo,
        txtime: probe_txtime(ipv4),
    }
}

pub(crate) fn set_gro(fd: RawFd, enabled: bool) -> io::Result<()> {
    set_int_option(fd, libc::IPPROTO_UDP, libc::UDP_GRO, i32::from(enabled))
}

pub(crate) fn enable_txtime(fd: RawFd) -> io::Result<()> {
    let config = libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };
    // SAFETY: `config` has the structure type required by `SO_TXTIME`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TXTIME,
            (&config as *const libc::sock_txtime).cast(),
            mem::size_of_val(&config) as libc::socklen_t,
        )
    };
    cvt_zero(result)
}

pub(crate) fn recv_one(fd: RawFd, buffer: &mut WireBuf) -> io::Result<ReceivedInfo> {
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_slice().as_mut_ptr().cast(),
        iov_len: buffer.as_slice().len(),
    };
    let mut control = [0_usize; CONTROL_WORDS];
    // SAFETY: `msghdr` is an all-zero-valid C structure, and all pointers stay
    // valid for the duration of the nonblocking `recvmsg`.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control);
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    let received = cvt_size(received)?;
    buffer.set_len(received);
    let mut info = parse_control(&message);
    info.len = received;
    Ok(info)
}

pub(crate) fn send_gso(fd: RawFd, datagrams: &[&[u8]]) -> io::Result<usize> {
    let Some((&first, rest)) = datagrams.split_first() else {
        return Ok(0);
    };
    let segment = first.len();
    if segment == 0
        || segment > u16::MAX as usize
        || rest.iter().any(|datagram| datagram.len() > segment)
        || rest
            .iter()
            .rev()
            .skip(1)
            .any(|datagram| datagram.len() != segment)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GSO datagrams require equal non-final segment sizes",
        ));
    }

    let iovecs: Vec<_> = datagrams
        .iter()
        .map(|datagram| libc::iovec {
            iov_base: datagram.as_ptr().cast_mut().cast(),
            iov_len: datagram.len(),
        })
        .collect();
    let total: usize = datagrams.iter().map(|datagram| datagram.len()).sum();
    let mut control = [0_usize; CONTROL_WORDS];
    // SAFETY: `msghdr` is all-zero-valid. The iovecs and control storage remain
    // live and fixed through `sendmsg`.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = iovecs.as_ptr().cast_mut();
    message.msg_iovlen = iovecs.len();
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(2) as usize };
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(io::Error::other("GSO control message did not fit"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(2) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), segment as u16);
    }
    let sent = unsafe { libc::sendmsg(fd, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    let sent = cvt_size(sent)?;
    if sent == total {
        Ok(datagrams.len())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("GSO send transmitted {sent} of {total} bytes"),
        ))
    }
}

pub(crate) fn send_txtime(fd: RawFd, bytes: &[u8], release_ns: u64) -> io::Result<()> {
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0_usize; CONTROL_WORDS];
    // SAFETY: `msghdr` is all-zero-valid. The iovec, control storage, and byte
    // slice stay live for the duration of `sendmsg`.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(8) as usize };
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err(io::Error::other("txtime control message did not fit"));
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_TXTIME;
        (*cmsg).cmsg_len = libc::CMSG_LEN(8) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u64>(), release_ns);
    }
    let sent = unsafe { libc::sendmsg(fd, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    let sent = cvt_size(sent)?;
    if sent == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("txtime send transmitted {sent} of {} bytes", bytes.len()),
        ))
    }
}

pub(crate) fn sendmmsg(fd: RawFd, datagrams: &[&[u8]]) -> io::Result<usize> {
    let mut iovecs = Vec::with_capacity(datagrams.len());
    for datagram in datagrams {
        iovecs.push(libc::iovec {
            iov_base: datagram.as_ptr().cast_mut().cast(),
            iov_len: datagram.len(),
        });
    }

    // SAFETY: `mmsghdr` is an all-zero-valid C array. Each `msg_iov` points at
    // a distinct initialized element of `iovecs`, which stays fixed for the
    // duration of `sendmmsg`.
    let mut messages: Vec<libc::mmsghdr> = (0..iovecs.len())
        .map(|_| unsafe { mem::zeroed() })
        .collect();
    for (message, iovec) in messages.iter_mut().zip(&mut iovecs) {
        message.msg_hdr.msg_iov = iovec;
        message.msg_hdr.msg_iovlen = 1;
    }

    // SAFETY: the descriptor and vector lengths are valid, and the kernel only
    // reads the iovec storage supplied above.
    let sent = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    cvt_count(sent)
}

pub(crate) fn recvmmsg(
    fd: RawFd,
    buffers: &mut [WireBuf],
    infos: &mut [ReceivedInfo],
) -> io::Result<usize> {
    assert_eq!(buffers.len(), infos.len());
    let mut iovecs = Vec::with_capacity(buffers.len());
    for buffer in buffers.iter_mut() {
        iovecs.push(libc::iovec {
            iov_base: buffer.as_mut_slice().as_mut_ptr().cast(),
            iov_len: buffer.as_slice().len(),
        });
    }

    // SAFETY: `mmsghdr` is an all-zero-valid C array. The initialized iovec
    // pointers remain live until `recvmmsg` returns.
    let mut messages: Vec<libc::mmsghdr> = (0..iovecs.len())
        .map(|_| unsafe { mem::zeroed() })
        .collect();
    let mut controls = vec![[0_usize; CONTROL_WORDS]; messages.len()];
    for ((message, iovec), control) in messages
        .iter_mut()
        .zip(&mut iovecs)
        .zip(controls.iter_mut())
    {
        message.msg_hdr.msg_iov = iovec;
        message.msg_hdr.msg_iovlen = 1;
        message.msg_hdr.msg_name = ptr::null_mut();
        message.msg_hdr.msg_namelen = 0;
        message.msg_hdr.msg_control = control.as_mut_ptr().cast();
        message.msg_hdr.msg_controllen = mem::size_of_val(control);
    }

    // SAFETY: the descriptor, message vector, and mutable receive buffers are
    // valid for the duration of the nonblocking call.
    let received = unsafe {
        libc::recvmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
        )
    };
    let received = cvt_count(received)?;
    for ((buffer, message), info) in buffers.iter_mut().zip(&messages).zip(infos).take(received) {
        buffer.set_len(message.msg_len as usize);
        *info = parse_control(&message.msg_hdr);
        info.len = message.msg_len as usize;
    }
    Ok(received)
}

fn parse_control(message: &libc::msghdr) -> ReceivedInfo {
    let mut info = ReceivedInfo::default();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let kind = unsafe { (*cmsg).cmsg_type };
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        match (level, kind) {
            (libc::IPPROTO_IP, libc::IP_TOS) => {
                info.ecn = Some(unsafe { ptr::read_unaligned(data.cast::<u8>()) } & 0x03);
            }
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => {
                info.ecn =
                    Some(unsafe { ptr::read_unaligned(data.cast::<libc::c_int>()) } as u8 & 0x03);
            }
            (libc::IPPROTO_UDP, libc::UDP_GRO) => {
                info.gso_size = Some(unsafe { ptr::read_unaligned(data.cast::<u16>()) } as usize);
            }
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let pktinfo = unsafe { ptr::read_unaligned(data.cast::<libc::in_pktinfo>()) };
                info.destination = Some(IpAddr::V4(Ipv4Addr::from(
                    pktinfo.ipi_addr.s_addr.to_ne_bytes(),
                )));
                info.interface_index = u32::try_from(pktinfo.ipi_ifindex).ok();
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let pktinfo = unsafe { ptr::read_unaligned(data.cast::<libc::in6_pktinfo>()) };
                info.destination = Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
                info.interface_index = Some(pktinfo.ipi6_ifindex);
            }
            _ => {}
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(message, cmsg) };
    }
    info
}

fn set_int_option(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `value` points to a correctly sized integer for these options.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    cvt_zero(result)
}

fn probe_txtime(ipv4: bool) -> bool {
    let family = if ipv4 { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: `socket` creates a temporary descriptor owned and closed here.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    let result = enable_txtime(fd);
    // SAFETY: `fd` was created above and is closed exactly once.
    unsafe {
        libc::close(fd);
    }
    result.is_ok()
}

fn cvt_zero(value: libc::c_int) -> io::Result<()> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cvt_count(value: libc::c_int) -> io::Result<usize> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value as usize)
    }
}

fn cvt_size(value: libc::ssize_t) -> io::Result<usize> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value as usize)
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use super::*;

    #[test]
    fn gso_preserves_udp_datagram_boundaries() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        if !probe(sender.as_raw_fd(), true).gso {
            return;
        }
        let datagrams: &[&[u8]] = &[b"one!", b"two!", b"end"];
        let sent = match send_gso(sender.as_raw_fd(), datagrams) {
            Ok(sent) => sent,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS)
                        | Some(libc::EINVAL)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::EPROTONOSUPPORT)
                ) =>
            {
                return;
            }
            Err(error) => panic!("GSO send failed: {error}"),
        };
        assert_eq!(sent, datagrams.len());

        let mut observed = Vec::new();
        let mut buffer = [0_u8; 16];
        for _ in 0..datagrams.len() {
            let (len, _) = receiver.recv_from(&mut buffer).unwrap();
            observed.push(buffer[..len].to_vec());
        }
        assert_eq!(observed, datagrams);
    }

    #[test]
    fn ecn_metadata_reports_the_received_codepoint() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let capabilities = probe(receiver.as_raw_fd(), true);
        if !capabilities.ecn {
            return;
        }
        set_int_option(sender.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TOS, 0x01)
            .expect("set ECN-capable traffic class");
        sender
            .send_to(b"ecn", receiver.local_addr().unwrap())
            .unwrap();
        let mut buffer = WireBuf::from_vec(vec![0; 16]);
        let info = recv_one(receiver.as_raw_fd(), &mut buffer).unwrap();
        assert_eq!(info.ecn, Some(1));
        if capabilities.pktinfo {
            assert_eq!(info.destination, Some(receiver.local_addr().unwrap().ip()));
            assert!(info.interface_index.is_some());
        }
        assert_eq!(buffer.as_slice(), b"ecn");
    }
}
