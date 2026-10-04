//! Live capture via Linux `AF_PACKET` raw sockets — the only `unsafe` code in the
//! workspace, and only compiled for `cfg(all(target_os = "linux", feature =
//! "live-capture"))`.
//!
//! Design note: this uses a plain `recv` loop with `SO_RCVTIMEO` (so the stop
//! flag is polled every second) rather than a `TPACKET_V3` mmap ring. It is
//! correct and privileges-light, but for sustained >1 Gbit/s line-rate the ring
//! path (or `pnet`/`pcap`) should be swapped in behind this same interface. Every
//! `unsafe` block below has a `// SAFETY:` justification.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::SystemTime;

use ingressd_core::metrics::Counters;
use ingressd_core::scope::HostAddrs;

use crate::{frame_to_event, EventTx, HostHandle, QueuePolicy};

/// Errors starting a live capture.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// socket() failed.
    #[error("socket: {0}")]
    Socket(std::io::Error),
    /// bind() failed.
    #[error("bind: {0}")]
    Bind(std::io::Error),
    /// setsockopt() failed.
    #[error("setsockopt: {0}")]
    SetSockOpt(std::io::Error),
    /// Named interface does not exist.
    #[error("interface '{0}' not found")]
    NoSuchInterface(String),
    /// Could not determine a default interface.
    #[error("no default interface found (specify --iface)")]
    NoDefaultInterface,
}

/// Start a live capture thread for `iface` (empty => auto-detect default route).
pub fn spawn(
    iface: &str,
    host: HostHandle,
    tx: EventTx,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    policy: QueuePolicy,
) -> Result<JoinHandle<()>, CaptureError> {
    let iface = iface.to_string();
    let fd = open_socket(&iface)?;
    std::thread::Builder::new()
        .name("ingressd-capture".to_string())
        .spawn(move || run(fd, &host, &tx, &counters, &stop, policy))
        .map_err(CaptureError::Socket)
}

fn open_socket(iface: &str) -> Result<c_int, CaptureError> {
    let name = if iface.is_empty() { default_iface()? } else { iface.to_string() };
    let cstr = CString::new(name.clone()).map_err(|_| CaptureError::NoSuchInterface(name.clone()))?;

    // SAFETY: socket() with constant, valid domain/type/protocol arguments; a
    // negative return is checked before the fd is used.
    let proto: c_int = (libc::ETH_P_ALL as u16).to_be() as c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(CaptureError::Socket(std::io::Error::last_os_error()));
    }

    // SAFETY: cstr is a valid NUL-terminated C string; 0 return means failure.
    let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if index == 0 {
        // SAFETY: fd is a valid socket we just opened; closing on the error path.
        unsafe { libc::close(fd) };
        return Err(CaptureError::NoSuchInterface(name));
    }

    let mut sll: libc::sockaddr_ll = unsafe {
        // SAFETY: an all-zero sockaddr_ll is a valid starting state; every field
        // we rely on (family, protocol, ifindex, halen) is set next.
        std::mem::zeroed()
    };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = index as c_int;
    sll.sll_halen = 0;

    // SAFETY: `sll` is a fully initialized sockaddr_ll and we pass its true size;
    // the cast to *const sockaddr is the standard socket API idiom.
    let rc = unsafe {
        libc::bind(
            fd,
            (&sll as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: valid fd.
        unsafe { libc::close(fd) };
        return Err(CaptureError::Bind(e));
    }

    // A 1s receive timeout lets the loop poll the stop flag between recvs.
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval of the correct size for SO_RCVTIMEO.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast::<std::os::raw::c_void>(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: valid fd.
        unsafe { libc::close(fd) };
        return Err(CaptureError::SetSockOpt(e));
    }

    Ok(fd)
}

fn run(fd: c_int, host: &HostHandle, tx: &EventTx, counters: &Counters, stop: &AtomicBool, policy: QueuePolicy) {
    let mut buf = vec![0u8; 65535];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // SAFETY: `buf` is a writable region of `buf.len()` bytes and `fd` is our
        // bound socket; the return is validated before `buf` is read.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast::<std::os::raw::c_void>(), buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                // Timeouts and interrupts are expected; just re-check the stop flag.
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => {
                    tracing::warn!("recv failed, stopping capture: {e}");
                    break;
                }
            }
        }
        let n = n as usize;
        counters.inc_packets(1);
        counters.add_bytes(n as u64);
        if let Some(ev) = frame_to_event(&buf[..n], SystemTime::now(), host, counters) {
            match policy {
                QueuePolicy::Drop => {
                    // Never block the kernel ring: drop under pressure and count it.
                    if tx.try_send(ev).is_err() {
                        counters.inc_drops(1);
                    }
                }
                QueuePolicy::Stall => {
                    if tx.blocking_send(ev).is_err() {
                        break;
                    }
                }
                QueuePolicy::Exit => {
                    if tx.try_send(ev).is_err() {
                        tracing::error!("capture channel full (fail-closed); stopping capture");
                        counters.inc_drops(1);
                        break;
                    }
                }
            }
        }
    }
    // SAFETY: closing our own socket fd exactly once at thread exit.
    unsafe { libc::close(fd) };
}

/// First interface with a default route (`00000000`) from `/proc/net/route`.
fn default_iface() -> Result<String, CaptureError> {
    let data = std::fs::read_to_string("/proc/net/route").map_err(|_| CaptureError::NoDefaultInterface)?;
    for line in data.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2 && f[1] == "00000000" {
            return Ok(f[0].to_string());
        }
    }
    Err(CaptureError::NoDefaultInterface)
}

/// All IPv4/IPv6 addresses currently assigned to this host's interfaces.
///
/// Used to seed [`HostAddrs`] for direction derivation; refreshed periodically by
/// the caller.
pub fn host_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a linked list we free below; only reads a valid
    // out-pointer.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node of the list returned by getifaddrs.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() {
            // SAFETY: family is a field of a valid sockaddr.
            let family = unsafe { (*node.ifa_addr).sa_family } as c_int;
            if family == libc::AF_INET {
                // SAFETY: for AF_INET, ifa_addr points to a sockaddr_in.
                let sa = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                // s_addr bytes are in network order; to_ne_bytes reproduces that
                // exact byte sequence regardless of host endianness.
                out.push(IpAddr::V4(Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes())));
            } else if family == libc::AF_INET6 {
                // SAFETY: for AF_INET6, ifa_addr points to a sockaddr_in6.
                let sa = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in6) };
                out.push(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
            }
        }
        // SAFETY: ifa_next is the list link.
        cur = unsafe { node.ifa_next };
    }
    // SAFETY: ifap was allocated by getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// Convenience: build a [`HostAddrs`] from the live interfaces.
pub fn live_host_addrs() -> HostAddrs {
    let mut h = HostAddrs::new();
    h.set(host_addresses());
    h
}
