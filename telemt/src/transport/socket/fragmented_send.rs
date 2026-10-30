use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

struct TcpMaxSegmentGuard {
    fd: RawFd,
    original: libc::c_int,
    changed: bool,
}

fn tcp_max_segment(fd: RawFd) -> Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(value)
}

fn set_tcp_max_segment(fd: RawFd, value: libc::c_int) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

impl TcpMaxSegmentGuard {
    fn install(fd: RawFd, requested: usize) -> Result<Self> {
        let requested = libc::c_int::try_from(requested).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "TCP fragment size exceeds the platform integer range",
            )
        })?;
        let original = tcp_max_segment(fd)?;
        let changed = requested < original;
        if changed {
            set_tcp_max_segment(fd, requested)?;
        }
        Ok(Self {
            fd,
            original,
            changed,
        })
    }

    fn restore(mut self) -> Result<()> {
        if self.changed {
            set_tcp_max_segment(self.fd, self.original)?;
            self.changed = false;
        }
        Ok(())
    }
}

impl Drop for TcpMaxSegmentGuard {
    fn drop(&mut self) {
        if self.changed {
            let _ = set_tcp_max_segment(self.fd, self.original);
        }
    }
}

fn force_tcp_push(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Sends an initial TCP response using best-effort userspace write chunking.
///
/// `fd` must refer to a connected, nonblocking TCP socket and remain valid for
/// the duration of this call. The caller retains ownership of the original fd.
/// The accepted socket is clamped to the requested `TCP_MAXSEG` for this send
/// and restored on success, error, or task cancellation. `MSG_EOR` remains only
/// a best-effort Linux hint: offloads may still coalesce capture boundaries.
pub(crate) async fn send_tcp_fragmented_fd(
    fd: RawFd,
    data: &[u8],
    fragment_size: usize,
) -> Result<()> {
    if fragment_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "TCP fragment size must be greater than zero",
        ));
    }
    if data.is_empty() {
        return Ok(());
    }
    if fd < 0 {
        return Err(Error::from_raw_os_error(libc::EBADF));
    }

    // SAFETY: the caller guarantees that fd remains open for this call.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let duplicated_fd = borrowed_fd.try_clone_to_owned()?;
    let async_fd = AsyncFd::with_interest(duplicated_fd, Interest::WRITABLE)?;
    let mss_guard = TcpMaxSegmentGuard::install(async_fd.get_ref().as_raw_fd(), fragment_size)?;

    let send_result = async {
        for fragment in data.chunks(fragment_size) {
            let mut offset = 0;
            while offset < fragment.len() {
                let mut writable = async_fd.writable().await?;
                let sent = match writable.try_io(|inner| {
                    let remaining = &fragment[offset..];
                    let sent = unsafe {
                        libc::send(
                            inner.get_ref().as_raw_fd(),
                            remaining.as_ptr().cast::<libc::c_void>(),
                            remaining.len(),
                            libc::MSG_DONTWAIT | libc::MSG_EOR | libc::MSG_NOSIGNAL,
                        )
                    };
                    if sent < 0 {
                        Err(Error::last_os_error())
                    } else if sent == 0 {
                        Err(Error::new(
                            ErrorKind::WriteZero,
                            "fragmented TCP send returned zero",
                        ))
                    } else {
                        Ok(sent as usize)
                    }
                }) {
                    Ok(Ok(sent)) => sent,
                    Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                };

                offset += sent;
                force_tcp_push(async_fd.get_ref().as_raw_fd())?;
            }
        }
        Ok(())
    }
    .await;

    let restore_result = mss_guard.restore();
    send_result.and(restore_result)
}

#[cfg(test)]
#[path = "fragmented_send_wire_tests.rs"]
mod wire_tests;
