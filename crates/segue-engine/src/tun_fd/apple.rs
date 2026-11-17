//! The private Darwin socket API the utun read path batches with.
//!
//! `recvmsg_x` and `struct msghdr_x` live in xnu's `bsd/sys/socket.h` but are
//! not part of the public SDK headers, so they are declared here by hand, the
//! way sing-tun does in `internal/rawfile_darwin/rawfile.go`. The symbol is
//! exported by `libSystem` on both macOS and iOS (`_recvmsg_x` in
//! `libSystem.tbd`). The layout below follows xnu's declaration: 56 bytes on
//! 64-bit, with `msg_datalen` a `size_t` at offset 48 (asserted below).
//!
//! Only the read direction is declared. `sendmsg_x` is deliberately absent:
//! write batching is a separate change.

use libc::{c_int, c_uint, c_void, iovec, size_t, ssize_t, socklen_t};

/// `MSG_DONTWAIT` from `bsd/sys/socket.h` (0x80 on Darwin). Declared here
/// rather than taken from `libc` so the value the syscall sees is the one this
/// module documents.
pub(super) const MSG_DONTWAIT: c_int = 0x80;

/// `MSG_TRUNC` from `bsd/sys/socket.h` (0x10 on Darwin): the datagram was
/// longer than the slot it was read into and the tail was discarded.
pub(super) const MSG_TRUNC: c_int = 0x10;

/// `struct msghdr_x` from xnu `bsd/sys/socket.h`.
///
/// The fields this code never reads are still part of the ABI: the kernel
/// inspects them, and older kernels reject a slot whose unused fields are not
/// zero, so they are kept and cleared rather than omitted.
#[repr(C)]
#[allow(dead_code)]
pub(super) struct MsgHdrX {
    pub(super) msg_name: *mut c_void,
    pub(super) msg_namelen: socklen_t,
    pub(super) msg_iov: *mut iovec,
    pub(super) msg_iovlen: c_int,
    pub(super) msg_control: *mut c_void,
    pub(super) msg_controllen: socklen_t,
    pub(super) msg_flags: c_int,
    pub(super) msg_datalen: size_t,
}

// SAFETY: the raw pointers in a header only ever point into the reader's own
// arena and iovec array, which move with the reader and are never shared with
// another thread. Sending the reader to another thread therefore sends the
// pointers with their targets, and no other thread can observe them.
unsafe impl Send for MsgHdrX {}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<MsgHdrX>() == 56);
    assert!(std::mem::offset_of!(MsgHdrX, msg_datalen) == 48);
};

impl MsgHdrX {
    /// An all-zero header, which is what the kernel expects for a slot that
    /// carries no name and no control data. The whole struct is cleared, not
    /// just the fields this code sets: older kernels check that the rest is
    /// empty (xnu `uipc_syscalls.c`, `recvit_x`).
    pub(super) fn zeroed() -> Self {
        // SAFETY: every field is a raw pointer or an integer, and the all-zero
        // bit pattern is valid for both, so a zeroed image is a valid value
        // (a null pointer and a length of zero is exactly the "no name, no
        // control data" header).
        unsafe { std::mem::zeroed() }
    }
}

extern "C" {
    /// `ssize_t recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags)`.
    ///
    /// Receives up to `cnt` datagrams, one per header slot, and returns how
    /// many slots it filled. It walks every submitted slot whether or not a
    /// packet is pending for it, so `cnt` must be the batch size, not the
    /// number of packets believed to be queued.
    pub(super) fn recvmsg_x(
        fd: c_int,
        msgp: *mut MsgHdrX,
        cnt: c_uint,
        flags: c_int,
    ) -> ssize_t;
}
