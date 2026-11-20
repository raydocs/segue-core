use libc::c_int;

#[cfg(all(unix, target_vendor = "apple"))]
mod apple;

const MAX_IP_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunFdPacketFormat {
    RawIp,
    DarwinUtun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunFdClosePolicy {
    Borrowed,
    Owned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunFdConfig {
    fd: c_int,
    packet_format: TunFdPacketFormat,
    close_policy: TunFdClosePolicy,
}

impl TunFdConfig {
    pub fn new(
        fd: c_int,
        packet_format: TunFdPacketFormat,
        close_policy: TunFdClosePolicy,
    ) -> Self {
        Self {
            fd,
            packet_format,
            close_policy,
        }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    pub fn packet_format(&self) -> TunFdPacketFormat {
        self.packet_format
    }

    pub fn close_policy(&self) -> TunFdClosePolicy {
        self.close_policy
    }

    pub fn close_if_owned(&self) {
        if self.close_policy == TunFdClosePolicy::Owned && self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use segue_tun::{TunEndpoint, TunError};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;

    #[cfg(target_vendor = "apple")]
    use super::apple;
    use super::{TunFdConfig, MAX_IP_PACKET_SIZE};
    use crate::TunFdPacketFormat;

    const DARWIN_UTUN_HEADER_LEN: usize = 4;
    const TUN_FD_WRITE_BATCH_MAX_PACKETS: usize = 128;
    /// Smallest read arena. One allocation serves roughly 40 MTU-sized
    /// packets, and never exceeds the single maximum-size packet buffer the
    /// per-packet path used to allocate, which bounds what one long-lived
    /// packet can pin. A larger MTU raises it to hold one whole read.
    const TUN_FD_READ_ARENA_MIN: usize = 64 * 1024;

    /// The smallest and largest number of packets one `recvmsg_x` call asks
    /// the kernel for. The size starts at the minimum and doubles when a batch
    /// comes back full, halves when it comes back under half full — sing-tun's
    /// `goReadBatch` adaptation (`stack_go_io_darwin.go`, profiles in
    /// `stack_go_profile_*.go`). The iOS profile caps a batch lower than the
    /// macOS one because the Network Extension budget does not allow
    /// macOS-sized bursts.
    #[cfg(any(target_vendor = "apple", test))]
    const TUN_FD_READ_BATCH_MIN: usize = 4;
    #[cfg(all(
        any(target_vendor = "apple", test),
        any(target_os = "ios", target_os = "tvos", target_os = "watchos")
    ))]
    const TUN_FD_READ_BATCH_MAX: usize = 32;
    #[cfg(all(
        any(target_vendor = "apple", test),
        not(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))
    ))]
    const TUN_FD_READ_BATCH_MAX: usize = 64;

    /// `SEGUE_TUN_BATCH=0` (or `false`, `off`, empty) turns Apple read
    /// batching off and leaves the single-packet `read(2)` path exactly as it
    /// is. It is read once per process, like Xray's `XRAY_*` flags.
    #[cfg(target_vendor = "apple")]
    const TUN_FD_BATCH_FLAG: &str = "SEGUE_TUN_BATCH";

    /// Whether a read of a Darwin utun descriptor may be batched. Off on every
    /// platform without `recvmsg_x`, for a raw-IP descriptor, and when the
    /// environment flag disables it.
    fn read_batching_enabled(packet_format: TunFdPacketFormat) -> bool {
        if packet_format != TunFdPacketFormat::DarwinUtun {
            return false;
        }
        #[cfg(target_vendor = "apple")]
        {
            static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            *ENABLED.get_or_init(|| {
                let value = std::env::var_os(TUN_FD_BATCH_FLAG);
                parse_batch_flag(value.as_deref())
            })
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            false
        }
    }

    /// The upper bound on one batch's arena. A batch of `batch_max` slots of
    /// `single_read` bytes each never exceeds it (see [`batch_max_for`]), so
    /// the memory one batch pins is stated: **at most 272 KiB**, reached when
    /// the slot count and the slot size trade off against each other. A
    /// 1500-byte MTU allocates only 64 × 1505 ≈ 94 KiB (32 slots, ≈47 KiB, on
    /// iOS). The arena stays pinned only until the stack has consumed the
    /// batch's packets, exactly as the single-packet arena does. The constant
    /// is above `TUN_FD_READ_BATCH_MIN × (MAX_IP_PACKET_SIZE + 5)`, so even a
    /// jumbo MTU keeps the starting batch size.
    #[cfg(any(target_vendor = "apple", test))]
    const TUN_FD_READ_BATCH_ARENA_MAX: usize = 272 * 1024;

    /// How many slots one batch may use, given the per-slot size: the
    /// platform cap, but never more than the arena budget allows, and never
    /// fewer than the starting size.
    #[cfg(any(target_vendor = "apple", test))]
    fn batch_max_for(single_read: usize) -> usize {
        (TUN_FD_READ_BATCH_ARENA_MAX / single_read.max(1))
            .clamp(TUN_FD_READ_BATCH_MIN, TUN_FD_READ_BATCH_MAX)
    }

    /// The next adaptive batch size, in the shape sing-tun uses: grow on a
    /// full batch, shrink below half a batch, hold in between. `max` is the
    /// caller's cap, itself bounded by what the arena can hold.
    #[cfg(any(target_vendor = "apple", test))]
    fn next_batch_size(requested: usize, received: usize, max: usize) -> usize {
        if received >= requested {
            requested
                .saturating_mul(2)
                .min(max)
                .max(TUN_FD_READ_BATCH_MIN)
        } else if received * 2 < requested {
            (requested / 2).max(TUN_FD_READ_BATCH_MIN).min(max)
        } else {
            requested.min(max)
        }
    }

    /// Whether an environment value turns read batching off: unset, `1`,
    /// `true`, `on` and anything else leave it on; empty, `0`, `false` and
    /// `off` turn it off.
    #[cfg(any(target_vendor = "apple", test))]
    fn parse_batch_flag(value: Option<&std::ffi::OsStr>) -> bool {
        match value {
            None => true,
            Some(value) => {
                !(value.is_empty() || value == "0" || value == "false" || value == "off")
            }
        }
    }

    /// How many pending packets a utun socket is allowed to accept before the
    /// interface pauses: sing-tun's `receiveBuffer/8*7/(mtu+4)`, clamped to
    /// 64 (`tun_darwin.go`). It is derived from `SO_RCVBUF` because the
    /// control socket's backlog is counted in bytes against that buffer,
    /// whereas this option makes the interface pause instead of dropping.
    #[cfg(any(target_vendor = "apple", test))]
    fn derive_utun_pending_packets(receive_buffer: usize, mtu: usize) -> libc::c_int {
        const UTUN_MAX_PENDING_PACKETS: libc::c_int = 64;
        let per_packet = mtu.saturating_add(DARWIN_UTUN_HEADER_LEN);
        if per_packet == 0 {
            return 1;
        }
        let pending = receive_buffer / 8 * 7 / per_packet;
        pending.clamp(1, UTUN_MAX_PENDING_PACKETS as usize) as libc::c_int
    }

    /// IP payload that still fits a 4 KiB mbuf cluster once the 4-byte utun
    /// prefix is included. `mbuf_allocpacket` takes a 16 KiB cluster — a pool
    /// of a few hundred — for anything above `MBIGCLBYTES` (4096, prefix
    /// included), and a `sendmsg_x` batch builds every packet before sending
    /// any, so a batch of larger frames fails with `ENOBUFS`. Those stay on
    /// the per-frame `writev`. sing-tun's `goDarwinBatchFrameLimit`.
    #[cfg(any(target_vendor = "apple", test))]
    const TUN_FD_SEND_FRAME_LIMIT: usize = 4096 - DARWIN_UTUN_HEADER_LEN;
    /// `sendmsg_x` batch cap. sing-tun's `goDarwinTransmitBatch`.
    #[cfg(any(target_vendor = "apple", test))]
    const TUN_FD_SEND_BATCH_MAX: usize = 64;

    /// `utun_pkt_input` in netif mode returns `ENOSPC` once the input chain
    /// passes `net.utun.max_pending_input` (512) and does not free the mbuf,
    /// and neither does `ctl_send`: every such refusal leaks one cluster until
    /// reboot. The chain drains when the host syncs its receive ring, which a
    /// successful input notifies, so the gate stays under the limit and, when
    /// the counter stops moving, lets a few packets through as a probe rather
    /// than waiting forever. sing-tun's `goDarwinGate*` constants.
    #[cfg(any(target_vendor = "apple", test))]
    const UTUN_INPUT_CHAIN_LIMIT: i64 = 512;
    #[cfg(any(target_vendor = "apple", test))]
    const UTUN_INPUT_CHAIN_HIGH_WATER: i64 = 384;
    #[cfg(any(target_vendor = "apple", test))]
    const UTUN_INPUT_CHAIN_PROBE: i64 = 8;
    #[cfg(any(target_vendor = "apple", test))]
    const UTUN_INPUT_CHAIN_PROBE_AFTER: i32 = 16;
    /// How often the interface counter may be read. sing-tun's `goDarwinGateSample`.
    /// Compiled into the pure-test build too, where nothing reads it.
    #[cfg(any(target_vendor = "apple", test))]
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    const UTUN_GATE_SAMPLE: Duration = Duration::from_millis(1);

    /// A fresh interface-counter reading, or the news that the 1 ms sample
    /// window has not elapsed. `Fresh(None)` is a failed read: the estimate
    /// stays where it was.
    #[cfg(any(target_vendor = "apple", test))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GateSample {
        NotDue,
        Fresh(Option<i64>),
    }

    /// Estimated utun input-chain depth. Pure: the counter and the clock are
    /// inputs, so the decisions are tested on every OS. Without a counter
    /// (`active == false`, sing-tun's `!netif`) the gate does not close —
    /// there is nothing to estimate, and closing would stall the tunnel.
    #[cfg(any(target_vendor = "apple", test))]
    #[derive(Debug, Clone)]
    struct UtunChainGate {
        active: bool,
        submitted: i64,
        sampled_at: i64,
        inflight_sample: i64,
        consumed_base: i64,
        last_consumed: i64,
        probe_end: i64,
        idle_polls: i32,
    }

    #[cfg(any(target_vendor = "apple", test))]
    impl UtunChainGate {
        fn inactive() -> Self {
            Self {
                active: false,
                submitted: 0,
                sampled_at: 0,
                inflight_sample: 0,
                consumed_base: 0,
                last_consumed: 0,
                probe_end: 0,
                idle_polls: 0,
            }
        }

        /// `consumed` is the interface's absolute input-packet counter at the
        /// moment the gate is armed, and becomes the baseline the estimate is
        /// measured from.
        fn armed(consumed: i64) -> Self {
            Self {
                active: true,
                consumed_base: consumed,
                last_consumed: consumed,
                ..Self::inactive()
            }
        }

        fn estimate(&self) -> i64 {
            self.inflight_sample + (self.submitted - self.sampled_at)
        }

        fn note_submitted(&mut self, count: usize) {
            self.submitted += count as i64;
        }

        /// The chain was already past the limit when the kernel refused.
        /// Frames the kernel freed behind the refused one never reach the
        /// counter, so the baseline is moved until the estimate reads the
        /// limit. sing-tun's `recordWriteError` for `ENOSPC`.
        fn note_enospc(&mut self, consumed: Option<i64>) {
            if !self.active {
                return;
            }
            if let Some(consumed) = consumed {
                self.last_consumed = consumed;
                self.consumed_base = consumed - (self.submitted - (UTUN_INPUT_CHAIN_LIMIT + 1));
            }
            self.inflight_sample = UTUN_INPUT_CHAIN_LIMIT + 1;
            self.sampled_at = self.submitted;
            self.probe_end = 0;
            self.idle_polls = 0;
        }

        fn apply_sample(&mut self, consumed: i64) -> bool {
            let progressed = consumed != self.last_consumed;
            if progressed {
                self.probe_end = 0;
            }
            self.last_consumed = consumed;
            let delta = consumed - self.consumed_base;
            self.inflight_sample = (self.submitted - delta).max(0);
            self.sampled_at = self.submitted;
            progressed
        }

        /// How many of `pending` frames may be submitted right now.
        fn admit(&mut self, pending: usize, sample: GateSample) -> usize {
            if !self.active || pending == 0 {
                return pending;
            }
            let pending_i = pending as i64;
            if self.estimate() + pending_i > UTUN_INPUT_CHAIN_HIGH_WATER {
                if let GateSample::Fresh(Some(consumed)) = sample {
                    self.apply_sample(consumed);
                }
            }
            room_from_estimate(self.estimate(), pending_i, self.probe_end, self.submitted)
        }

        /// One blocked poll. A sample that does not move the counter counts
        /// toward the probe; a sample that does clears it. A sample that is
        /// not due leaves the idle count alone and just rechecks the room.
        fn poll_blocked(&mut self, pending: usize, sample: GateSample) -> usize {
            if !self.active {
                return pending;
            }
            if let GateSample::Fresh(reading) = sample {
                let progressed = match reading {
                    Some(consumed) => self.apply_sample(consumed),
                    None => false,
                };
                if progressed {
                    self.idle_polls = 0;
                } else {
                    self.idle_polls = self.idle_polls.saturating_add(1);
                }
                if self.idle_polls >= UTUN_INPUT_CHAIN_PROBE_AFTER {
                    self.probe_end = self.submitted + UTUN_INPUT_CHAIN_PROBE;
                    self.idle_polls = 0;
                }
            }
            self.admit(pending, GateSample::NotDue)
        }
    }

    /// sing-tun's `gateRoom` arithmetic, split out so the clamp is obvious:
    /// never more than `pending`, never past one under the limit, and never
    /// negative. The probe term is what lets a stuck counter move again.
    #[cfg(any(target_vendor = "apple", test))]
    fn room_from_estimate(estimate: i64, pending: i64, probe_end: i64, submitted: i64) -> usize {
        let mut room = UTUN_INPUT_CHAIN_HIGH_WATER - estimate;
        let probe = (probe_end - submitted).min(UTUN_INPUT_CHAIN_LIMIT - 1 - estimate);
        room = room.max(probe);
        room.min(pending).max(0) as usize
    }

    /// What the next frame of a utun write should do. A closed gate submits
    /// nothing — not a `sendmsg_x`, and not a single `writev`. The single
    /// write is the syscall that leaks a cluster once the chain is over the
    /// limit, so "the gate says no" means wait, not fall through.
    #[cfg(any(target_vendor = "apple", test))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PlannedSend {
        Wait,
        /// The frame does not fit a 4 KiB cluster. One `writev`, and only
        /// because the gate allowed at least one packet.
        Single,
        /// This many leading frames, all of them small enough to batch.
        Batch(usize),
    }

    #[cfg(any(target_vendor = "apple", test))]
    fn plan_send(next_len: usize, batchable: usize, room: usize) -> PlannedSend {
        if room == 0 {
            return PlannedSend::Wait;
        }
        if next_len > TUN_FD_SEND_FRAME_LIMIT {
            return PlannedSend::Single;
        }
        let count = batchable.min(room).min(TUN_FD_SEND_BATCH_MAX);
        if count == 0 {
            // Small, but not a packet this code will put in a batch (no IP
            // version). The caller reports it; it is not a write.
            return PlannedSend::Wait;
        }
        PlannedSend::Batch(count)
    }

    /// How many leading packets of `packets` may share one `sendmsg_x`: each
    /// must fit the cluster limit and carry an IP version, and there may be
    /// at most `limit` of them.
    #[cfg(any(target_vendor = "apple", test))]
    fn batchable_count(packets: &[Bytes], limit: usize) -> usize {
        let mut count = 0;
        for packet in packets.iter().take(limit) {
            if packet.len() > TUN_FD_SEND_FRAME_LIMIT || ip_family_byte(packet).is_err() {
                break;
            }
            count += 1;
        }
        count
    }

    /// What one `sendmsg_x` result did to the messages handed to it. This is
    /// the only place a syscall result becomes a cursor movement, so a
    /// partial batch, `EAGAIN` and `ENOBUFS` cannot drop or resend a packet
    /// by accident.
    #[cfg(any(target_vendor = "apple", test))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SendAccount {
        /// `done` messages were accepted. `done < submitted` is a partial
        /// batch: the tail was not sent and must be submitted again.
        Progress { done: usize },
        /// Nothing was sent. Retry the same messages.
        RetrySame,
        /// Nothing was sent, and the batch was too big to build (`ENOBUFS` or
        /// `EMSGSIZE` of more than one message). Retry a smaller prefix.
        RetrySmaller,
        /// The one message was refused (`EINVAL` / `EMSGSIZE`). Drop it.
        DropOne,
        /// The descriptor is gone. Do not retry, and do not pretend the
        /// messages were delivered.
        Fatal,
        /// The kernel took every submitted message: the ones before the
        /// failure were delivered, the failing one is the kernel's, and the
        /// rest were dropped. Resending them would duplicate the delivered
        /// prefix. `enospc` is the leaking refusal and realigns the gate.
        Consumed { enospc: bool },
    }

    #[cfg(any(target_vendor = "apple", test))]
    fn account_send(submitted: usize, result: Result<usize, i32>) -> SendAccount {
        let errno = match result {
            Ok(done) => {
                let done = done.min(submitted);
                return if done == 0 {
                    SendAccount::RetrySame
                } else {
                    SendAccount::Progress { done }
                };
            }
            Err(errno) => errno,
        };
        if errno == libc::EINTR
            || errno == libc::EAGAIN
            || errno == libc::EWOULDBLOCK
            || (errno == libc::ENOBUFS && submitted <= 1)
        {
            return SendAccount::RetrySame;
        }
        if (errno == libc::ENOBUFS || errno == libc::EMSGSIZE) && submitted > 1 {
            return SendAccount::RetrySmaller;
        }
        if (errno == libc::EMSGSIZE || errno == libc::EINVAL) && submitted <= 1 {
            return SendAccount::DropOne;
        }
        if errno == libc::EBADF || errno == libc::ENXIO || errno == libc::ENOTCONN {
            return SendAccount::Fatal;
        }
        SendAccount::Consumed {
            enospc: errno == libc::ENOSPC,
        }
    }

    /// `ifi_ipackets` inside a `NET_RT_IFLIST2` buffer. The offsets are the
    /// LP64 `if_msghdr2` / packed-4 `if_data64` layout (asserted below): the
    /// counter is a `u64` at byte 56 of an `RTM_IFINFO2` message.
    #[cfg(any(target_vendor = "apple", test))]
    const IF_MSGHDR2_TYPE: usize = 3;
    #[cfg(any(target_vendor = "apple", test))]
    const IF_MSGHDR2_INDEX: usize = 12;
    #[cfg(any(target_vendor = "apple", test))]
    const IF_MSGHDR2_IPACKETS: usize = 56;
    #[cfg(any(target_vendor = "apple", test))]
    const IF_MSGHDR2_SIZE: usize = 160;
    #[cfg(any(target_vendor = "apple", test))]
    const RTM_IFINFO2: u8 = 0x12;

    #[cfg(any(target_vendor = "apple", test))]
    #[repr(C)]
    #[allow(dead_code)]
    struct IfMsgHdr2Head {
        msglen: u16,
        version: u8,
        typ: u8,
        addrs: i32,
        flags: i32,
        index: u16,
        snd_len: i32,
        snd_maxlen: i32,
        snd_drops: i32,
        timer: i32,
    }

    /// The prefix of `if_data64` through `ifi_ipackets`. The real struct is
    /// `#pragma pack(4)`, so the `u64` counters are 4-byte aligned.
    #[cfg(any(target_vendor = "apple", test))]
    #[repr(C, packed(4))]
    #[allow(dead_code)]
    struct IfData64Head {
        prefix: [u8; 8],
        mtu: u32,
        metric: u32,
        baudrate: u64,
        ipackets: u64,
        rest_counters: [u64; 10],
        recvtiming: u32,
        xmittiming: u32,
        lastchange_sec: i32,
        lastchange_usec: i32,
    }

    #[cfg(any(target_vendor = "apple", test))]
    const _: () = {
        assert!(std::mem::size_of::<IfMsgHdr2Head>() == 32);
        assert!(std::mem::offset_of!(IfMsgHdr2Head, index) == IF_MSGHDR2_INDEX);
        assert!(std::mem::offset_of!(IfData64Head, ipackets) == 24);
        assert!(std::mem::size_of::<IfData64Head>() == 128);
        assert!(32 + 24 == IF_MSGHDR2_IPACKETS);
        assert!(32 + 128 == IF_MSGHDR2_SIZE);
    };

    /// The input-packet counter for `index` in a `NET_RT_IFLIST2` buffer, or
    /// `None` when that interface's `RTM_IFINFO2` message is not there.
    #[cfg(any(target_vendor = "apple", test))]
    fn utun_ipackets_from_rib(rib: &[u8], index: u16) -> Option<i64> {
        let mut rest = rib;
        while rest.len() >= 4 {
            let msglen = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            if msglen == 0 || msglen > rest.len() {
                break;
            }
            if msglen >= IF_MSGHDR2_SIZE
                && rest[IF_MSGHDR2_TYPE] == RTM_IFINFO2
                && u16::from_le_bytes([rest[IF_MSGHDR2_INDEX], rest[IF_MSGHDR2_INDEX + 1]]) == index
            {
                let mut octets = [0u8; 8];
                octets.copy_from_slice(&rest[IF_MSGHDR2_IPACKETS..IF_MSGHDR2_IPACKETS + 8]);
                return i64::try_from(u64::from_le_bytes(octets)).ok();
            }
            rest = &rest[msglen..];
        }
        None
    }

    pub struct TunFdRuntime {
        shutdown: watch::Sender<bool>,
        read_task: JoinHandle<()>,
        write_task: JoinHandle<()>,
    }

    impl TunFdRuntime {
        pub fn start(config: TunFdConfig, tun: Arc<TunEndpoint>) -> io::Result<Self> {
            if let Err(err) = set_nonblocking(config.fd) {
                config.close_if_owned();
                return Err(err);
            }
            let packet_format = config.packet_format;
            let inner = TunFd::new(config, tun.mtu())?;
            // SAFETY: TunFd owns a private duplicate. Its AsRawFd always returns
            // that descriptor, which stays open until AsyncFd drops the owner.
            let fd = Arc::new(unsafe { AsyncFd::register(inner) }?);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let read_task = tokio::spawn(read_loop(
                Arc::clone(&fd),
                Arc::clone(&tun),
                shutdown_rx.clone(),
                packet_format,
            ));
            let write_task = tokio::spawn(write_loop(fd, tun, shutdown_rx, packet_format));

            Ok(Self {
                shutdown,
                read_task,
                write_task,
            })
        }

        pub async fn stop(self) {
            let _ = self.shutdown.send(true);
            self.read_task.abort();
            self.write_task.abort();
            let _ = self.read_task.await;
            let _ = self.write_task.await;
        }
    }

    struct TunFd {
        fd: OwnedFd,
        config: TunFdConfig,
    }

    impl TunFd {
        fn new(config: TunFdConfig, mtu: usize) -> io::Result<Self> {
            // A raw descriptor supplied by a host cannot guarantee AsyncFd's
            // lifetime. Duplicate it atomically with CLOEXEC so the registration
            // has its own owner even when the original is borrowed.
            let fd = unsafe { libc::fcntl(config.fd, libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                config.close_if_owned();
                return Err(error);
            }
            // SAFETY: fcntl returned a new open descriptor that we alone own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if config.packet_format == TunFdPacketFormat::DarwinUtun {
                set_utun_max_pending_packets(fd.as_raw_fd(), config.fd, mtu);
            }
            Ok(Self { fd, config })
        }
    }

    /// Best-effort `UTUN_OPT_MAX_PENDING_PACKETS` on a utun control socket, so
    /// the interface pauses when the receive buffer fills instead of letting
    /// the socket drop outbound packets with `ENOBUFS`. A failure says nothing
    /// about the descriptor's ability to carry packets — every macOS version
    /// before the option existed answers `ENOPROTOOPT` — so it is logged at
    /// debug and ignored. The value is derived from the *host* descriptor
    /// because that is the one the kernel knows; the duplicate shares the
    /// socket, so the option applies to both.
    #[cfg(target_vendor = "apple")]
    fn set_utun_max_pending_packets(dup_fd: RawFd, host_fd: RawFd, mtu: usize) {
        // `SOL_SYSTEM` (2) is the level these sysctl-style socket options live
        // under; `UTUN_OPT_MAX_PENDING_PACKETS` is 16 (`if_utun.h`).
        const SOL_SYSTEM: libc::c_int = 2;
        const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;
        let Some(receive_buffer) = utun_receive_buffer(host_fd) else {
            return;
        };
        let value = derive_utun_pending_packets(receive_buffer, mtu);
        // SAFETY: `host_fd` is a live descriptor owned by the caller, and
        // `value` is a `c_int` of the length passed.
        let rc = unsafe {
            libc::setsockopt(
                host_fd,
                SOL_SYSTEM,
                UTUN_OPT_MAX_PENDING_PACKETS,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            // No `RuntimeLogger` reaches this far — the fd is built before the
            // engine has one — so the debug channel available here is a debug
            // build's stderr. A release build drops the message and the tunnel
            // carries on; the option is an optimisation, not a requirement.
            debug_log_utun_option_failure(dup_fd, io::Error::last_os_error());
        }
    }

    /// Reports a failed best-effort utun option at debug level. Silent in a
    /// release build, where there is no logger to write to yet.
    #[cfg(target_vendor = "apple")]
    fn debug_log_utun_option_failure(fd: RawFd, error: io::Error) {
        #[cfg(debug_assertions)]
        eprintln!("segue: utun option on fd {fd} not set (continuing): {error}");
        #[cfg(not(debug_assertions))]
        let _ = (fd, error);
    }

    #[cfg(not(target_vendor = "apple"))]
    fn set_utun_max_pending_packets(_dup_fd: RawFd, _host_fd: RawFd, _mtu: usize) {}

    /// The socket's receive buffer in bytes, raised towards sing-tun's 8 MiB
    /// target first: `SO_RCVBUF` is clamped to `kern.ipc.maxsockbuf`, so the
    /// halving walk stops at the first size the kernel accepts (1 MiB floor).
    /// The value read back afterwards is what the option is derived from.
    #[cfg(target_vendor = "apple")]
    fn utun_receive_buffer(fd: RawFd) -> Option<usize> {
        const TARGET: libc::c_int = 8 << 20;
        const FLOOR: libc::c_int = 1 << 20;
        let mut size = TARGET;
        while size >= FLOOR {
            // SAFETY: `size` is a live `c_int` of the length passed.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc == 0 {
                break;
            }
            size /= 2;
        }
        let mut current: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `current` and `length` are live and sized as declared.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut current as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        (rc == 0 && current > 0).then_some(current as usize)
    }

    impl AsRawFd for TunFd {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl Drop for TunFd {
        fn drop(&mut self) {
            self.config.close_if_owned();
        }
    }

    /// Transient fd failures start with a short retry delay so brief network
    /// transitions recover quickly, then back off to a bounded one-second poll.
    /// The pump must not give up on them: nobody supervises these tasks, so a
    /// returned loop would leave the host reporting a connected but dead tunnel.
    const TUN_FD_IO_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
    const TUN_FD_IO_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(1);
    const TUN_FD_IO_RETRY_MAX_SHIFT: u32 = 7;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TunFdIoDisposition {
        /// The syscall was interrupted and should be reissued at once. Not a
        /// failure: it neither backs off nor advances the retry state.
        RetryImmediately,
        /// The payload cannot be encoded and never will be. Dropping it is the
        /// only progress available, and it says nothing about the descriptor.
        DropPacket,
        Retry,
        Fatal,
    }

    /// Classifies a pump I/O error. Everything is retryable except conditions
    /// that mean the descriptor itself is gone, because a tunnel that stops
    /// moving packets is far worse than one that retries a doomed read.
    fn io_disposition(error: &io::Error) -> TunFdIoDisposition {
        if error.kind() == io::ErrorKind::Interrupted {
            return TunFdIoDisposition::RetryImmediately;
        }
        if error.kind() == io::ErrorKind::InvalidData {
            return TunFdIoDisposition::DropPacket;
        }
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return TunFdIoDisposition::Fatal;
        }
        match error.raw_os_error() {
            Some(libc::EBADF) | Some(libc::ENXIO) | Some(libc::ENOTCONN) => {
                TunFdIoDisposition::Fatal
            }
            _ => TunFdIoDisposition::Retry,
        }
    }

    /// Classifies a failed write of one packet. `EINVAL` and `EMSGSIZE` are
    /// the kernel refusing that packet, not the descriptor: it would refuse
    /// it again, and the packets queued behind it would wait for ever.
    fn write_io_disposition(error: &io::Error) -> TunFdIoDisposition {
        match error.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::EMSGSIZE) => TunFdIoDisposition::DropPacket,
            _ => io_disposition(error),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TunFdLoopAction {
        Continue,
        BackOff,
        Stop,
    }

    #[derive(Debug)]
    struct PacketBatchWriteError {
        error: io::Error,
        written_packets: usize,
    }

    impl PacketBatchWriteError {
        fn new(written_packets: usize, error: io::Error) -> Self {
            Self {
                error,
                written_packets,
            }
        }
    }

    trait PacketBatchWriter {
        async fn write_batch(
            &mut self,
            packet_format: TunFdPacketFormat,
            packets: &[Bytes],
        ) -> Result<(), PacketBatchWriteError>;
    }

    struct AsyncFdPacketBatchWriter<'a> {
        fd: &'a AsyncFd<TunFd>,
        /// Present on Apple even when batching is off, so the write loop has
        /// one shape. `enabled` is what selects `sendmsg_x`.
        #[cfg(target_vendor = "apple")]
        utun: UtunSendState,
    }

    impl PacketBatchWriter for AsyncFdPacketBatchWriter<'_> {
        async fn write_batch(
            &mut self,
            packet_format: TunFdPacketFormat,
            packets: &[Bytes],
        ) -> Result<(), PacketBatchWriteError> {
            #[cfg(target_vendor = "apple")]
            if self.utun.enabled {
                return write_utun_send_batch(self.fd, packets, &mut self.utun).await;
            }
            write_packet_batch(self.fd, packet_format, packets).await
        }
    }

    /// Advances the consecutive-failure state for one I/O outcome and reports
    /// what the pump should do next. Only `Retry` advances the backoff: an
    /// interrupt is not a failure, and an unencodable packet says nothing about
    /// the fd. Transient failures never stop an unsupervised pump.
    fn advance_failure_state(
        disposition: TunFdIoDisposition,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        match disposition {
            TunFdIoDisposition::RetryImmediately | TunFdIoDisposition::DropPacket => {
                TunFdLoopAction::Continue
            }
            TunFdIoDisposition::Fatal => TunFdLoopAction::Stop,
            TunFdIoDisposition::Retry => {
                *consecutive_errors = (*consecutive_errors).saturating_add(1);
                TunFdLoopAction::BackOff
            }
        }
    }

    fn retry_backoff(consecutive_errors: u32) -> Duration {
        let shift = consecutive_errors
            .saturating_sub(1)
            .min(TUN_FD_IO_RETRY_MAX_SHIFT);
        TUN_FD_IO_RETRY_INITIAL_BACKOFF
            .saturating_mul(1_u32 << shift)
            .min(TUN_FD_IO_RETRY_MAX_BACKOFF)
    }

    /// Classifies one pump I/O failure, records it, and advances its backoff
    /// state. Only a `Retry` reflects on the descriptor, so it is the only
    /// disposition the stats see: an interrupt is not a failure and an
    /// unencodable packet is a data defect. The exit counters stay with the
    /// loops, which are the only ones that know which direction gave up.
    fn observe_io_failure(
        tun: &TunEndpoint,
        disposition: TunFdIoDisposition,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        if disposition == TunFdIoDisposition::Retry {
            tun.record_tun_fd_transient_io_error();
        }
        advance_failure_state(disposition, consecutive_errors)
    }

    async fn read_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: TunFdPacketFormat,
    ) {
        let mut reader = PacketReader::new(packet_format, tun.mtu());
        let mut consecutive_errors: u32 = 0;
        // Reused across reads so the packet list itself never allocates. It
        // holds at most one batch's packets, which the reader has already
        // carved out of its arena.
        let mut packets: Vec<Bytes> = Vec::new();

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                read = reader.read_into(&fd, &mut packets) => {
                    match read {
                        Ok(_) => {
                            consecutive_errors = 0;
                            if let Err(TunError::QueueClosed) =
                                tun.push_inbound_batch(packets.drain(..))
                            {
                                break;
                            }
                        }
                        Err(err) => {
                            let disposition = io_disposition(&err);
                            match observe_io_failure(&tun, disposition, &mut consecutive_errors) {
                                TunFdLoopAction::Continue => {}
                                TunFdLoopAction::BackOff => {
                                    tokio::time::sleep(retry_backoff(consecutive_errors)).await;
                                }
                                TunFdLoopAction::Stop => {
                                    tun.record_tun_fd_read_loop_exit();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn write_loop(
        fd: Arc<AsyncFd<TunFd>>,
        tun: Arc<TunEndpoint>,
        mut shutdown: watch::Receiver<bool>,
        packet_format: TunFdPacketFormat,
    ) {
        let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
        let mut next_packet = 0;
        let mut written_packets_in_batch = 0;
        let mut consecutive_errors: u32 = 0;
        let mut writer = AsyncFdPacketBatchWriter {
            fd: fd.as_ref(),
            #[cfg(target_vendor = "apple")]
            utun: UtunSendState::new(fd.as_ref().as_raw_fd(), packet_format),
        };

        loop {
            if next_packet < batch.len() {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    action = write_pending_packet_batch(
                        &mut writer,
                        &tun,
                        packet_format,
                        &batch,
                        &mut next_packet,
                        &mut written_packets_in_batch,
                        &mut consecutive_errors,
                    ) => {
                        match action {
                            TunFdLoopAction::Continue => {}
                            TunFdLoopAction::BackOff => {
                                tokio::time::sleep(retry_backoff(consecutive_errors)).await;
                            }
                            TunFdLoopAction::Stop => {
                                tun.record_tun_fd_write_loop_exit();
                                break;
                            }
                        }
                    }
                }
                continue;
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                result = tun.poll_outbound_batch_into(
                    TUN_FD_WRITE_BATCH_MAX_PACKETS,
                    &mut batch,
                ) => {
                    match result {
                        Ok(()) => {
                            next_packet = 0;
                            written_packets_in_batch = 0;
                        }
                        Err(TunError::QueueClosed) => break,
                        Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {}
                    }
                }
            }
        }
    }

    /// Attempts the currently unwritten slice of one dequeued batch. Progress
    /// is committed to `next_packet` before an error is classified, so the
    /// following loop iteration retries only the unwritten tail and never polls
    /// a new batch over it.
    async fn write_pending_packet_batch<W: PacketBatchWriter>(
        writer: &mut W,
        tun: &TunEndpoint,
        packet_format: TunFdPacketFormat,
        batch: &[Bytes],
        next_packet: &mut usize,
        written_packets_in_batch: &mut usize,
        consecutive_errors: &mut u32,
    ) -> TunFdLoopAction {
        let pending_packets = &batch[*next_packet..];
        match writer.write_batch(packet_format, pending_packets).await {
            Ok(()) => {
                *written_packets_in_batch += pending_packets.len();
                *next_packet = batch.len();
                finish_tun_fd_write_batch(tun, written_packets_in_batch);
                *consecutive_errors = 0;
                TunFdLoopAction::Continue
            }
            Err(PacketBatchWriteError {
                error,
                written_packets,
            }) => {
                let written_packets = written_packets.min(pending_packets.len());
                if written_packets > 0 {
                    *written_packets_in_batch += written_packets;
                    *next_packet += written_packets;
                    *consecutive_errors = 0;
                }

                if *next_packet == batch.len() {
                    finish_tun_fd_write_batch(tun, written_packets_in_batch);
                    return TunFdLoopAction::Continue;
                }

                let disposition = write_io_disposition(&error);
                let action = observe_io_failure(tun, disposition, consecutive_errors);
                if disposition == TunFdIoDisposition::DropPacket {
                    tun.record_tun_fd_outbound_drops(1);
                    *next_packet += 1;
                    if *next_packet == batch.len() {
                        finish_tun_fd_write_batch(tun, written_packets_in_batch);
                    }
                } else if action == TunFdLoopAction::Stop {
                    tun.record_tun_fd_outbound_drops(batch.len() - *next_packet);
                    *next_packet = batch.len();
                    finish_tun_fd_write_batch(tun, written_packets_in_batch);
                }
                action
            }
        }
    }

    fn finish_tun_fd_write_batch(tun: &TunEndpoint, written_packets_in_batch: &mut usize) {
        if *written_packets_in_batch > 0 {
            tun.record_tun_fd_write_batch(*written_packets_in_batch);
            *written_packets_in_batch = 0;
        }
    }

    /// One slot of a batched read, as the kernel reported it: how many bytes
    /// it wrote and whether it says the datagram was truncated.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[cfg(any(target_vendor = "apple", test))]
    struct BatchSlot {
        len: usize,
        truncated: bool,
    }

    /// Carves the packets of one batch out of `arena`, in slot order.
    ///
    /// Every slot occupies a fixed `stride` of the arena, whether or not it
    /// carried a packet, because that is how the buffers were laid out for the
    /// syscall. A slot is dropped when the kernel flagged it truncated or when
    /// it holds no payload past the format header; the rest are split off the
    /// shared allocation without a copy, exactly as the single-packet path
    /// does. This is the pure half of batching: it never touches a descriptor,
    /// so it runs and is tested on every platform.
    #[cfg(any(target_vendor = "apple", test))]
    fn carve_batch(
        arena: &mut BytesMut,
        slots: &[BatchSlot],
        stride: usize,
        header_len: usize,
        out: &mut Vec<Bytes>,
    ) {
        if slots.is_empty() || stride == 0 {
            return;
        }
        let total = slots.len().saturating_mul(stride);
        if arena.len() < total {
            return;
        }
        let mut region = arena.split_to(total);
        for slot in slots {
            let mut packet = region.split_to(stride);
            // A datagram longer than the slot is truncated to it; the extra
            // byte the slot reserves past the MTU is what keeps an oversized
            // packet observable, so it is still rejected downstream.
            packet.truncate(slot.len.min(stride));
            if slot.truncated || packet.len() <= header_len {
                continue;
            }
            packet.advance(header_len);
            out.push(packet.freeze());
        }
    }

    /// Carves inbound packets out of a shared arena so a packet reaches the
    /// queue without a per-packet allocation and without a copy: the read
    /// lands directly in the arena's spare capacity and the packet is split
    /// off it, sharing the allocation with its neighbours.
    struct PacketReader {
        arena: BytesMut,
        /// Bytes offered to one `read`: one MTU-sized packet plus the format
        /// header, plus one byte. That extra byte is what makes an oversized
        /// packet observable — it comes back one byte over the MTU and
        /// `push_inbound` rejects it, exactly as it did when the whole
        /// oversized packet was read and rejected.
        single_read: usize,
        arena_len: usize,
        header_len: usize,
        /// Apple only, and only when batching is on: the state one
        /// `recvmsg_x` batch needs. `None` means the single-packet path.
        #[cfg(target_vendor = "apple")]
        batch: Option<BatchState>,
    }

    /// One `iovec` slot, wrapped so the reader stays `Send`.
    ///
    /// `libc::iovec` holds a raw pointer and is therefore neither `Send` nor
    /// `Sync` by default, but these pointers only ever address the reader's
    /// own arena, which travels with it.
    #[cfg(target_vendor = "apple")]
    struct BatchIovec(libc::iovec);

    // SAFETY: see the type's comment — the pointer targets the owning
    // reader's arena and iovec array, which move together and are never
    // shared.
    #[cfg(target_vendor = "apple")]
    unsafe impl Send for BatchIovec {}

    /// A fresh batch arena of `len` bytes: allocated, zero-filled and then
    /// emptied, so its whole capacity is initialised behind a zero length.
    /// That keeps `advance_mut` sound over a slot the kernel only partly
    /// wrote, while `spare_capacity_mut` still spans the whole buffer.
    #[cfg(target_vendor = "apple")]
    fn batch_arena(len: usize) -> BytesMut {
        let mut arena = BytesMut::zeroed(len);
        arena.clear();
        arena
    }

    /// The reusable state of a batched read. Its memory is bounded: the arena
    /// holds at most `max * single_read` bytes, which [`batch_max_for`] keeps
    /// at or below [`TUN_FD_READ_BATCH_ARENA_MAX`] (272 KiB) for any MTU, and
    /// the header and iovec vectors are allocated once at `max` entries.
    #[cfg(target_vendor = "apple")]
    struct BatchState {
        max: usize,
        size: usize,
        arena: BytesMut,
        headers: Vec<apple::MsgHdrX>,
        iovs: Vec<BatchIovec>,
        slots: Vec<BatchSlot>,
    }

    impl PacketReader {
        fn new(packet_format: TunFdPacketFormat, mtu: usize) -> Self {
            let header_len = match packet_format {
                TunFdPacketFormat::RawIp => 0,
                TunFdPacketFormat::DarwinUtun => DARWIN_UTUN_HEADER_LEN,
            };
            let single_read = mtu
                .min(MAX_IP_PACKET_SIZE)
                .saturating_add(header_len)
                .saturating_add(1);
            let arena_len = single_read.max(TUN_FD_READ_ARENA_MIN);
            let batching = read_batching_enabled(packet_format);
            // The single-packet arena is only allocated when it can be used:
            // a batching reader would otherwise hold 64 KiB it never reads
            // into, on top of the batch arena.
            let arena = if batching {
                BytesMut::new()
            } else {
                BytesMut::with_capacity(arena_len)
            };
            #[cfg(target_vendor = "apple")]
            let batch = batching.then(|| {
                let max = batch_max_for(single_read);
                BatchState {
                    max,
                    size: TUN_FD_READ_BATCH_MIN.min(max),
                    // Allocated per batch in `read_batch`; empty here.
                    arena: BytesMut::new(),
                    headers: (0..max).map(|_| apple::MsgHdrX::zeroed()).collect(),
                    iovs: (0..max)
                        .map(|_| {
                            BatchIovec(libc::iovec {
                                iov_base: std::ptr::null_mut(),
                                iov_len: 0,
                            })
                        })
                        .collect(),
                    slots: Vec::with_capacity(max),
                }
            });
            Self {
                arena,
                single_read,
                arena_len,
                header_len,
                #[cfg(target_vendor = "apple")]
                batch,
            }
        }

        /// Reads whatever the descriptor has ready, appending the packets to
        /// `out` and returning how many were added. `Ok(0)` means a read that
        /// carried no payload, not an error; a descriptor at EOF is an error,
        /// as it is on the single-packet path.
        async fn read_into<T: AsRawFd>(
            &mut self,
            fd: &AsyncFd<T>,
            out: &mut Vec<Bytes>,
        ) -> io::Result<usize> {
            #[cfg(target_vendor = "apple")]
            {
                if self.batch.is_some() {
                    return self.read_batch(fd, out).await;
                }
            }
            self.read_packet_batch(fd, out).await
        }

        /// Reads up to a bounded batch of ready packets on a single-read
        /// descriptor (`RawIp` or non-batched `DarwinUtun`) without re-awaiting
        /// readiness between already-queued datagrams.
        async fn read_packet_batch<T: AsRawFd>(
            &mut self,
            fd: &AsyncFd<T>,
            out: &mut Vec<Bytes>,
        ) -> io::Result<usize> {
            const RAW_READ_BATCH_MAX: usize = 32;
            let mut added = 0_usize;
            let mut reads = 0_usize;

            loop {
                let mut guard = fd.readable().await?;
                while reads < RAW_READ_BATCH_MAX {
                    // A packet is split off whole, so the arena is always empty
                    // here and its capacity is what is left of the allocation.
                    // The exhausted arena is released rather than recycled: the
                    // packets carved from it keep it alive until the stack has
                    // consumed them, so it is never exclusively owned at this
                    // point and `try_reclaim` would always fail.
                    if self.arena.capacity() < self.single_read {
                        self.arena = BytesMut::with_capacity(self.arena_len);
                    }

                    let single_read = self.single_read;
                    let spare = self.arena.spare_capacity_mut();
                    let result = guard.try_io(|inner| {
                        // SAFETY: the arena reserved at least `single_read`
                        // spare bytes above, and nothing else references them
                        // until they are split off.
                        let read = unsafe {
                            libc::read(
                                inner.get_ref().as_raw_fd(),
                                spare.as_mut_ptr().cast(),
                                single_read,
                            )
                        };
                        if read < 0 {
                            Err(io::Error::last_os_error())
                        } else {
                            Ok(read as usize)
                        }
                    });

                    match result {
                        Ok(Ok(0)) => {
                            if reads > 0 {
                                return Ok(added);
                            }
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tun fd reached EOF",
                            ));
                        }
                        Ok(Ok(len)) => {
                            reads += 1;
                            if let Some(packet) = self.split_packet(len) {
                                out.push(packet);
                                added += 1;
                            }
                        }
                        Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                            if reads > 0 {
                                return Ok(added);
                            }
                            break;
                        }
                        Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => {
                            if reads > 0 {
                                return Ok(added);
                            }
                        }
                        Ok(Err(err)) => {
                            if reads > 0 {
                                return Ok(added);
                            }
                            return Err(err);
                        }
                        Err(_) => {
                            if reads > 0 {
                                return Ok(added);
                            }
                            break;
                        }
                    }
                }

                if reads > 0 {
                    return Ok(added);
                }
            }
        }

        /// Splits the `len` bytes just read off the arena and strips the
        /// format header.
        fn split_packet(&mut self, len: usize) -> Option<Bytes> {
            // SAFETY: `read` reported `len` bytes written into the spare
            // capacity, so they are initialized.
            unsafe { self.arena.advance_mut(len) };
            let mut packet = self.arena.split_to(len);
            if packet.len() <= self.header_len {
                return None;
            }
            packet.advance(self.header_len);
            Some(packet.freeze())
        }

        /// Reads up to the current adaptive batch size in one `recvmsg_x`
        /// call. The batch size grows when a batch comes back full and shrinks
        /// when it comes back under half full, so a busy tunnel amortises the
        /// syscall and an idle one does not ask for packets that are not
        /// there.
        #[cfg(target_vendor = "apple")]
        async fn read_batch<T: AsRawFd>(
            &mut self,
            fd: &AsyncFd<T>,
            out: &mut Vec<Bytes>,
        ) -> io::Result<usize> {
            let single_read = self.single_read;
            let header_len = self.header_len;
            let batch = self
                .batch
                .as_mut()
                .expect("batching reader has batch state");
            loop {
                let requested = batch.size.min(batch.max).max(1);
                let arena_needed = requested * single_read;
                // Reuse remaining zero-initialized tail capacity across
                // `WouldBlock` retries and small batches; only allocate a
                // fresh slab when the remaining capacity falls short.
                if batch.arena.capacity() < arena_needed {
                    batch.arena = batch_arena(arena_needed);
                }

                // Lay the slots out back to back in the arena's spare
                // capacity. The raw pointer stays inside this block: holding
                // one across the await below would make the future `!Send`
                // and the read loop could not be spawned.
                {
                    // Disjoint field borrows, so the iovec and its header can
                    // be written together.
                    let BatchState {
                        arena,
                        headers,
                        iovs,
                        ..
                    } = batch;
                    let base = arena.spare_capacity_mut().as_mut_ptr().cast::<u8>();
                    for index in 0..requested {
                        // SAFETY: the arena reserved `requested * single_read`
                        // bytes above, so slot `index` lies inside it.
                        let slot = unsafe { base.add(index * single_read) };
                        iovs[index] = BatchIovec(libc::iovec {
                            iov_base: slot.cast(),
                            iov_len: single_read,
                        });
                        // The whole header is cleared, not just the fields set
                        // here: older kernels reject a slot whose unused
                        // fields are not empty.
                        headers[index] = apple::MsgHdrX::zeroed();
                        headers[index].msg_iov = &mut iovs[index].0;
                        headers[index].msg_iovlen = 1;
                    }
                }

                let mut guard = fd.readable().await?;
                let headers = &mut batch.headers[..requested];
                let result = guard.try_io(|inner| {
                    // SAFETY: `headers` is a live array of `requested`
                    // initialised slots, each pointing at its own slot of the
                    // arena, and the descriptor is open for the call.
                    let received = unsafe {
                        apple::recvmsg_x(
                            inner.get_ref().as_raw_fd(),
                            headers.as_mut_ptr(),
                            requested as libc::c_uint,
                            apple::MSG_DONTWAIT,
                        )
                    };
                    if received < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(received as usize)
                    }
                });

                let received = match result {
                    Ok(Ok(received)) => received,
                    Ok(Err(err))
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue
                    }
                    Ok(Err(err)) => return Err(err),
                    Err(_) => continue,
                };
                // A datagram socket with a closed peer answers `ECONNRESET`
                // and a zero-length datagram still counts as one slot, so a
                // fill count of zero should not occur; if it ever does, treat
                // it as a read with no payload and go back to waiting on
                // readiness rather than declaring the tunnel dead.
                if received == 0 {
                    return Ok(0);
                }
                let received = received.min(requested);

                batch.slots.clear();
                for header in &batch.headers[..received] {
                    batch.slots.push(BatchSlot {
                        len: header.msg_datalen,
                        truncated: header.msg_flags & apple::MSG_TRUNC != 0,
                    });
                }
                // SAFETY: the kernel reported `received` slots written, each
                // `single_read` bytes, so that prefix of the spare capacity is
                // initialised.
                unsafe { batch.arena.advance_mut(received * single_read) };
                carve_batch(&mut batch.arena, &batch.slots, single_read, header_len, out);
                batch.size = next_batch_size(requested, received, batch.max);
                return Ok(received);
            }
        }
    }

    async fn write_packet_batch(
        fd: &AsyncFd<TunFd>,
        packet_format: TunFdPacketFormat,
        packets: &[Bytes],
    ) -> Result<(), PacketBatchWriteError> {
        let mut packet_index = 0;

        while packet_index < packets.len() {
            let mut guard = fd
                .writable()
                .await
                .map_err(|error| PacketBatchWriteError::new(packet_index, error))?;

            loop {
                let packet = EncodedPacket::new(packet_format, packets[packet_index].as_ref())
                    .map_err(|error| PacketBatchWriteError::new(packet_index, error))?;
                let result = guard.try_io(|inner| {
                    let written = packet.write_to_fd(inner.get_ref().as_raw_fd());
                    if written < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if written as usize != packet.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!(
                                "short tun fd write: wrote {written} of {} bytes",
                                packet.len()
                            ),
                        ));
                    }
                    Ok(())
                });

                match result {
                    Ok(Ok(())) => {
                        packet_index += 1;
                        if packet_index == packets.len() {
                            return Ok(());
                        }
                    }
                    Ok(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Ok(Err(err)) => {
                        return Err(PacketBatchWriteError::new(packet_index, err));
                    }
                    Err(_) => break,
                }
            }
        }

        Ok(())
    }

    /// Apple utun write batching. Frames that fit a 4 KiB cluster go out
    /// together through `sendmsg_x`; a larger frame is one `writev`, the same
    /// call the unbatched path makes. Both are limited by [`UtunChainGate`]:
    /// when the estimated input chain is at the high water the write waits,
    /// and a closed gate never falls through to a single write. `EAGAIN` and
    /// `ENOBUFS` leave every unsent packet queued; a short `sendmsg_x` commits
    /// only the count it returned.
    #[cfg(target_vendor = "apple")]
    async fn write_utun_send_batch<T: AsRawFd>(
        fd: &AsyncFd<T>,
        packets: &[Bytes],
        state: &mut UtunSendState,
    ) -> Result<(), PacketBatchWriteError> {
        let mut index = 0;
        while index < packets.len() {
            // An unencodable packet is dropped by the caller. Checking it
            // before the gate means a bad packet is not stuck behind a closed
            // gate, and it is never handed to the kernel.
            if let Err(error) = ip_family_byte(packets[index].as_ref()) {
                return Err(PacketBatchWriteError::new(index, error));
            }

            let room = state.admit_or_wait(packets.len() - index).await;
            let batchable = batchable_count(&packets[index..], room.min(TUN_FD_SEND_BATCH_MAX));
            match plan_send(packets[index].len(), batchable, room) {
                PlannedSend::Wait => {
                    return Err(PacketBatchWriteError::new(
                        index,
                        io::Error::from_raw_os_error(libc::EAGAIN),
                    ));
                }
                PlannedSend::Single => {
                    let error = write_one_packet(
                        fd,
                        TunFdPacketFormat::DarwinUtun,
                        packets[index].as_ref(),
                    )
                    .await;
                    match error {
                        Ok(()) => {
                            state.chain.note_submitted(1);
                            index += 1;
                        }
                        Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                            // The kernel took the packet and leaked its
                            // cluster. Retrying would leak another.
                            state.chain.note_submitted(1);
                            state.realign_after_enospc();
                            index += 1;
                            return Err(PacketBatchWriteError::new(index, error));
                        }
                        Err(error) => {
                            return Err(PacketBatchWriteError::new(index, error));
                        }
                    }
                }
                PlannedSend::Batch(count) => {
                    // `written_packets` counts from the start of this run.
                    // Shift it by the frames already committed, or a later
                    // error would resend them.
                    match sendmsg_x_accounted(fd, &packets[index..index + count], state).await {
                        Ok(done) => index += done,
                        Err(error) => {
                            return Err(PacketBatchWriteError::new(
                                index + error.written_packets,
                                error.error,
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// One `write` / `writev` of a single packet, waiting out `EAGAIN` and
    /// `EINTR`. A short write is an error, as it is on the unbatched path:
    /// the kernel's datagram sockets do not deliver a prefix of one message.
    #[cfg(target_vendor = "apple")]
    async fn write_one_packet<T: AsRawFd>(
        fd: &AsyncFd<T>,
        packet_format: TunFdPacketFormat,
        packet: &[u8],
    ) -> io::Result<()> {
        let encoded = EncodedPacket::new(packet_format, packet)?;
        loop {
            let mut guard = fd.writable().await?;
            let result = guard.try_io(|inner| {
                let written = encoded.write_to_fd(inner.get_ref().as_raw_fd());
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                if written as usize != encoded.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "short tun fd write: wrote {written} of {} bytes",
                            encoded.len()
                        ),
                    ));
                }
                Ok(())
            });
            match result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error))
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    /// Submits `packets` (already known to be one batchable run) and returns
    /// how many of them the kernel accepted. `ENOBUFS` and a multi-message
    /// `EMSGSIZE` shrink the run and try again, because those failures are
    /// raised before anything is sent. Anything the kernel consumed is not
    /// part of the returned count's complement: the caller advances by the
    /// returned count only, except a consumed run, which is reported as an
    /// error whose `written_packets` already includes it.
    #[cfg(target_vendor = "apple")]
    async fn sendmsg_x_accounted<T: AsRawFd>(
        fd: &AsyncFd<T>,
        packets: &[Bytes],
        state: &mut UtunSendState,
    ) -> Result<usize, PacketBatchWriteError> {
        let mut limit = packets.len();
        loop {
            let count = batchable_count(packets, limit).min(packets.len());
            if count == 0 {
                return Err(PacketBatchWriteError::new(
                    0,
                    io::Error::new(io::ErrorKind::InvalidData, "tun packet is not IPv4 or IPv6"),
                ));
            }
            let result = state.syscall_sendmsg_x(fd, &packets[..count]).await;
            let account = match &result {
                Ok(done) => account_send(count, Ok(*done)),
                Err(error) => match error.raw_os_error() {
                    Some(errno) => account_send(count, Err(errno)),
                    None => {
                        return Err(PacketBatchWriteError::new(
                            0,
                            io::Error::new(error.kind(), error.to_string()),
                        ));
                    }
                },
            };
            match account {
                SendAccount::Progress { done } => {
                    state.chain.note_submitted(done);
                    return Ok(done);
                }
                SendAccount::RetrySame => {
                    let error = result.err().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::WriteZero, "sendmsg_x accepted nothing")
                    });
                    return Err(PacketBatchWriteError::new(0, error));
                }
                SendAccount::RetrySmaller => {
                    let next = count.div_ceil(2);
                    if next == 0 || next >= count {
                        let error = result
                            .err()
                            .unwrap_or_else(|| io::Error::from_raw_os_error(libc::ENOBUFS));
                        return Err(PacketBatchWriteError::new(0, error));
                    }
                    limit = next;
                }
                SendAccount::DropOne => {
                    let error = result
                        .err()
                        .unwrap_or_else(|| io::Error::from_raw_os_error(libc::EINVAL));
                    return Err(PacketBatchWriteError::new(0, error));
                }
                SendAccount::Fatal => {
                    let error = result
                        .err()
                        .unwrap_or_else(|| io::Error::from_raw_os_error(libc::EBADF));
                    return Err(PacketBatchWriteError::new(0, error));
                }
                SendAccount::Consumed { enospc } => {
                    state.chain.note_submitted(count);
                    if enospc {
                        state.realign_after_enospc();
                    }
                    // `EINVAL` / `EMSGSIZE` would tell the caller to drop the
                    // packet *after* this run. The run itself is already
                    // consumed; the following packet was not part of it.
                    let errno = result.as_ref().err().and_then(io::Error::raw_os_error);
                    let error = match errno {
                        Some(libc::EINVAL | libc::EMSGSIZE) | None => {
                            io::Error::from_raw_os_error(if enospc {
                                libc::ENOSPC
                            } else {
                                libc::EIO
                            })
                        }
                        Some(_) => result.expect_err("errno was taken from this error"),
                    };
                    // `written_packets` is the whole run: the caller must not
                    // submit it again. The error still backs off whatever
                    // follows the run, unless the run finished the batch, in
                    // which case there is nothing left to retry.
                    return Err(PacketBatchWriteError::new(count, error));
                }
            }
        }
    }

    /// The utun write gate plus the scratch `sendmsg_x` fills in. The scratch
    /// is heap-stable, so the pointers written into it for one syscall stay
    /// valid for that call even though the future around it is movable; they
    /// are rewritten before every call and never read after it returns.
    #[cfg(target_vendor = "apple")]
    struct UtunSendState {
        chain: UtunChainGate,
        enabled: bool,
        ifindex: u32,
        rib: Vec<u8>,
        last_sample: Option<std::time::Instant>,
        headers: Vec<[u8; 4]>,
        iovs: Vec<BatchIovec>,
        msgs: Vec<apple::MsgHdrX>,
    }

    #[cfg(target_vendor = "apple")]
    impl UtunSendState {
        fn new(fd: RawFd, packet_format: TunFdPacketFormat) -> Self {
            let enabled = packet_format == TunFdPacketFormat::DarwinUtun
                && read_batching_enabled(packet_format);
            let mut chain = UtunChainGate::inactive();
            let mut ifindex = 0;
            let mut rib = Vec::new();
            let index = if enabled { utun_netif_index(fd) } else { None };
            if let Some(index) = index {
                rib.resize(UTUN_GATE_RIB_SIZE, 0);
                if let Ok(consumed) = read_utun_ipackets(index, &mut rib) {
                    chain = UtunChainGate::armed(consumed);
                    ifindex = index;
                }
            }
            let slots = if enabled { TUN_FD_SEND_BATCH_MAX } else { 0 };
            Self {
                chain,
                enabled,
                ifindex,
                rib,
                // The arming sample just happened; the next one waits out the
                // same 1 ms window sing-tun uses.
                last_sample: enabled.then(std::time::Instant::now),
                headers: vec![[0; DARWIN_UTUN_HEADER_LEN]; slots],
                iovs: (0..slots * 2)
                    .map(|_| {
                        BatchIovec(libc::iovec {
                            iov_base: std::ptr::null_mut(),
                            iov_len: 0,
                        })
                    })
                    .collect(),
                msgs: (0..slots).map(|_| apple::MsgHdrX::zeroed()).collect(),
            }
        }

        async fn admit_or_wait(&mut self, pending: usize) -> usize {
            let room = self.admit(pending);
            if room > 0 || !self.chain.active {
                return room;
            }
            // Long enough for the probe to arm (16 samples, one per ms) and
            // short enough that shutdown is not stuck behind it.
            let deadline = std::time::Instant::now() + Duration::from_millis(20);
            loop {
                let room = self.poll_blocked(pending);
                let now = std::time::Instant::now();
                if room > 0 || now >= deadline {
                    return room;
                }
                let next_sample = self
                    .last_sample
                    .map(|sampled| sampled + UTUN_GATE_SAMPLE)
                    .unwrap_or(now);
                let sleep_for = next_sample
                    .saturating_duration_since(now)
                    .min(deadline.saturating_duration_since(now))
                    .max(Duration::from_micros(100));
                tokio::time::sleep(sleep_for).await;
            }
        }

        fn admit(&mut self, pending: usize) -> usize {
            if !self.chain.active {
                return pending;
            }
            let over =
                self.chain.estimate().saturating_add(pending as i64) > UTUN_INPUT_CHAIN_HIGH_WATER;
            let sample = if over && self.sample_due() {
                self.read_sample()
            } else {
                GateSample::NotDue
            };
            self.chain.admit(pending, sample)
        }

        fn poll_blocked(&mut self, pending: usize) -> usize {
            let sample = if self.sample_due() {
                self.read_sample()
            } else {
                GateSample::NotDue
            };
            self.chain.poll_blocked(pending, sample)
        }

        fn sample_due(&self) -> bool {
            self.last_sample
                .map(|sampled| {
                    std::time::Instant::now().saturating_duration_since(sampled) >= UTUN_GATE_SAMPLE
                })
                .unwrap_or(true)
        }

        fn read_sample(&mut self) -> GateSample {
            self.last_sample = Some(std::time::Instant::now());
            if self.ifindex == 0 {
                return GateSample::Fresh(None);
            }
            GateSample::Fresh(read_utun_ipackets(self.ifindex, &mut self.rib).ok())
        }

        fn realign_after_enospc(&mut self) {
            let consumed = if self.ifindex == 0 {
                None
            } else {
                read_utun_ipackets(self.ifindex, &mut self.rib).ok()
            };
            self.chain.note_enospc(consumed);
            self.last_sample = Some(std::time::Instant::now());
        }

        fn arm_messages(&mut self, packets: &[Bytes]) {
            let UtunSendState {
                headers,
                iovs,
                msgs,
                ..
            } = self;
            for (index, packet) in packets.iter().enumerate() {
                let family = ip_family_byte(packet).unwrap_or(0);
                headers[index] = [0, 0, 0, family];
                let packet = packet.as_ref();
                iovs[index * 2] = BatchIovec(libc::iovec {
                    iov_base: headers[index].as_mut_ptr().cast(),
                    iov_len: DARWIN_UTUN_HEADER_LEN,
                });
                iovs[index * 2 + 1] = BatchIovec(libc::iovec {
                    iov_base: packet.as_ptr().cast_mut().cast(),
                    iov_len: packet.len(),
                });
                // The whole header is cleared, not just the fields set here:
                // older kernels reject a slot whose unused fields are not empty.
                msgs[index] = apple::MsgHdrX::zeroed();
                msgs[index].msg_iov = &mut iovs[index * 2].0;
                msgs[index].msg_iovlen = 2;
            }
        }

        async fn syscall_sendmsg_x<T: AsRawFd>(
            &mut self,
            fd: &AsyncFd<T>,
            packets: &[Bytes],
        ) -> io::Result<usize> {
            loop {
                let mut guard = fd.writable().await?;
                // Pointers are taken after the await, used only for this
                // synchronous call, and never stored in the future as a local.
                // The bytes they address live on the heap (the scratch vecs and
                // the packet buffers), which does not move with the future.
                self.arm_messages(packets);
                let msgs = self.msgs.as_mut_ptr();
                let count = packets.len() as libc::c_uint;
                let result = guard.try_io(|inner| {
                    // SAFETY: `msgs` is `count` initialised headers, each with
                    // two iovecs pointing at this state's header bytes and the
                    // caller's packet, and the descriptor is open for the call.
                    let sent = unsafe {
                        apple::sendmsg_x(
                            inner.get_ref().as_raw_fd(),
                            msgs,
                            count,
                            apple::MSG_DONTWAIT,
                        )
                    };
                    if sent < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(sent as usize)
                    }
                });
                match result {
                    Ok(Ok(sent)) => return Ok(sent),
                    Ok(Err(error))
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        }
    }

    /// `UTUN_OPT_ENABLE_NETIF` is 20 and `UTUN_OPT_IFNAME` is 2, both under
    /// `SYSPROTO_CONTROL` (2). The gate arms only when the socket says it is
    /// in netif mode and its input counter can be read; that is the mode in
    /// which an over-full chain leaks. Any failure leaves the gate open.
    #[cfg(target_vendor = "apple")]
    fn utun_netif_index(fd: RawFd) -> Option<u32> {
        const SYSPROTO_CONTROL: libc::c_int = 2;
        const UTUN_OPT_IFNAME: libc::c_int = 2;
        const UTUN_OPT_ENABLE_NETIF: libc::c_int = 20;
        let mut enabled: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `enabled` and `length` are live and sized as declared, and
        // `fd` is the caller's open descriptor.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_ENABLE_NETIF,
                (&mut enabled as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if rc != 0 || enabled == 0 {
            return None;
        }
        let mut name = [0u8; UTUN_IFNAME_CAP];
        length = name.len() as libc::socklen_t;
        // SAFETY: `name` is a live buffer of `length` bytes.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if rc != 0 || !name.contains(&0) {
            return None;
        }
        // SAFETY: `name` is NUL-terminated, as checked above.
        let index = unsafe { libc::if_nametoindex(name.as_ptr().cast()) };
        (index != 0).then_some(index)
    }

    #[cfg(target_vendor = "apple")]
    const UTUN_IFNAME_CAP: usize = 16;
    #[cfg(target_vendor = "apple")]
    const UTUN_GATE_RIB_SIZE: usize = 4096;
    #[cfg(target_vendor = "apple")]
    const UTUN_GATE_RIB_MAX: usize = 1 << 20;
    /// `NET_RT_IFLIST2` from `net/route.h`. One interface is requested by
    /// putting its index in the last name component, so the transfer stays
    /// one message.
    #[cfg(target_vendor = "apple")]
    const NET_RT_IFLIST2: libc::c_int = 6;

    #[cfg(target_vendor = "apple")]
    fn read_utun_ipackets(index: u32, buf: &mut Vec<u8>) -> io::Result<i64> {
        if buf.len() < UTUN_GATE_RIB_SIZE {
            buf.resize(UTUN_GATE_RIB_SIZE, 0);
        }
        let mut mib: [libc::c_int; 6] = [
            libc::CTL_NET,
            libc::AF_ROUTE,
            0,
            libc::AF_UNSPEC,
            NET_RT_IFLIST2,
            index as libc::c_int,
        ];
        loop {
            let mut length: libc::size_t = buf.len();
            // SAFETY: `mib` is the six-element name, `buf` is `length` bytes,
            // and a null new-value reads the sysctl without writing it.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as libc::c_uint,
                    buf.as_mut_ptr().cast(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOMEM) && buf.len() < UTUN_GATE_RIB_MAX {
                    buf.resize(buf.len().saturating_mul(2).min(UTUN_GATE_RIB_MAX), 0);
                    continue;
                }
                return Err(error);
            }
            let length = length.min(buf.len());
            return utun_ipackets_from_rib(&buf[..length], index as u16).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "utun interface counter is not in the routing table",
                )
            });
        }
    }

    /// The address family a packet's first nibble names, as the byte a utun
    /// header carries. Anything else is not a packet the descriptor will
    /// accept, and retrying it would wedge the queue behind it.
    fn ip_family_byte(packet: &[u8]) -> io::Result<u8> {
        match packet.first().copied().map(|byte| byte >> 4) {
            Some(4) => Ok(libc::AF_INET as u8),
            Some(6) => Ok(libc::AF_INET6 as u8),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tun packet is not IPv4 or IPv6",
            )),
        }
    }

    enum EncodedPacket<'a> {
        RawIp(&'a [u8]),
        DarwinUtun { header: [u8; 4], payload: &'a [u8] },
    }

    impl<'a> EncodedPacket<'a> {
        fn new(packet_format: TunFdPacketFormat, packet: &'a [u8]) -> io::Result<Self> {
            // Checked for both formats: a raw-IP device refuses anything else
            // with `EINVAL`, which says nothing about the descriptor.
            let family = ip_family_byte(packet)?;
            match packet_format {
                TunFdPacketFormat::RawIp => Ok(Self::RawIp(packet)),
                TunFdPacketFormat::DarwinUtun => Ok(Self::DarwinUtun {
                    header: [0, 0, 0, family],
                    payload: packet,
                }),
            }
        }

        fn len(&self) -> usize {
            match self {
                Self::RawIp(packet) => packet.len(),
                Self::DarwinUtun { payload, .. } => DARWIN_UTUN_HEADER_LEN + payload.len(),
            }
        }

        #[cfg(test)]
        fn header(&self) -> Option<[u8; 4]> {
            match self {
                Self::RawIp(_) => None,
                Self::DarwinUtun { header, .. } => Some(*header),
            }
        }

        #[cfg(test)]
        fn payload(&self) -> &'a [u8] {
            match self {
                Self::RawIp(packet) => packet,
                Self::DarwinUtun { payload, .. } => payload,
            }
        }

        fn write_to_fd(&self, fd: RawFd) -> libc::ssize_t {
            match self {
                Self::RawIp(packet) => unsafe {
                    libc::write(fd, packet.as_ptr().cast(), packet.len())
                },
                Self::DarwinUtun { header, payload } => {
                    let iov = [
                        libc::iovec {
                            iov_base: header.as_ptr().cast_mut().cast(),
                            iov_len: header.len(),
                        },
                        libc::iovec {
                            iov_base: payload.as_ptr().cast_mut().cast(),
                            iov_len: payload.len(),
                        },
                    ];
                    unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) }
                }
            }
        }
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun fd must be non-negative",
            ));
        }

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::collections::VecDeque;
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;

        use crate::TunFdClosePolicy;

        use super::*;
        use segue_tun::TunConfig;

        enum ScriptedBatchWrite {
            Complete,
            Fail(PacketBatchWriteError),
        }

        struct ScriptedPacketBatchWriter {
            outcomes: VecDeque<ScriptedBatchWrite>,
            calls: Vec<Vec<Bytes>>,
            written: Vec<Bytes>,
        }

        impl ScriptedPacketBatchWriter {
            fn new(outcomes: impl IntoIterator<Item = ScriptedBatchWrite>) -> Self {
                Self {
                    outcomes: outcomes.into_iter().collect(),
                    calls: Vec::new(),
                    written: Vec::new(),
                }
            }
        }

        impl PacketBatchWriter for ScriptedPacketBatchWriter {
            async fn write_batch(
                &mut self,
                _packet_format: TunFdPacketFormat,
                packets: &[Bytes],
            ) -> Result<(), PacketBatchWriteError> {
                self.calls.push(packets.to_vec());
                match self.outcomes.pop_front().expect("missing scripted write") {
                    ScriptedBatchWrite::Complete => {
                        self.written.extend(packets.iter().cloned());
                        Ok(())
                    }
                    ScriptedBatchWrite::Fail(failure) => {
                        assert!(failure.written_packets <= packets.len());
                        self.written
                            .extend(packets[..failure.written_packets].iter().cloned());
                        Err(failure)
                    }
                }
            }
        }

        /// Fills `reader`'s arena with `payload` the way a successful `read`
        /// would, then carves the packet out of it.
        fn feed(reader: &mut PacketReader, payload: &[u8]) -> Option<Bytes> {
            if reader.arena.capacity() < reader.single_read {
                reader.arena = BytesMut::with_capacity(reader.arena_len);
            }
            let spare = reader.arena.spare_capacity_mut();
            assert!(spare.len() >= payload.len());
            // SAFETY: `spare` has room for `payload`, which is initialized.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    spare.as_mut_ptr().cast::<u8>(),
                    payload.len(),
                );
            }
            reader.split_packet(payload.len())
        }

        #[test]
        fn consecutive_packets_are_carved_out_of_one_arena() {
            let mut reader = PacketReader::new(TunFdPacketFormat::RawIp, 1500);
            let first = feed(&mut reader, &[1_u8; 1200]).expect("first packet");
            let second = feed(&mut reader, &[2_u8; 300]).expect("second packet");

            assert_eq!(first.len(), 1200);
            assert_eq!(second.len(), 300);
            assert!(first.iter().all(|byte| *byte == 1));
            assert!(second.iter().all(|byte| *byte == 2));
            // Both packets point into the same allocation, back to back: the
            // second read neither allocated nor copied.
            assert_eq!(unsafe { first.as_ptr().add(first.len()) }, second.as_ptr());
        }

        #[test]
        fn a_new_arena_is_allocated_only_once_the_old_one_is_exhausted() {
            const PAYLOAD: usize = 1500;
            let mut reader = PacketReader::new(TunFdPacketFormat::RawIp, 1500);
            let capacity = reader.arena.capacity();
            let expected = (capacity - reader.single_read) / PAYLOAD + 1;
            assert!(expected > 1, "the arena must amortize allocations");

            let mut previous = feed(&mut reader, &[7_u8; PAYLOAD]).expect("packet");
            let mut carved = 1;
            loop {
                let next = feed(&mut reader, &[7_u8; PAYLOAD]).expect("packet");
                if unsafe { previous.as_ptr().add(previous.len()) } != next.as_ptr() {
                    break;
                }
                previous = next;
                carved += 1;
            }

            assert_eq!(
                carved, expected,
                "one arena must serve every read that still fits in it"
            );
        }

        #[test]
        fn the_darwin_utun_header_is_stripped_without_copying_the_payload() {
            let mut reader = PacketReader::new(TunFdPacketFormat::DarwinUtun, 1500);
            let mut framed = vec![0, 0, 0, libc::AF_INET as u8];
            framed.extend_from_slice(&[0x45, 0x11, 0x22, 0x33]);

            let packet = feed(&mut reader, &framed).expect("packet");

            assert_eq!(&packet[..], &[0x45, 0x11, 0x22, 0x33]);
        }

        #[test]
        fn a_read_that_carries_no_payload_yields_no_packet() {
            let mut raw = PacketReader::new(TunFdPacketFormat::RawIp, 1500);
            assert!(feed(&mut raw, &[]).is_none());

            let mut utun = PacketReader::new(TunFdPacketFormat::DarwinUtun, 1500);
            assert!(feed(&mut utun, &[0, 0, 0, libc::AF_INET as u8]).is_none());
        }

        #[test]
        fn one_read_offers_room_for_an_oversized_packet_so_it_stays_rejectable() {
            // Reading one byte past the MTU is what keeps an oversized packet
            // observable: it comes back over the MTU and is dropped by
            // `push_inbound`, instead of being silently truncated to a
            // plausible-looking packet.
            let raw = PacketReader::new(TunFdPacketFormat::RawIp, 1500);
            assert_eq!(raw.single_read, 1501);

            let utun = PacketReader::new(TunFdPacketFormat::DarwinUtun, 1500);
            assert_eq!(utun.single_read, 1505);
        }

        #[test]
        fn a_jumbo_mtu_arena_still_holds_one_whole_read() {
            let mut reader = PacketReader::new(TunFdPacketFormat::DarwinUtun, MAX_IP_PACKET_SIZE);
            assert_eq!(reader.single_read, MAX_IP_PACKET_SIZE + 5);
            // The single-packet arena is sized at `arena_len` and allocated
            // lazily: a batching reader (Apple's default) holds no arena until
            // a read needs one, so the size guarantee is `arena_len`, and
            // `feed` allocates it the way `read_packet` does on first use.
            assert!(reader.arena_len >= reader.single_read);

            let mut framed = vec![0, 0, 0, libc::AF_INET as u8];
            framed.resize(MAX_IP_PACKET_SIZE + DARWIN_UTUN_HEADER_LEN, 0x45);
            let packet = feed(&mut reader, &framed).expect("one whole jumbo read");
            assert_eq!(packet.len(), MAX_IP_PACKET_SIZE);
        }

        fn test_packet_batch() -> Vec<Bytes> {
            vec![
                Bytes::from_static(&[0x45, 0x01]),
                Bytes::from_static(&[0x45, 0x02]),
                Bytes::from_static(&[0x45, 0x03]),
            ]
        }

        fn test_tun_endpoint() -> TunEndpoint {
            TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: 4,
            })
        }

        #[tokio::test]
        async fn stopping_owned_tun_closes_original_and_registered_duplicate() {
            let (host, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let runtime = TunFdRuntime::start(
                TunFdConfig::new(
                    host.into_raw_fd(),
                    TunFdPacketFormat::RawIp,
                    TunFdClosePolicy::Owned,
                ),
                Arc::new(test_tun_endpoint()),
            )
            .unwrap();

            runtime.stop().await;

            assert_eq!(
                peer.read(&mut [0]).unwrap(),
                0,
                "both descriptors must close"
            );
        }

        #[tokio::test]
        async fn stopping_borrowed_tun_leaves_the_callers_descriptor_open() {
            let (mut host, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let runtime = TunFdRuntime::start(
                TunFdConfig::new(
                    host.as_raw_fd(),
                    TunFdPacketFormat::RawIp,
                    TunFdClosePolicy::Borrowed,
                ),
                Arc::new(test_tun_endpoint()),
            )
            .unwrap();

            runtime.stop().await;

            host.write_all(b"x").unwrap();
            let mut received = [0];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"x");
            drop(host);
            assert_eq!(peer.read(&mut received).unwrap(), 0, "duplicate must close");
        }

        #[test]
        fn tun_registration_owns_a_cloexec_duplicate() {
            let (host, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let inner = TunFd::new(
                TunFdConfig::new(
                    host.as_raw_fd(),
                    TunFdPacketFormat::RawIp,
                    TunFdClosePolicy::Borrowed,
                ),
                1500,
            )
            .unwrap();
            assert_ne!(inner.as_raw_fd(), host.as_raw_fd());
            assert_ne!(
                unsafe { libc::fcntl(inner.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            drop(host);
            let mut registered = std::fs::File::from(inner.fd.try_clone().unwrap());
            registered.write_all(b"x").unwrap();
            let mut received = [0];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"x");
        }

        #[test]
        fn darwin_utun_encoded_packet_borrows_payload_and_adds_family_header() {
            let packet = [0x45, 0x00, 0x00, 0x14];
            let encoded = EncodedPacket::new(TunFdPacketFormat::DarwinUtun, &packet).unwrap();

            assert_eq!(encoded.len(), DARWIN_UTUN_HEADER_LEN + packet.len());
            assert_eq!(encoded.header(), Some([0, 0, 0, libc::AF_INET as u8]));
            assert!(std::ptr::eq(encoded.payload().as_ptr(), packet.as_ptr()));
        }

        #[test]
        fn transient_tun_fd_errors_are_retried_not_fatal() {
            for errno in [
                libc::ENOBUFS,
                libc::ENOMEM,
                libc::ENETDOWN,
                libc::ENETUNREACH,
                libc::EHOSTDOWN,
                libc::EHOSTUNREACH,
                libc::ETIMEDOUT,
                libc::EIO,
            ] {
                assert_eq!(
                    io_disposition(&io::Error::from_raw_os_error(errno)),
                    TunFdIoDisposition::Retry,
                    "errno {errno} must be retried"
                );
            }
        }

        #[test]
        fn a_closed_descriptor_is_fatal() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EBADF)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::ENXIO)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::ENOTCONN)),
                TunFdIoDisposition::Fatal
            );
            assert_eq!(
                io_disposition(&io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
                TunFdIoDisposition::Fatal
            );
        }

        #[test]
        fn interrupts_are_retried_without_counting_as_failures() {
            assert_eq!(
                io_disposition(&io::Error::from_raw_os_error(libc::EINTR)),
                TunFdIoDisposition::RetryImmediately
            );
            assert_eq!(
                io_disposition(&io::Error::new(io::ErrorKind::Interrupted, "eintr")),
                TunFdIoDisposition::RetryImmediately
            );
        }

        #[test]
        fn only_transient_retries_advance_the_backoff_state() {
            let mut consecutive = 0;

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::RetryImmediately, &mut consecutive),
                TunFdLoopAction::Continue
            );
            assert_eq!(consecutive, 0);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::DropPacket, &mut consecutive),
                TunFdLoopAction::Continue
            );
            assert_eq!(consecutive, 0);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                TunFdLoopAction::BackOff
            );
            assert_eq!(consecutive, 1);

            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Fatal, &mut consecutive),
                TunFdLoopAction::Stop
            );
        }

        #[test]
        fn transient_failures_never_stop_the_unsupervised_pump() {
            let mut consecutive = 0;

            for _ in 0..64 {
                assert_eq!(
                    advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                    TunFdLoopAction::BackOff
                );
            }
            assert_eq!(consecutive, 64);
            assert_eq!(retry_backoff(consecutive), TUN_FD_IO_RETRY_MAX_BACKOFF);

            consecutive = u32::MAX;
            assert_eq!(
                advance_failure_state(TunFdIoDisposition::Retry, &mut consecutive),
                TunFdLoopAction::BackOff
            );
            assert_eq!(consecutive, u32::MAX);
        }

        #[test]
        fn transient_retry_backoff_grows_and_caps_at_one_second() {
            assert_eq!(retry_backoff(0), Duration::from_millis(10));
            assert_eq!(retry_backoff(1), Duration::from_millis(10));
            assert_eq!(retry_backoff(2), Duration::from_millis(20));
            assert_eq!(retry_backoff(7), Duration::from_millis(640));
            assert_eq!(retry_backoff(8), Duration::from_secs(1));
            assert_eq!(retry_backoff(u32::MAX), Duration::from_secs(1));
        }

        #[test]
        fn an_unencodable_packet_is_dropped_not_retried() {
            let malformed = [0x00, 0x00, 0x00, 0x00];
            for format in [TunFdPacketFormat::DarwinUtun, TunFdPacketFormat::RawIp] {
                for packet in [&malformed[..], &[][..]] {
                    // `EncodedPacket` is not `Debug`, so `expect_err` is unavailable here.
                    let error = match EncodedPacket::new(format, packet) {
                        Ok(_) => panic!("a packet with no IP version must not encode"),
                        Err(error) => error,
                    };
                    assert_eq!(io_disposition(&error), TunFdIoDisposition::DropPacket);
                }
            }
        }

        /// The kernel refusing one packet is not the descriptor failing: on a
        /// write it is dropped, where a retry would hold every packet behind
        /// it for ever. A read that fails the same way is still retried.
        #[test]
        fn a_packet_the_kernel_refuses_is_dropped_on_write_alone() {
            for errno in [libc::EINVAL, libc::EMSGSIZE] {
                let error = io::Error::from_raw_os_error(errno);
                assert_eq!(write_io_disposition(&error), TunFdIoDisposition::DropPacket);
                assert_eq!(io_disposition(&error), TunFdIoDisposition::Retry);
            }
            for errno in [libc::ENOBUFS, libc::EIO] {
                let error = io::Error::from_raw_os_error(errno);
                assert_eq!(write_io_disposition(&error), TunFdIoDisposition::Retry);
            }
            let closed = io::Error::from_raw_os_error(libc::EBADF);
            assert_eq!(write_io_disposition(&closed), TunFdIoDisposition::Fatal);
        }

        #[tokio::test]
        async fn a_refused_packet_does_not_hold_the_packets_behind_it() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    1,
                    io::Error::from_raw_os_error(libc::EINVAL),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;
            for _ in 0..2 {
                assert_eq!(
                    write_pending_packet_batch(
                        &mut writer,
                        &tun,
                        TunFdPacketFormat::RawIp,
                        &batch,
                        &mut next_packet,
                        &mut written_packets_in_batch,
                        &mut consecutive_errors,
                    )
                    .await,
                    TunFdLoopAction::Continue
                );
            }
            assert_eq!(writer.written, vec![batch[0].clone(), batch[2].clone()]);
            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 0);
            assert_eq!(stats.outbound_dropped_packets, 1);
        }

        #[tokio::test]
        async fn transient_write_error_retries_the_same_pending_batch() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    0,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 0);
            assert_eq!(consecutive_errors, 1);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(consecutive_errors, 0);
            assert_eq!(writer.calls, vec![batch.clone(), batch.clone()]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batches, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn partial_batch_progress_retries_only_the_unwritten_tail() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    1,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 9;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 1);
            assert_eq!(
                consecutive_errors, 1,
                "write progress resets the backoff state"
            );

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(writer.calls[0], batch);
            assert_eq!(writer.calls[1], batch[1..]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batches, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.tun_fd_write_batch_max_packets, 3);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn invalid_packet_drops_only_it_and_keeps_the_later_tail() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    1,
                    io::Error::new(io::ErrorKind::InvalidData, "malformed packet"),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::DarwinUtun,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, 2, "one packet was written and one dropped");

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::DarwinUtun,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(writer.calls[1], batch[2..]);
            assert_eq!(writer.written, vec![batch[0].clone(), batch[2].clone()]);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 0);
            assert_eq!(stats.tun_fd_write_batch_packets, 2);
            assert_eq!(stats.dropped_packets, 1);
            assert_eq!(stats.outbound_dropped_packets, 1);
        }

        #[tokio::test]
        async fn transient_error_at_the_legacy_cutoff_keeps_the_batch_pending() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([
                ScriptedBatchWrite::Fail(PacketBatchWriteError::new(
                    0,
                    io::Error::from_raw_os_error(libc::ENOBUFS),
                )),
                ScriptedBatchWrite::Complete,
            ]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 63;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::BackOff
            );
            assert_eq!(next_packet, 0);
            assert_eq!(consecutive_errors, 64);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Continue
            );
            assert_eq!(next_packet, batch.len());
            assert_eq!(consecutive_errors, 0);
            assert_eq!(writer.calls, vec![batch.clone(), batch.clone()]);
            assert_eq!(writer.written, batch);

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 1);
            assert_eq!(stats.tun_fd_write_batch_packets, 3);
            assert_eq!(stats.dropped_packets, 0);
            assert_eq!(stats.outbound_dropped_packets, 0);
        }

        #[tokio::test]
        async fn fatal_write_error_counts_the_unwritten_tail_as_dropped() {
            let tun = test_tun_endpoint();
            let batch = test_packet_batch();
            let mut writer = ScriptedPacketBatchWriter::new([ScriptedBatchWrite::Fail(
                PacketBatchWriteError::new(1, io::Error::from_raw_os_error(libc::EBADF)),
            )]);
            let mut next_packet = 0;
            let mut written_packets_in_batch = 0;
            let mut consecutive_errors = 0;

            assert_eq!(
                write_pending_packet_batch(
                    &mut writer,
                    &tun,
                    TunFdPacketFormat::RawIp,
                    &batch,
                    &mut next_packet,
                    &mut written_packets_in_batch,
                    &mut consecutive_errors,
                )
                .await,
                TunFdLoopAction::Stop
            );
            assert_eq!(next_packet, batch.len());

            let stats = tun.stats().await;
            assert_eq!(stats.tun_fd_transient_io_errors, 0);
            assert_eq!(stats.tun_fd_write_batch_packets, 1);
            assert_eq!(stats.dropped_packets, 2);
            assert_eq!(stats.outbound_dropped_packets, 2);
        }

        #[tokio::test]
        async fn outbound_batch_drains_queued_packets_up_to_limit() {
            let tun = TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: TUN_FD_WRITE_BATCH_MAX_PACKETS + 2,
            });
            for index in 0..TUN_FD_WRITE_BATCH_MAX_PACKETS + 1 {
                tun.push_outbound(Bytes::from(vec![0x45, index as u8]))
                    .await
                    .unwrap();
            }

            let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();

            assert_eq!(batch.len(), TUN_FD_WRITE_BATCH_MAX_PACKETS);
            assert_eq!(
                tun.try_poll_outbound().await.unwrap(),
                Some(Bytes::from(vec![
                    0x45,
                    TUN_FD_WRITE_BATCH_MAX_PACKETS as u8
                ]))
            );
        }

        #[tokio::test]
        async fn outbound_batch_reuses_caller_vector_allocation() {
            let tun = TunEndpoint::new(TunConfig {
                mtu: 1500,
                queue_depth: 4,
            });
            let mut batch = Vec::with_capacity(TUN_FD_WRITE_BATCH_MAX_PACKETS);
            let allocation = batch.as_ptr();

            tun.push_outbound(Bytes::from_static(&[0x45, 0x00]))
                .await
                .unwrap();
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();
            batch.clear();
            tun.push_outbound(Bytes::from_static(&[0x60, 0x00]))
                .await
                .unwrap();
            tun.poll_outbound_batch_into(TUN_FD_WRITE_BATCH_MAX_PACKETS, &mut batch)
                .await
                .unwrap();

            assert_eq!(batch.as_ptr(), allocation);
        }

        // ---- Batched read: the pure parts, tested on every OS ----

        #[test]
        fn batch_size_grows_on_a_full_batch_and_stops_at_the_cap() {
            assert_eq!(next_batch_size(4, 4, 64), 8);
            assert_eq!(next_batch_size(8, 8, 64), 16);
            assert_eq!(next_batch_size(32, 32, 64), 64);
            assert_eq!(next_batch_size(64, 64, 64), 64, "capped");
        }

        #[test]
        fn batch_size_halves_below_half_full_and_never_under_the_start() {
            assert_eq!(next_batch_size(64, 31, 64), 32);
            assert_eq!(next_batch_size(8, 3, 64), 4);
            assert_eq!(next_batch_size(4, 1, 64), TUN_FD_READ_BATCH_MIN);
            // Between half and full the size holds.
            assert_eq!(next_batch_size(16, 8, 64), 16);
            assert_eq!(next_batch_size(16, 15, 64), 16);
        }

        #[test]
        fn a_batch_never_exceeds_the_arena_budget() {
            // A 1500-byte MTU gets the platform batch cap.
            assert_eq!(batch_max_for(1505), TUN_FD_READ_BATCH_MAX.min(64));
            // A jumbo MTU cannot fit the cap, so the slot count drops instead.
            let single = MAX_IP_PACKET_SIZE + DARWIN_UTUN_HEADER_LEN + 1;
            let max = batch_max_for(single);
            assert!(max <= TUN_FD_READ_BATCH_ARENA_MAX / single);
            assert!(max * single <= TUN_FD_READ_BATCH_ARENA_MAX);
            assert!(max >= TUN_FD_READ_BATCH_MIN);
            // A slot so large that even the starting batch busts the budget
            // still gets the starting size, so batching is never disabled by
            // a pathological slot size.
            assert_eq!(batch_max_for(usize::MAX / 2), TUN_FD_READ_BATCH_MIN);
        }

        #[test]
        fn the_batch_flag_is_off_only_for_its_off_values() {
            use std::ffi::OsStr;
            assert!(parse_batch_flag(None));
            assert!(parse_batch_flag(Some(OsStr::new("1"))));
            assert!(parse_batch_flag(Some(OsStr::new("true"))));
            assert!(parse_batch_flag(Some(OsStr::new("on"))));
            assert!(!parse_batch_flag(Some(OsStr::new("0"))));
            assert!(!parse_batch_flag(Some(OsStr::new("false"))));
            assert!(!parse_batch_flag(Some(OsStr::new("off"))));
            assert!(!parse_batch_flag(Some(OsStr::new(""))));
        }

        #[test]
        fn utun_pending_packets_follow_the_receive_buffer() {
            // A 64 KiB buffer with a 1500-byte MTU: 64k/8*7/1504 = 38.
            assert_eq!(derive_utun_pending_packets(64 * 1024, 1500), 38);
            // A 512 KiB buffer derives 305, clamped to the 64 ceiling.
            assert_eq!(derive_utun_pending_packets(512 * 1024, 1500), 64);
            // An 8 MiB buffer is clamped too.
            assert_eq!(derive_utun_pending_packets(8 << 20, 1500), 64);
            // A buffer smaller than one packet still asks for one.
            assert_eq!(derive_utun_pending_packets(0, 1500), 1);
            assert_eq!(derive_utun_pending_packets(1000, 1500), 1);
        }

        /// Lays `packets` out in `stride`-sized slots, the way a batch read
        /// would, and returns the arena plus the slot descriptors.
        fn staged_batch_arena(
            packets: &[(usize, bool)],
            stride: usize,
        ) -> (BytesMut, Vec<BatchSlot>) {
            let mut arena = BytesMut::with_capacity(packets.len() * stride + 1);
            let mut slots = Vec::new();
            for (len, truncated) in packets {
                let start = arena.len();
                arena.resize(start + stride, 0);
                for (index, byte) in arena[start..start + *len].iter_mut().enumerate() {
                    *byte = index as u8;
                }
                slots.push(BatchSlot {
                    len: *len,
                    truncated: *truncated,
                });
            }
            (arena, slots)
        }

        #[test]
        fn carving_a_batch_yields_one_untouched_packet_per_slot() {
            let stride = 64;
            let packets = [(10, false), (20, false), (30, false)];
            let (mut arena, slots) = staged_batch_arena(&packets, stride);
            let mut out = Vec::new();
            carve_batch(&mut arena, &slots, stride, 0, &mut out);

            assert_eq!(out.len(), 3);
            assert_eq!(out[0].len(), 10);
            assert_eq!(out[1].len(), 20);
            assert_eq!(out[2].len(), 30);
            assert_eq!(&out[1][..4], &[0, 1, 2, 3]);
            assert!(arena.is_empty(), "the whole batch was carved out");
        }

        #[test]
        fn carving_strips_the_utun_header_without_copying_the_payload() {
            let stride = 32;
            let mut framed = vec![0, 0, 0, libc::AF_INET as u8];
            framed.extend_from_slice(&[0x45, 0x11, 0x22, 0x33]);
            let mut arena = BytesMut::with_capacity(stride);
            arena.extend_from_slice(&framed);
            arena.resize(stride, 0);
            let slots = [BatchSlot {
                len: framed.len(),
                truncated: false,
            }];

            let mut out = Vec::new();
            carve_batch(&mut arena, &slots, stride, DARWIN_UTUN_HEADER_LEN, &mut out);

            assert_eq!(&out[0][..], &[0x45, 0x11, 0x22, 0x33]);
        }

        #[test]
        fn a_truncated_slot_is_dropped_even_when_it_looks_like_a_packet() {
            let stride = 32;
            let (mut arena, slots) = staged_batch_arena(&[(32, true), (32, false)], stride);
            let mut out = Vec::new();
            carve_batch(&mut arena, &slots, stride, 0, &mut out);
            assert_eq!(out.len(), 1, "only the untruncated slot survives");
        }

        #[test]
        fn a_slot_with_no_payload_past_the_header_is_dropped() {
            let stride = 16;
            // Empty, and header-only: neither carries a packet.
            let packets = [(0, false), (4, false), (8, false)];
            let (mut arena, slots) = staged_batch_arena(&packets, stride);
            let mut out = Vec::new();
            carve_batch(&mut arena, &slots, stride, DARWIN_UTUN_HEADER_LEN, &mut out);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].len(), 4);
        }

        #[test]
        fn a_short_batch_carves_only_the_slots_the_kernel_filled() {
            // `recvmsg_x` returns the count it filled; the reader slices the
            // slot list to it, so carving sees a prefix and leaves the rest.
            let stride = 32;
            let (mut arena, slots) = staged_batch_arena(&[(10, false), (10, false)], stride);
            let mut out = Vec::new();
            carve_batch(&mut arena, &slots[..1], stride, 0, &mut out);
            assert_eq!(out.len(), 1);
            // One slot's stride was consumed; the unfilled slot stays.
            assert_eq!(arena.len(), stride);
        }

        #[test]
        fn an_oversized_datagram_is_carved_at_the_slot_size() {
            // `msg_datalen` can exceed the slot when the kernel did not flag
            // truncation; the packet is cut to the slot so the extra byte is
            // still what makes it rejectable downstream.
            let stride = 8;
            let mut arena = BytesMut::with_capacity(stride);
            arena.resize(stride, 0x45);
            let slots = [BatchSlot {
                len: 40,
                truncated: false,
            }];
            let mut out = Vec::new();
            carve_batch(&mut arena, &slots, stride, 0, &mut out);
            assert_eq!(out[0].len(), stride);
        }

        #[test]
        fn carving_an_empty_batch_does_nothing() {
            let mut arena = BytesMut::with_capacity(8);
            arena.resize(8, 0);
            let mut out = Vec::new();
            carve_batch(&mut arena, &[], 8, 0, &mut out);
            assert!(out.is_empty());
            assert_eq!(arena.len(), 8);
        }

        #[test]
        fn a_raw_ip_reader_never_batches() {
            let reader = PacketReader::new(TunFdPacketFormat::RawIp, 1500);
            #[cfg(target_vendor = "apple")]
            assert!(reader.batch.is_none());
            assert_eq!(reader.header_len, 0);
        }

        /// `recvmsg_x` works on a `socketpair(AF_UNIX, SOCK_DGRAM)`, which is
        /// the same datagram shape as a utun fd, so the syscall half of the
        /// batch can be exercised without a tunnel or privileges.
        #[cfg(target_vendor = "apple")]
        #[tokio::test]
        async fn a_batched_read_of_a_dgram_socketpair_returns_every_datagram() {
            use std::os::fd::FromRawFd;

            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a two-element array the call fills in.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
            // SAFETY: `socketpair` returned two descriptors this test owns.
            let sender = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
            // SAFETY: as above for the second descriptor.
            let receiver = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
            set_nonblocking(receiver.as_raw_fd()).unwrap();

            // Each datagram is framed with the 4-byte utun header, which the
            // batch must strip exactly as the single-packet path does.
            let payloads: [&[u8]; 3] = [&[1, 2, 3, 4], &[5, 6, 7], &[8, 9]];
            for payload in payloads {
                let mut framed = vec![0, 0, 0, libc::AF_INET as u8];
                framed.extend_from_slice(payload);
                // SAFETY: the descriptor is open and `framed` is a live slice.
                let written = unsafe {
                    libc::write(sender.as_raw_fd(), framed.as_ptr().cast(), framed.len())
                };
                assert_eq!(written, framed.len() as isize);
            }

            // RawIp here so the utun-only socket options are not attempted on
            // a plain dgram socket; the reader's format is what selects
            // batching, and it is set to utun below.
            let reader_fd = TunFd::new(
                TunFdConfig::new(
                    receiver.as_raw_fd(),
                    TunFdPacketFormat::RawIp,
                    TunFdClosePolicy::Borrowed,
                ),
                1500,
            )
            .unwrap();
            // SAFETY: the duplicate lives until `reader_fd` drops, which the
            // registration below keeps as its owner.
            let afd = unsafe { AsyncFd::register(reader_fd) }.unwrap();

            let mut reader = PacketReader::new(TunFdPacketFormat::DarwinUtun, 1500);
            if reader.batch.is_none() {
                // `SEGUE_TUN_BATCH` is off in this environment; the syscall
                // path is not reachable, and the pure tests still cover the
                // carving.
                return;
            }

            let mut out = Vec::new();
            let count = reader.read_into(&afd, &mut out).await.unwrap();
            assert_eq!(count, payloads.len());
            assert_eq!(out.len(), payloads.len());
            for (packet, payload) in out.iter().zip(payloads) {
                assert_eq!(&packet[..], payload);
            }
        }

        #[test]
        fn an_oversized_frame_is_not_batched_and_a_closed_gate_writes_nothing() {
            assert_eq!(TUN_FD_SEND_FRAME_LIMIT, 4092);
            assert_eq!(TUN_FD_SEND_BATCH_MAX, 64);

            let small = 100;
            let big = TUN_FD_SEND_FRAME_LIMIT + 1;
            // The gate refusing room is not a single write, whatever the frame
            // size: that write is the syscall that leaks a cluster.
            assert_eq!(plan_send(small, 4, 0), PlannedSend::Wait);
            assert_eq!(plan_send(big, 0, 0), PlannedSend::Wait);
            assert_eq!(plan_send(big, 0, 3), PlannedSend::Single);
            assert_eq!(plan_send(small, 3, 10), PlannedSend::Batch(3));
            assert_eq!(plan_send(small, 80, 100), PlannedSend::Batch(64));
            assert_eq!(plan_send(small, 10, 4), PlannedSend::Batch(4));
            // A small frame the batcher rejected (no IP version) is not sent.
            assert_eq!(plan_send(small, 0, 5), PlannedSend::Wait);
            assert_eq!(
                plan_send(TUN_FD_SEND_FRAME_LIMIT, 1, 1),
                PlannedSend::Batch(1),
                "a frame that fills the 4 KiB cluster exactly is still batched"
            );
        }

        #[test]
        fn batchable_count_stops_at_an_oversized_or_unversioned_frame() {
            let small = Bytes::from_static(&[0x45, 1]);
            let v6 = Bytes::from_static(&[0x60, 1]);
            let bad = Bytes::from_static(&[0x00, 1]);
            let exact = Bytes::from(vec![0x45; TUN_FD_SEND_FRAME_LIMIT]);
            let big = Bytes::from(vec![0x45; TUN_FD_SEND_FRAME_LIMIT + 1]);

            assert_eq!(
                batchable_count(&[small.clone(), v6.clone(), big.clone(), small.clone()], 10),
                2
            );
            assert_eq!(batchable_count(&[exact], 10), 1);
            assert_eq!(batchable_count(&[big, small.clone()], 10), 0);
            assert_eq!(batchable_count(&[small.clone(), bad, v6], 10), 1);
            assert_eq!(batchable_count(&vec![small; 80], 100), 80);
            assert_eq!(batchable_count(&[], 10), 0);
        }

        #[test]
        fn the_gate_stops_at_the_high_water_and_reopens_when_the_host_drains() {
            let mut gate = UtunChainGate::inactive();
            gate.note_submitted(10_000);
            assert_eq!(gate.admit(7, GateSample::NotDue), 7);
            assert_eq!(gate.poll_blocked(3, GateSample::Fresh(None)), 3);

            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(10);
            // Under the high water a sample is not applied, so a counter that
            // has already caught up does not lower the estimate yet.
            assert_eq!(gate.admit(5, GateSample::Fresh(Some(10))), 5);
            assert_eq!(gate.estimate(), 10);

            gate.note_submitted(374);
            assert_eq!(gate.estimate(), 384);
            // Not due: the draining counter is ignored and the gate stays shut.
            assert_eq!(gate.admit(8, GateSample::NotDue), 0);
            assert_eq!(gate.estimate(), 384);
            // Due: the host has taken everything submitted, so the chain is empty.
            assert_eq!(gate.admit(8, GateSample::Fresh(Some(384))), 8);
            assert_eq!(gate.estimate(), 0);
        }

        #[test]
        fn idle_polls_arm_a_probe_that_stays_under_the_leaking_limit() {
            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(384);
            for _ in 0..15 {
                assert_eq!(gate.poll_blocked(10, GateSample::Fresh(Some(0))), 0);
            }
            // The 16th idle sample lets a probe through, and no more than the
            // eight-packet probe.
            assert_eq!(gate.poll_blocked(10, GateSample::Fresh(Some(0))), 8);

            // Movement clears the probe and reopens from the new estimate.
            assert_eq!(gate.poll_blocked(10, GateSample::Fresh(Some(20))), 10);
            assert!(gate.estimate() < UTUN_INPUT_CHAIN_HIGH_WATER);

            // One under the limit the probe is a single packet; at the limit
            // it is nothing. 512 is where the kernel leaks.
            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(510);
            for _ in 0..16 {
                let _ = gate.poll_blocked(10, GateSample::Fresh(Some(0)));
            }
            assert_eq!(gate.admit(10, GateSample::NotDue), 1);

            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(511);
            for _ in 0..16 {
                assert_eq!(gate.poll_blocked(10, GateSample::Fresh(Some(0))), 0);
            }
            assert_eq!(gate.admit(10, GateSample::NotDue), 0);
        }

        #[test]
        fn enospc_realigns_the_estimate_to_just_over_the_limit() {
            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(10);
            gate.note_enospc(Some(4));
            assert_eq!(gate.estimate(), UTUN_INPUT_CHAIN_LIMIT + 1);
            assert_eq!(gate.admit(5, GateSample::NotDue), 0);

            // A sample that has not caught up keeps the gate shut. One that
            // has, reopens it. The figures follow the baseline `note_enospc`
            // installs: inflight = 517 - consumed, and 383 is the first
            // estimate with room.
            assert_eq!(gate.admit(5, GateSample::Fresh(Some(133))), 0);
            assert_eq!(gate.estimate(), 384);
            assert_eq!(gate.admit(5, GateSample::Fresh(Some(134))), 1);
            assert_eq!(gate.estimate(), 383);

            // No counter at all still forces the estimate over the limit.
            let mut gate = UtunChainGate::armed(0);
            gate.note_submitted(3);
            gate.note_enospc(None);
            assert_eq!(gate.estimate(), UTUN_INPUT_CHAIN_LIMIT + 1);
            assert_eq!(gate.admit(1, GateSample::NotDue), 0);

            // An inactive gate has nothing to realign and does not close.
            let mut gate = UtunChainGate::inactive();
            gate.note_enospc(Some(0));
            assert_eq!(gate.admit(4, GateSample::NotDue), 4);
        }

        #[test]
        fn a_partial_send_commits_only_what_was_accepted_and_eagain_commits_nothing() {
            assert_eq!(account_send(4, Ok(2)), SendAccount::Progress { done: 2 });
            assert_eq!(account_send(4, Ok(4)), SendAccount::Progress { done: 4 });
            // A count past the submission cannot commit a packet that was not
            // handed over, and a zero count is not progress.
            assert_eq!(account_send(2, Ok(9)), SendAccount::Progress { done: 2 });
            assert_eq!(account_send(4, Ok(0)), SendAccount::RetrySame);

            assert_eq!(account_send(3, Err(libc::EAGAIN)), SendAccount::RetrySame);
            assert_eq!(
                account_send(3, Err(libc::EWOULDBLOCK)),
                SendAccount::RetrySame
            );
            assert_eq!(account_send(3, Err(libc::EINTR)), SendAccount::RetrySame);
            // `ENOBUFS` sent nothing. More than one message is retried
            // smaller; the last message is retried whole, not dropped.
            assert_eq!(
                account_send(3, Err(libc::ENOBUFS)),
                SendAccount::RetrySmaller
            );
            assert_eq!(account_send(1, Err(libc::ENOBUFS)), SendAccount::RetrySame);
            assert_eq!(
                account_send(2, Err(libc::EMSGSIZE)),
                SendAccount::RetrySmaller
            );
            assert_eq!(account_send(1, Err(libc::EMSGSIZE)), SendAccount::DropOne);
            assert_eq!(account_send(1, Err(libc::EINVAL)), SendAccount::DropOne);
            // A multi-message `EINVAL` may have delivered a prefix. The whole
            // submission is consumed so that prefix is not sent again.
            assert_eq!(
                account_send(3, Err(libc::EINVAL)),
                SendAccount::Consumed { enospc: false }
            );
            assert_eq!(
                account_send(4, Err(libc::ENOSPC)),
                SendAccount::Consumed { enospc: true }
            );
            assert_eq!(
                account_send(4, Err(libc::EIO)),
                SendAccount::Consumed { enospc: false }
            );
            assert_eq!(account_send(4, Err(libc::EBADF)), SendAccount::Fatal);
            assert_eq!(account_send(1, Err(libc::ENOTCONN)), SendAccount::Fatal);
        }

        /// Walks the same decisions `sendmsg_x_accounted` makes, over one
        /// queue, and checks every packet is committed once. This is the
        /// partial-batch / `EAGAIN` / `ENOBUFS` contract without a socket.
        #[test]
        fn replaying_a_short_batch_then_eagain_then_enobufs_neither_drops_nor_duplicates() {
            let total = 5;
            // Submission sizes the loop would have chosen, and what the
            // kernel said back. A shrink halves the next submission.
            let steps = [
                (4, Ok(2)),
                (3, Err(libc::EAGAIN)),
                (3, Err(libc::ENOBUFS)),
                (2, Ok(2)),
                (1, Ok(1)),
            ];
            let mut cursor = 0;
            let mut committed = Vec::new();
            for (submitted, result) in steps {
                assert!(submitted <= total - cursor);
                match account_send(submitted, result) {
                    SendAccount::Progress { done } => {
                        committed.extend(cursor..cursor + done);
                        cursor += done;
                    }
                    SendAccount::RetrySame | SendAccount::RetrySmaller => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(cursor, total);
            assert_eq!(committed, (0..total).collect::<Vec<_>>());
        }

        #[test]
        fn the_interface_counter_is_read_from_the_matching_ifinfo2_message() {
            fn message(index: u16, ipackets: u64, msglen: usize) -> Vec<u8> {
                let mut msg = vec![0u8; msglen];
                msg[0..2].copy_from_slice(&(msglen as u16).to_le_bytes());
                if msglen > IF_MSGHDR2_TYPE {
                    msg[IF_MSGHDR2_TYPE] = RTM_IFINFO2;
                }
                if msglen >= IF_MSGHDR2_INDEX + 2 {
                    msg[IF_MSGHDR2_INDEX..IF_MSGHDR2_INDEX + 2]
                        .copy_from_slice(&index.to_le_bytes());
                }
                if msglen >= IF_MSGHDR2_IPACKETS + 8 {
                    msg[IF_MSGHDR2_IPACKETS..IF_MSGHDR2_IPACKETS + 8]
                        .copy_from_slice(&ipackets.to_le_bytes());
                }
                msg
            }

            // A short message is skipped rather than read past its end, and
            // the counter comes from the matching message only.
            let mut rib = message(2, 11, 20);
            rib.extend(message(7, 99, IF_MSGHDR2_SIZE));
            rib.extend(message(8, 5, IF_MSGHDR2_SIZE));
            assert_eq!(utun_ipackets_from_rib(&rib, 7), Some(99));
            assert_eq!(utun_ipackets_from_rib(&rib, 8), Some(5));
            assert_eq!(utun_ipackets_from_rib(&rib, 2), None);
            // A zero length ends the walk, so a later message is invisible.
            let mut stalled = message(3, 4, IF_MSGHDR2_SIZE);
            stalled.extend_from_slice(&[0, 0]);
            stalled.extend(message(1, 9, IF_MSGHDR2_SIZE));
            assert_eq!(utun_ipackets_from_rib(&stalled, 1), None);
            assert_eq!(utun_ipackets_from_rib(&stalled, 3), Some(4));
        }

        /// `sendmsg_x` on a `socketpair(AF_UNIX, SOCK_DGRAM)` is the same
        /// datagram shape as a utun fd, so the write syscall can be exercised
        /// without a tunnel. More packets than one batch, plus one frame
        /// bigger than the path MTU but still inside the 4 KiB cluster (a
        /// unix datagram will not carry the oversized-frame case; that one
        /// is the planner test above), must all arrive in order with the
        /// utun family header and nothing duplicated.
        #[cfg(target_vendor = "apple")]
        #[tokio::test]
        async fn a_batched_write_of_a_dgram_socketpair_delivers_every_datagram() {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: `fds` is a two-element array the call fills in.
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
            // SAFETY: `socketpair` returned two descriptors this test owns.
            let sender = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            // SAFETY: as above for the second descriptor.
            let receiver = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            set_nonblocking(sender.as_raw_fd()).unwrap();
            set_nonblocking(receiver.as_raw_fd()).unwrap();
            let buffer: libc::c_int = 1 << 20;
            let buffer_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
                // SAFETY: `buffer` is a live `c_int` of the length passed.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&buffer as *const libc::c_int).cast(),
                        buffer_len,
                    );
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        (&buffer as *const libc::c_int).cast(),
                        buffer_len,
                    );
                }
            }

            // RawIp so utun socket options are not attempted on a unix
            // socket. The writer's format is what selects batching.
            let writer_fd = TunFd::new(
                TunFdConfig::new(
                    sender.as_raw_fd(),
                    TunFdPacketFormat::RawIp,
                    TunFdClosePolicy::Borrowed,
                ),
                1500,
            )
            .unwrap();
            // SAFETY: the duplicate lives until `writer_fd` drops, which the
            // registration below keeps as its owner.
            let afd = unsafe { AsyncFd::register(writer_fd) }.unwrap();
            let mut state = UtunSendState::new(afd.as_raw_fd(), TunFdPacketFormat::DarwinUtun);
            if !state.enabled {
                // `SEGUE_TUN_BATCH` is off; the pure tests still cover the gate.
                return;
            }

            let mut packets = Vec::new();
            // One past the batch cap, so the run takes two `sendmsg_x` calls.
            for byte in 0..TUN_FD_SEND_BATCH_MAX as u8 + 6 {
                packets.push(Bytes::from(vec![0x45, byte, byte ^ 0x5a]));
            }
            // Still inside the cluster limit, so it is batched, and inside the
            // unix datagram limit, so the socket can actually carry it.
            let mut medium = vec![0x45; 1500];
            medium[1] = 0xcd;
            packets.push(Bytes::from(medium));

            write_utun_send_batch(&afd, &packets, &mut state)
                .await
                .unwrap();

            let mut got = Vec::new();
            let mut buf = vec![0u8; 2048];
            loop {
                // SAFETY: `buf` is a live buffer and the descriptor is open.
                let read =
                    unsafe { libc::read(receiver.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if read < 0 {
                    let error = io::Error::last_os_error();
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::WouldBlock,
                        "unexpected read error: {error}"
                    );
                    break;
                }
                assert!(read > 0);
                got.push(buf[..read as usize].to_vec());
            }
            assert_eq!(got.len(), packets.len());
            let header = [0, 0, 0, libc::AF_INET as u8];
            for (frame, packet) in got.iter().zip(&packets) {
                assert_eq!(&frame[..header.len()], &header);
                assert_eq!(&frame[header.len()..], packet.as_ref());
            }
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use std::io;
    use std::sync::Arc;

    use segue_tun::TunEndpoint;

    use super::TunFdConfig;

    pub struct TunFdRuntime;

    impl TunFdRuntime {
        pub fn start(config: TunFdConfig, _tun: Arc<TunEndpoint>) -> io::Result<Self> {
            config.close_if_owned();
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fd-backed TUN is only supported on Unix platforms",
            ))
        }

        pub async fn stop(self) {}
    }
}

pub use platform::TunFdRuntime;
