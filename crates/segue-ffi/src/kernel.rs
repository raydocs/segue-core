//! ABI 1.18 kernel-mode C types and capability declarations.
//!
//! The C entry points arrive with the behavior specified for stages 2–5;
//! this module deliberately exports none of them. Full paths leave feature-off
//! imports in `lib.rs` unchanged.

/// Kill-switch and event changes are published in these fixed ABI values.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayKernelEventKind {
    PostureChanged = 0,
    ExitChanged = 1,
    PolicyChanged = 2,
    Revoked = 3,
    ControlRefused = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayKernelPosture {
    Connecting = 0,
    Connected = 1,
    Reconnecting = 2,
    Error = 3,
    Disconnected = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrayKernelEvent {
    /// Caller allocation size; an ABI-major-1 writer preserves it.
    pub struct_size: usize,
    pub kind: XrayKernelEventKind,
    pub value: u64,
    /// Host-independent monotonic milliseconds, for ordering only.
    pub timestamp_ms: u64,
}

/// First-generation kernel counters. Future fields are append-only.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct XrayKernelStats {
    pub struct_size: usize,
    pub tcp_accepted: u64,
    pub tcp_refused_policy: u64,
    pub udp_refused_policy: u64,
    pub udp_refused_quic: u64,
    pub fakeip_entries: u64,
    pub fakeip_refusals: u64,
    pub dns_cache_entries: u64,
    pub dns_upstream_queries: u64,
    pub session_opens: u64,
    pub session_resumes: u64,
    pub session_carrier_failures: u64,
    pub policy_installs: u64,
    pub policy_refusals: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use segue_kernel::killswitch::Posture;

    #[test]
    fn kernel_posture_numeric_abi_matches_the_kernel() {
        for (posture, ffi) in [
            (Posture::Connecting, XrayKernelPosture::Connecting),
            (Posture::Connected, XrayKernelPosture::Connected),
            (Posture::Reconnecting, XrayKernelPosture::Reconnecting),
            (Posture::Error, XrayKernelPosture::Error),
            (Posture::Disconnected, XrayKernelPosture::Disconnected),
        ] {
            assert_eq!(posture as u64, ffi as u64);
        }
    }

    #[test]
    fn kernel_event_numeric_abi_is_fixed() {
        for (actual, expected) in [
            (XrayKernelEventKind::PostureChanged as u32, 0),
            (XrayKernelEventKind::ExitChanged as u32, 1),
            (XrayKernelEventKind::PolicyChanged as u32, 2),
            (XrayKernelEventKind::Revoked as u32, 3),
            (XrayKernelEventKind::ControlRefused as u32, 4),
        ] {
            assert_eq!(actual, expected);
        }
    }
}
