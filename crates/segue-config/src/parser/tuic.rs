use super::*;
use crate::{TuicCongestionControl, TuicSettings, TuicUdpRelayMode};
use std::time::Duration;

impl Parser<'_> {
    pub(super) fn parse_tuic_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<TuicSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "TUIC settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::TUIC);
        let Some(server) = self.string_at(settings, "server") else {
            self.error(format!("{path}.server"), "TUIC requires a server");
            return None;
        };
        let server = normalize_xray_address_text(server);
        if server.is_empty()
            || server.len() > 255
            || server
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            self.error(format!("{path}.server"), "invalid TUIC server");
            return None;
        }
        let server = server
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(server.into()), TargetAddr::Ip);
        let port = self.u16_at(settings, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "TUIC port must be nonzero");
        }
        // TUIC takes an RFC 4122 UUID, not Xray's custom user-id aliases.
        let uuid = self
            .string_at(settings, "uuid")
            .and_then(|raw| uuid::Uuid::parse_str(raw).ok());
        let Some(uuid) = uuid else {
            self.error(format!("{path}.uuid"), "TUIC requires an RFC 4122 UUID");
            return None;
        };
        let Some(password) = self.string_at(settings, "password") else {
            self.error(format!("{path}.password"), "TUIC requires a password");
            return None;
        };
        if password.is_empty() || password.len() > 4096 {
            self.error(
                format!("{path}.password"),
                "TUIC password must contain 1..=4096 UTF-8 bytes",
            );
            return None;
        }
        let congestion_control = match settings.get("congestion_control") {
            None | Some(Value::Null) => TuicCongestionControl::default(),
            Some(Value::String(value)) => match value.as_str() {
                "cubic" => TuicCongestionControl::Cubic,
                "new_reno" => TuicCongestionControl::NewReno,
                "bbr" => TuicCongestionControl::Bbr,
                _ => {
                    self.error(
                        format!("{path}.congestion_control"),
                        "TUIC congestion_control must be cubic, new_reno or bbr",
                    );
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{path}.congestion_control"),
                    "TUIC congestion_control must be a string",
                );
                return None;
            }
        };
        let udp_relay_mode = match settings.get("udp_relay_mode") {
            None | Some(Value::Null) => TuicUdpRelayMode::default(),
            Some(Value::String(value)) => match value.as_str() {
                "native" => TuicUdpRelayMode::Native,
                "quic" => TuicUdpRelayMode::Quic,
                _ => {
                    self.error(
                        format!("{path}.udp_relay_mode"),
                        "TUIC udp_relay_mode must be native or quic",
                    );
                    return None;
                }
            },
            Some(_) => {
                self.error(
                    format!("{path}.udp_relay_mode"),
                    "TUIC udp_relay_mode must be a string",
                );
                return None;
            }
        };
        let zero_rtt_handshake = match settings.get("zero_rtt_handshake") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                self.error(
                    format!("{path}.zero_rtt_handshake"),
                    "TUIC zero_rtt_handshake must be a boolean",
                );
                return None;
            }
        };
        let heartbeat_path = format!("{path}.heartbeat");
        let heartbeat = match settings.get("heartbeat") {
            None | Some(Value::Null) => Duration::from_secs(10),
            Some(Value::String(value)) => match parse_xray_duration(value) {
                Some(duration) if !duration.is_zero() => duration,
                _ => {
                    self.error(heartbeat_path, "TUIC heartbeat must be a positive duration");
                    return None;
                }
            },
            // sing-box's `badoption.Duration`, like a Go time.Duration number.
            Some(Value::Number(value)) if value.as_u64().is_some_and(|value| value > 0) => {
                Duration::from_nanos(value.as_u64().expect("checked positive integer"))
            }
            Some(_) => {
                self.error(heartbeat_path, "TUIC heartbeat must be a positive duration");
                return None;
            }
        };
        Some(TuicSettings {
            server,
            port,
            uuid,
            password: zeroize::Zeroizing::new(password.to_owned()),
            congestion_control,
            udp_relay_mode,
            zero_rtt_handshake,
            heartbeat,
        })
    }

    pub(super) fn validate_tuic_stream(
        &mut self,
        settings: &OutboundSettings,
        stream: &mut StreamSettings,
        chained: bool,
        index: usize,
    ) {
        let OutboundSettings::Tuic(_) = settings else {
            return;
        };
        let StreamSecurity::Tls(tls) = &mut stream.security else {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "TUIC requires TLS 1.3 over QUIC",
            );
            return;
        };
        if stream.network != Network::Udp
            || !matches!(stream.transport, StreamTransport::Raw)
            || chained
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings"),
                "TUIC owns its UDP QUIC transport; use network udp, raw security-only settings, and no chaining",
            );
        }
        // As with the other QUIC carriers, a TCP ClientHello fingerprint is
        // not applied to QUIC's unshaped TLS 1.3 handshake.
        tls.fingerprint = None;
        if tls.alpn.is_empty() {
            tls.alpn.push("h3".into());
        }
        if stream.tcp_fragment.is_some()
            || stream.tcp_header_custom.is_some()
            || stream.tcp_sudoku.is_some()
            || stream.tcp_xmc.is_some()
            || stream.udp_header_custom.is_some()
            || stream.udp_sudoku.is_some()
            || stream.udp_xdns.is_some()
            || stream.udp_realm.is_some()
            || stream.udp_xicmp.is_some()
            || stream.udp_noise.is_some()
            || stream.udp_salamander.is_some()
            || stream.quic_params.is_some()
            || tls.ech_config_list.is_some()
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings"),
                "TUIC uses its own QUIC configuration; masks, quicParams and ECH are unsupported",
            );
        }
    }
}
