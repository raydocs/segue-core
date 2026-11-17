use super::*;
use crate::AnyTlsOutboundSettings;
use std::time::Duration;

impl Parser<'_> {
    /// `anytls` settings: one server reached over TLS, with sing-box's field
    /// names. Xray-core has no AnyTLS, so nothing here is Xray compatibility;
    /// the parser is fail-closed like every other outbound's.
    pub(super) fn parse_anytls_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<AnyTlsOutboundSettings> {
        let path = format!("$.outbounds[{index}].settings");
        let Some(settings) = outbound.get("settings").filter(|v| v.is_object()) else {
            self.error(path, "AnyTLS settings must be an object");
            return None;
        };
        self.reject_unknown_fields(settings, &path, &surface::ANYTLS);

        let Some(address) = self.string_at(settings, "address") else {
            self.error(
                format!("{path}.address"),
                "AnyTLS requires a server address",
            );
            return None;
        };
        let address = normalize_xray_address_text(address);
        if address.is_empty()
            || address.len() > 255
            || address.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            self.error(format!("{path}.address"), "invalid AnyTLS server address");
            return None;
        }
        let address = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip);
        let port = self.u16_at(settings, "port", format!("{path}.port"))?;
        if port == 0 {
            self.error(format!("{path}.port"), "AnyTLS port must be nonzero");
        }
        let Some(password) = self.string_at(settings, "password") else {
            self.error(format!("{path}.password"), "AnyTLS requires a password");
            return None;
        };
        if password.is_empty() {
            self.error(
                format!("{path}.password"),
                "AnyTLS password must not be empty",
            );
            return None;
        }
        let password = zeroize::Zeroizing::new(password.to_owned());

        // sing-box spells both as Go durations; a bare number is nanoseconds,
        // as `badoption.Duration` reads it. An absent or zero value takes the
        // reference's thirty-second floor when the pool is built.
        let idle_session_check_interval =
            self.duration_field(settings, "idle_session_check_interval", &path)?;
        let idle_session_timeout = self.duration_field(settings, "idle_session_timeout", &path)?;
        // `optional_u32_at` reports a malformed value itself and answers
        // `None` for both "absent" and "malformed".
        let min_idle_session = self
            .optional_u32_at(
                settings,
                "min_idle_session",
                format!("{path}.min_idle_session"),
            )
            // A malformed value already recorded an error, which fails the
            // parse; treating it as zero here changes nothing.
            .map_or(0, |value| value as usize);
        // The pool keeps at most eight sessions, so a larger minimum can
        // never be honoured; refuse it rather than silently keeping fewer.
        if min_idle_session > crate::MAX_ANYTLS_IDLE_SESSIONS {
            self.error(
                format!("{path}.min_idle_session"),
                format!(
                    "min_idle_session must be 0..={}",
                    crate::MAX_ANYTLS_IDLE_SESSIONS
                ),
            );
            return None;
        }
        let client_metadata = match settings.get("client_metadata") {
            None => None,
            Some(Value::String(value)) => {
                if value.chars().any(|c| c == '\n' || c == '\r' || c == '=') {
                    self.error(
                        format!("{path}.client_metadata"),
                        "client_metadata must not contain newlines or `=`",
                    );
                    return None;
                }
                (!value.is_empty()).then(|| value.clone())
            }
            Some(_) => {
                self.error(
                    format!("{path}.client_metadata"),
                    "field `client_metadata` must be a string",
                );
                return None;
            }
        };
        let level = self
            .optional_u32_at(settings, "level", format!("{path}.level"))
            .unwrap_or_default();
        if level > 255 {
            self.error(format!("{path}.level"), "AnyTLS level must be 0..255");
        }
        Some(AnyTlsOutboundSettings {
            server: address,
            port,
            password,
            idle_session_check_interval: idle_session_check_interval.unwrap_or_default(),
            idle_session_timeout: idle_session_timeout.unwrap_or_default(),
            min_idle_session,
            client_metadata,
            level,
        })
    }

    /// One duration field: a Go duration string, or a number of nanoseconds.
    /// Returns `None` when absent; errors when malformed.
    fn duration_field(
        &mut self,
        value: &Value,
        key: &str,
        base_path: &str,
    ) -> Option<Option<Duration>> {
        let path = format!("{base_path}.{key}");
        match value.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(raw)) => match parse_xray_duration(raw) {
                Some(duration) if !duration.is_zero() => Some(Some(duration)),
                Some(_) => {
                    self.error(path, format!("field `{key}` must be a positive duration"));
                    None
                }
                None => {
                    self.error(path, format!("field `{key}` must be a Go duration"));
                    None
                }
            },
            Some(Value::Number(raw)) => match raw.as_u64() {
                // `time.Duration` is nanoseconds.
                Some(nanoseconds) if nanoseconds > 0 => {
                    Some(Some(Duration::from_nanos(nanoseconds)))
                }
                _ => {
                    self.error(path, format!("field `{key}` must be a positive duration"));
                    None
                }
            },
            Some(_) => {
                self.error(path, format!("field `{key}` must be a duration"));
                None
            }
        }
    }

    /// AnyTLS has no plaintext mode: the password digest would be visible and
    /// the framing unauthenticated. Both the parser and the outbound refuse a
    /// public server without TLS, and the parser refuses it everywhere.
    pub(super) fn validate_anytls_stream(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        index: usize,
    ) {
        let OutboundSettings::AnyTls(_) = settings else {
            return;
        };
        if stream.security == StreamSecurity::None {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "AnyTLS requires TLS or REALITY",
            );
        }
        if let StreamSecurity::Tls(tls) = &stream.security {
            if tls.allow_insecure {
                self.error(
                    format!("$.outbounds[{index}].streamSettings.tlsSettings.allowInsecure"),
                    "AnyTLS requires certificate verification",
                );
            }
        }
    }
}
