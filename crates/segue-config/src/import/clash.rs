//! Clash/mihomo YAML conversion.
//!
//! Field names follow mihomo's `proxy:"..."` struct tags
//! (`adapter/outbound/*.go`) and its group tags (`adapter/outboundgroup`).
//! Everything not carried is reported as a warning rather than dropped
//! silently; see the module docs on [`super`] for the supported subset.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use super::{
    base_config, block_outbound, boolean, direct_outbound, dns_object, dns_server_string,
    fake_ip_object, fake_ip_pool, grpc_settings, header_pairs, host_header, httpupgrade_settings,
    object, outbound, plaintext_server_exempt, port, reality_object, stream_settings, string,
    string_list, tls_object, ws_settings, xhttp_settings, Ctx, ImportError,
};

/// `DIRECT` and `REJECT`, Clash's two built-in targets.
const DIRECT: &str = "DIRECT";
const REJECT: &str = "REJECT";

pub(super) fn convert(bytes: &[u8], ctx: &mut Ctx) -> Result<Value, ImportError> {
    let root: Value =
        serde_yaml_ng::from_slice(bytes).map_err(|_| ImportError::Syntax("Clash YAML"))?;
    let Some(root) = root.as_object() else {
        return Err(ImportError::Syntax("Clash YAML"));
    };

    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: HashSet<String> = HashSet::new();
    for (index, proxy) in array(root.get("proxies")).iter().enumerate() {
        let path = format!("proxies[{index}]");
        let Some(map) = proxy.as_object() else {
            ctx.warn(
                path.as_str(),
                "proxy entry is not a mapping and was dropped",
            );
            continue;
        };
        let name = string(map, "name").unwrap_or_default().to_owned();
        if name.is_empty() {
            ctx.warn(path.as_str(), "proxy without a name was dropped");
            continue;
        }
        if tags.contains(&name) {
            ctx.warn(
                format!("{path}.name"),
                format!("duplicate proxy name `{name}` was dropped"),
            );
            continue;
        }
        match convert_proxy(&name, map, &path, ctx) {
            Some(outbound) => {
                tags.insert(name);
                outbounds.push(outbound);
            }
            None => ctx.warn(path, format!("proxy `{name}` was dropped")),
        }
    }

    // Groups become balancers. Members are matched by tag prefix, which is how
    // Segue expands selectors.
    let mut balancers: Vec<Value> = Vec::new();
    let mut group_tags: HashSet<String> = HashSet::new();
    // Each group's flattened leaf members, so a later group can inline it.
    let mut group_members: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut observatory_selectors: Vec<String> = Vec::new();
    let mut probe_url: Option<String> = None;
    let mut probe_interval: Option<u64> = None;
    let mut needs_direct = false;
    let mut needs_reject = false;

    for (index, group) in array(root.get("proxy-groups")).iter().enumerate() {
        let path = format!("proxy-groups[{index}]");
        let Some(map) = group.as_object() else {
            ctx.warn(
                path.as_str(),
                "proxy group is not a mapping and was dropped",
            );
            continue;
        };
        let name = string(map, "name").unwrap_or_default().to_owned();
        if name.is_empty() {
            ctx.warn(path.as_str(), "proxy group without a name was dropped");
            continue;
        }
        if group_tags.contains(&name) {
            ctx.warn(
                format!("{path}.name"),
                format!("duplicate proxy group name `{name}` was dropped"),
            );
            continue;
        }
        let kind = string(map, "type").unwrap_or_default().to_ascii_lowercase();
        let mut members: Vec<String> = Vec::new();
        for member in string_list(map.get("proxies")) {
            if member == DIRECT {
                needs_direct = true;
            } else if member == REJECT {
                needs_reject = true;
            } else if group_tags.contains(&member) {
                // A balancer's selector only expands against leaf outbounds,
                // so a nested group is flattened into its own members. A
                // group that appears later in the file has none yet.
                let nested = group_members.get(&member).cloned().unwrap_or_default();
                if nested.is_empty() {
                    ctx.warn(
                        format!("{path}.proxies"),
                        format!("member `{member}` is a proxy group defined later in the file; it was dropped"),
                    );
                } else {
                    ctx.warn(
                        format!("{path}.proxies"),
                        format!(
                            "member `{member}` is another proxy group; its members were inlined"
                        ),
                    );
                }
                for leaf in nested {
                    if !members.contains(&leaf) {
                        members.push(leaf);
                    }
                }
                continue;
            } else if !tags.contains(&member) {
                ctx.warn(
                    format!("{path}.proxies"),
                    format!("member `{member}` names no proxy or group and was dropped"),
                );
                continue;
            }
            if !members.contains(&member) {
                members.push(member);
            }
        }
        if members.is_empty() {
            ctx.warn(
                path.clone(),
                format!("proxy group `{name}` has no usable member and was dropped"),
            );
            continue;
        }
        if let Some(providers) = map.get("use") {
            ctx.warn(
                format!("{path}.use"),
                format!(
                    "proxy providers {} are not imported; only listed `proxies` members are used",
                    string_list(Some(providers)).join(", ")
                ),
            );
        }
        for unknown in [
            "include-all",
            "include-all-proxies",
            "include-all-providers",
        ] {
            if boolean(map, unknown) {
                ctx.warn(
                    format!("{path}.{unknown}"),
                    "including every proxy automatically is unsupported; list members explicitly",
                );
            }
        }
        warn_prefix_collisions(&members, &path, ctx);

        let strategy = match kind.as_str() {
            "select" => {
                ctx.warn(
                    format!("{path}.type"),
                    "`select` has no manual choice in a static config; the group becomes a random balancer, and the selector can be overridden at runtime",
                );
                json!({"type": "random"})
            }
            "url-test" | "urltest" => {
                if let Some(url) = string(map, "url").filter(|url| !url.is_empty()) {
                    if probe_url.is_none() {
                        probe_url = Some(url.to_owned());
                    }
                }
                if let Some(interval) = map.get("interval").and_then(Value::as_u64) {
                    if interval >= 1 {
                        probe_interval = Some(probe_interval.map_or(interval, |v| v.min(interval)));
                    }
                }
                observatory_selectors.extend(members.iter().cloned());
                json!({"type": "leastPing"})
            }
            "fallback" => {
                ctx.warn(
                    format!("{path}.type"),
                    "`fallback` ordering is not represented; the group becomes a random balancer",
                );
                json!({"type": "random"})
            }
            "load-balance" => json!({"type": "roundRobin"}),
            other => {
                ctx.warn(
                    format!("{path}.type"),
                    format!("unsupported proxy group type `{other}`; the group was dropped"),
                );
                continue;
            }
        };
        let mut balancer = Map::new();
        balancer.insert("tag".into(), json!(name));
        balancer.insert("selector".into(), json!(members));
        balancer.insert("strategy".into(), strategy);
        balancers.push(Value::Object(balancer));
        group_members.insert(name.clone(), members);
        group_tags.insert(name);
    }

    // Rules last, since they may reference DIRECT/REJECT.
    let mut rules: Vec<Value> = Vec::new();
    let mut final_rule: Option<Value> = None;
    for (index, raw) in array(root.get("rules")).iter().enumerate() {
        let path = format!("rules[{index}]");
        let Some(text) = raw.as_str() else {
            ctx.warn(path.as_str(), "rule is not a string and was dropped");
            continue;
        };
        match convert_rule(
            text,
            &path,
            &tags,
            &group_tags,
            &mut needs_direct,
            &mut needs_reject,
            ctx,
        ) {
            RuleTarget::Rule(rule) => rules.push(rule),
            RuleTarget::Final(rule) => {
                if final_rule.is_some() {
                    ctx.warn(path, "a second MATCH rule was dropped");
                } else {
                    final_rule = Some(rule);
                }
            }
            RuleTarget::Dropped => {}
        }
    }

    if let Some(providers) = root.get("rule-providers").and_then(Value::as_object) {
        for (name, provider) in providers {
            let local = provider.get("path").and_then(Value::as_str);
            ctx.warn(
                format!("rule-providers.{name}"),
                match local {
                    Some(path) => format!(
                        "rule provider `{name}` reads `{path}` at runtime; the importer cannot read files, so RULE-SET rules using it were dropped. Convert the file to a sing-box `.srs` and reference it with `ext-srs:` instead"
                    ),
                    None => format!("rule provider `{name}` is remote and was dropped"),
                },
            );
        }
    }

    for key in [
        "port",
        "socks-port",
        "mixed-port",
        "allow-lan",
        "mode",
        "log-level",
        "external-controller",
        "secret",
        "proxy-providers",
    ] {
        if root.get(key).is_some() {
            ctx.warn(
                key,
                "Clash listener/proxy setting has no Xray equivalent and was dropped",
            );
        }
    }

    // Assemble: proxies first, then the built-ins the profile referenced.
    if needs_direct {
        outbounds.push(direct_outbound(DIRECT));
    }
    if needs_reject {
        outbounds.push(block_outbound(REJECT));
    }
    rules.extend(final_rule);
    let mut config = base_config(outbounds);
    if !balancers.is_empty() {
        config["routing"]["balancers"] = Value::Array(balancers);
    }
    config["routing"]["rules"] = Value::Array(rules);
    if !observatory_selectors.is_empty() {
        observatory_selectors.sort();
        observatory_selectors.dedup();
        let mut observatory = Map::new();
        observatory.insert("subjectSelector".into(), json!(observatory_selectors));
        if let Some(url) = probe_url {
            observatory.insert("probeURL".into(), json!(url));
        }
        if let Some(interval) = probe_interval {
            observatory.insert("probeInterval".into(), json!(format!("{interval}s")));
        }
        config["observatory"] = Value::Object(observatory);
    }
    if let Some(dns) = convert_dns(root.get("dns"), ctx) {
        config["dns"] = dns;
    }
    Ok(config)
}

fn array(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// One rule is either a normal routing rule or Clash's trailing `MATCH`.
enum RuleTarget {
    Rule(Value),
    Final(Value),
    Dropped,
}

fn convert_rule(
    text: &str,
    path: &str,
    proxies: &HashSet<String>,
    groups: &HashSet<String>,
    needs_direct: &mut bool,
    needs_reject: &mut bool,
    ctx: &mut Ctx,
) -> RuleTarget {
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        ctx.warn(path, format!("malformed rule `{text}` was dropped"));
        return RuleTarget::Dropped;
    }
    let kind = parts[0].to_ascii_uppercase();
    if matches!(kind.as_str(), "AND" | "OR" | "NOT" | "SUB-RULE") {
        ctx.warn(
            path,
            format!("logical rule type `{kind}` is unsupported and was dropped"),
        );
        return RuleTarget::Dropped;
    }

    let (payload, target): (Option<String>, &str) = if kind == "MATCH" {
        (None, parts[1])
    } else {
        if parts.len() < 3 {
            ctx.warn(path, format!("rule `{text}` has no target and was dropped"));
            return RuleTarget::Dropped;
        }
        // A regex payload may itself contain commas, so it takes everything
        // before the target.
        if kind == "DOMAIN-REGEX" {
            (
                Some(parts[1..parts.len() - 1].join(",")),
                parts[parts.len() - 1],
            )
        } else {
            (Some(parts[1].to_owned()), parts[2])
        }
    };

    let Some(target_value) = target_value(target, proxies, groups, needs_direct, needs_reject)
    else {
        ctx.warn(
            path,
            format!("rule targets `{target}`, which names no proxy or group; the rule was dropped"),
        );
        return RuleTarget::Dropped;
    };

    let Some(payload) = payload else {
        // MATCH: a rule whose condition always holds, sorted last.
        let mut rule = Map::new();
        rule.insert("network".into(), json!(["tcp", "udp"]));
        rule.extend(target_value);
        return RuleTarget::Final(Value::Object(rule));
    };
    let payload = payload.trim().to_owned();
    if payload.is_empty() {
        ctx.warn(path, "rule has an empty payload and was dropped");
        return RuleTarget::Dropped;
    }
    let payload = payload.as_str();

    let condition: (&str, Value) = match kind.as_str() {
        // `DOMAIN` is an exact name; `DOMAIN-SUFFIX` a suffix.
        "DOMAIN" => ("domain", json!([format!("full:{payload}")])),
        "DOMAIN-SUFFIX" => ("domain", json!([format!("domain:{payload}")])),
        "DOMAIN-KEYWORD" => ("domain", json!([format!("keyword:{payload}")])),
        "DOMAIN-REGEX" => ("domain", json!([format!("regexp:{payload}")])),
        "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            if !payload.contains('/') {
                ctx.warn(
                    path,
                    format!("`{payload}` is not a CIDR and the rule was dropped"),
                );
                return RuleTarget::Dropped;
            }
            let field = if kind.starts_with("SRC-") {
                "sourceIP"
            } else {
                "ip"
            };
            (field, json!([payload]))
        }
        "GEOIP" => ("ip", json!([format!("geoip:{payload}")])),
        "GEOSITE" => ("domain", json!([format!("geosite:{payload}")])),
        "PROCESS-NAME" | "PROCESS-PATH" | "PROCESS-PATH-REGEX" => {
            ctx.warn(
                path,
                format!("`{kind}` matches a local process, which Xray routing cannot express; the rule was dropped"),
            );
            return RuleTarget::Dropped;
        }
        "DST-PORT" => ("port", json!(payload)),
        "SRC-PORT" => ("sourcePort", json!(payload)),
        "NETWORK" => ("network", json!([payload])),
        "RULE-SET" => {
            ctx.warn(
                path,
                format!("RULE-SET `{payload}` needs its provider file; the rule was dropped"),
            );
            return RuleTarget::Dropped;
        }
        other => {
            ctx.warn(
                path,
                format!("unsupported rule type `{other}`; the rule was dropped"),
            );
            return RuleTarget::Dropped;
        }
    };
    let mut rule = Map::new();
    rule.insert(condition.0.into(), condition.1);
    rule.extend(target_value);
    RuleTarget::Rule(Value::Object(rule))
}

fn target_value(
    target: &str,
    proxies: &HashSet<String>,
    groups: &HashSet<String>,
    needs_direct: &mut bool,
    needs_reject: &mut bool,
) -> Option<Map<String, Value>> {
    let mut map = Map::new();
    if target == DIRECT {
        *needs_direct = true;
        map.insert("outboundTag".into(), json!(DIRECT));
    } else if target == REJECT {
        *needs_reject = true;
        map.insert("outboundTag".into(), json!(REJECT));
    } else if groups.contains(target) {
        map.insert("balancerTag".into(), json!(target));
    } else if proxies.contains(target) {
        map.insert("outboundTag".into(), json!(target));
    } else {
        return None;
    }
    Some(map)
}

/// Balancer selectors are tag prefixes, so one member name that prefixes
/// another silently pulls the longer one into the group too.
fn warn_prefix_collisions(members: &[String], path: &str, ctx: &mut Ctx) {
    for (index, member) in members.iter().enumerate() {
        for other in &members[index + 1..] {
            if other.starts_with(member.as_str()) || member.starts_with(other.as_str()) {
                ctx.warn(
                    format!("{path}.proxies"),
                    format!("members `{member}` and `{other}` collide as tag prefixes; both may join this group"),
                );
            }
        }
    }
}

fn convert_dns(dns: Option<&Value>, ctx: &mut Ctx) -> Option<Value> {
    let dns = dns?.as_object()?;
    let mut servers = Vec::new();
    for (index, raw) in string_list(dns.get("nameserver")).iter().enumerate() {
        if let Some(server) = dns_server_string(raw, ctx, &format!("dns.nameserver[{index}]")) {
            servers.push(server);
        }
    }
    let fake_ip = if string(dns, "enhanced-mode")
        .is_some_and(|mode| mode.eq_ignore_ascii_case("fake-ip"))
    {
        let range = string(dns, "fake-ip-range").unwrap_or("198.18.0.1/16");
        let ttl = dns
            .get("fake-ip-ttl")
            .and_then(Value::as_u64)
            .and_then(|ttl| u32::try_from(ttl).ok())
            .unwrap_or(0);
        let fake_ip = fake_ip_pool(range).and_then(|pool| fake_ip_object(&pool, ttl));
        if fake_ip.is_none() {
            ctx.warn(
                "dns.fake-ip-range",
                format!("fake-IP range `{range}` is not a usable IPv4 CIDR; fake IP was disabled"),
            );
        }
        fake_ip
    } else {
        None
    };
    let exempt = dns.get("fake-ip-filter").map(|filter| {
        string_list(Some(filter))
            .into_iter()
            .filter_map(|entry| clash_domain_rule_to_xray(&entry, ctx))
            .collect::<Vec<_>>()
    });
    for key in [
        "fallback",
        "nameserver-policy",
        "default-nameserver",
        "proxy-server-nameserver",
        "fallback-filter",
    ] {
        if dns.get(key).is_some() {
            ctx.warn(
                format!("dns.{key}"),
                "this DNS section has no direct equivalent and was dropped",
            );
        }
    }
    dns_object(servers, fake_ip, exempt, ctx)
}

/// Clash fake-IP filters mix `+`/`*` wildcards and regexes; Xray domain rules
/// express suffixes, full names and substrings, plus a regex whose syntax is
/// its own. Wildcards become suffixes and anything else with regex
/// metacharacters is dropped rather than risk an uncompilable rule.
fn clash_domain_rule_to_xray(entry: &str, ctx: &mut Ctx) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Some(rest) = entry.strip_prefix("+.") {
        return Some(format!("domain:{rest}"));
    }
    if let Some(rest) = entry.strip_prefix("*.") {
        return Some(format!("domain:{rest}"));
    }
    if let Some(rest) = entry.strip_prefix('.') {
        return Some(format!("domain:{rest}"));
    }
    if entry.contains(['*', '(', '[', '\\', '^', '$']) {
        ctx.warn(
            "dns.fake-ip-filter",
            format!(
                "filter `{entry}` is a regular expression, which is not carried; it was dropped"
            ),
        );
        return None;
    }
    if entry.starts_with("geosite:") || entry.starts_with("rule-set:") {
        return None;
    }
    Some(format!("domain:{entry}"))
}

fn convert_proxy(name: &str, map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<Value> {
    let kind = string(map, "type")?.to_ascii_lowercase();
    let server = string(map, "server").unwrap_or_default().to_owned();
    if server.is_empty() {
        ctx.warn(format!("{path}.server"), "missing server address");
        return None;
    }
    let Some(proxy_port) = port(map.get("port")) else {
        ctx.warn(format!("{path}.port"), "missing or invalid port");
        return None;
    };
    match kind.as_str() {
        "vless" => vless_outbound(name, map, path, &server, proxy_port, false, ctx),
        "vmess" => vless_outbound(name, map, path, &server, proxy_port, true, ctx),
        "trojan" => trojan_outbound(name, map, path, &server, proxy_port, ctx),
        "ss" | "shadowsocks" => ss_outbound(name, map, path, &server, proxy_port, ctx),
        "hysteria2" | "hy2" => hysteria2_outbound(name, map, path, &server, proxy_port, ctx),
        "anytls" => anytls_outbound(name, map, path, &server, proxy_port, ctx),
        "wireguard" => wireguard_outbound(name, map, path, ctx),
        "socks5" => socks_outbound(name, map, path, &server, proxy_port, ctx),
        "http" => http_outbound(name, map, path, &server, proxy_port, ctx),
        "tuic" => {
            ctx.warn(
                path,
                "TUIC is not supported by Segue's config model; the proxy was dropped",
            );
            None
        }
        other => {
            ctx.warn(
                path,
                format!("unsupported proxy type `{other}`; the proxy was dropped"),
            );
            None
        }
    }
}

/// VLESS and VMess share everything but the credential and protocol name.
fn vless_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    vmess: bool,
    ctx: &mut Ctx,
) -> Option<Value> {
    let protocol = if vmess { "vmess" } else { "vless" };
    let Some(credential) = string(map, "uuid").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.uuid"), "missing UUID");
        return None;
    };
    let reality = object(map, "reality-opts");
    let tls_on = boolean(map, "tls") || reality.is_some();
    let sni = string(map, "servername")
        .or_else(|| string(map, "sni"))
        .map(str::to_owned);
    let alpn = string_list(map.get("alpn"));
    let fingerprint = string(map, "client-fingerprint")
        .or_else(|| string(map, "fingerprint"))
        .map(str::to_owned);
    let insecure = boolean(map, "skip-cert-verify");

    if vmess {
        let alter_id = map.get("alterId").and_then(Value::as_u64).unwrap_or(0);
        if alter_id != 0 {
            ctx.warn(
                format!("{path}.alterId"),
                "legacy VMess alterId is unsupported; it was written as 0",
            );
        }
    }

    let security = if let Some(reality) = reality {
        let public_key = string(reality, "public-key").unwrap_or_default();
        let short_id = string(reality, "short-id").unwrap_or_default();
        let mut reality = reality_object(
            sni.as_deref(),
            public_key,
            short_id,
            fingerprint.as_deref(),
            ctx,
            path,
        );
        reality["kind"] = json!("reality");
        Some(reality)
    } else if tls_on {
        let mut tls = tls_object(
            sni.as_deref(),
            &alpn,
            fingerprint.as_deref(),
            insecure,
            ctx,
            path,
        );
        tls["kind"] = json!("tls");
        Some(tls)
    } else {
        None
    };
    // Segue refuses a plaintext VLESS outbound to a public server unless the
    // user carries VLESS encryption; VMess has no such rule.
    let encrypted = string(map, "encryption").is_some_and(|value| value != "none");
    if !vmess && security.is_none() && !encrypted && !plaintext_server_exempt(server) {
        ctx.warn(
            path,
            "VLESS without TLS or encryption to a public server is refused by Segue; the proxy was dropped",
        );
        return None;
    }

    let (network, transport) = convert_transport(map, path, ctx);
    if security
        .as_ref()
        .is_some_and(|security| security["kind"] == "reality")
        && !matches!(network, "raw" | "grpc" | "xhttp")
    {
        ctx.warn(
            path,
            format!(
                "REALITY only runs over raw, gRPC and XHTTP; the `{network}` transport was dropped"
            ),
        );
        return None;
    }
    let stream = stream_settings(network, security, transport);

    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(proxy_port));
    settings.insert("id".into(), json!(credential));
    if vmess {
        // mihomo's `cipher` names AEAD ciphers only; anything else becomes
        // `auto` so the outbound still parses.
        let cipher = string(map, "cipher").filter(|cipher| {
            matches!(
                cipher.to_ascii_lowercase().as_str(),
                "" | "auto" | "aes-128-gcm" | "chacha20-poly1305"
            )
        });
        if cipher.is_none() && map.get("cipher").is_some() {
            ctx.warn(
                format!("{path}.cipher"),
                "only auto, aes-128-gcm and chacha20-poly1305 VMess ciphers are supported; `auto` was used",
            );
        }
        settings.insert("security".into(), json!(cipher.unwrap_or("auto")));
        if boolean(map, "authenticated-length") {
            settings.insert("experiments".into(), json!("AuthenticatedLength"));
        }
    } else {
        settings.insert(
            "encryption".into(),
            json!(string(map, "encryption").unwrap_or("none")),
        );
        if let Some(flow) = string(map, "flow").filter(|flow| !flow.is_empty()) {
            settings.insert("flow".into(), json!(flow));
        }
    }
    Some(outbound(name, protocol, Value::Object(settings), stream))
}

/// Maps Clash's `network`/`*-opts` blocks onto one Xray transport block.
/// Returns the Xray `network` name and, unless the transport is plain raw
/// TCP, the settings key and its value.
fn convert_transport(
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> (&'static str, Option<(&'static str, Value)>) {
    let network = string(map, "network").unwrap_or("tcp").to_ascii_lowercase();
    match network.as_str() {
        "" | "tcp" | "raw" => ("raw", None),
        "ws" | "websocket" => {
            let ws = object(map, "ws-opts");
            let http_upgrade = ws
                .and_then(|ws| ws.get("v2ray-http-upgrade"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let path_value = ws
                .and_then(|ws| ws.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let headers = header_pairs(ws.and_then(|ws| ws.get("headers")));
            let host = host_header(&headers).map(str::to_owned);
            let rest: Vec<(String, String)> = headers
                .into_iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                .collect();
            if http_upgrade {
                (
                    "httpupgrade",
                    Some((
                        "httpupgradeSettings",
                        httpupgrade_settings(&path_value, host.as_deref()),
                    )),
                )
            } else {
                (
                    "ws",
                    Some((
                        "wsSettings",
                        ws_settings(&path_value, host.as_deref(), &rest),
                    )),
                )
            }
        }
        "grpc" => {
            let service = object(map, "grpc-opts")
                .and_then(|grpc| grpc.get("grpc-service-name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            ("grpc", Some(("grpcSettings", grpc_settings(service))))
        }
        "xhttp" => {
            let opts = map
                .get("xhttp-opts")
                .or_else(|| map.get("ws-opts"))
                .and_then(Value::as_object);
            let path_value = opts
                .and_then(|opts| opts.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let host = opts
                .and_then(|opts| opts.get("host"))
                .and_then(Value::as_str);
            let mode = opts
                .and_then(|opts| opts.get("mode"))
                .and_then(Value::as_str);
            (
                "xhttp",
                Some(("xhttpSettings", xhttp_settings(path_value, host, mode))),
            )
        }
        // Xray removed the `h2` transport, and XHTTP is a different wire
        // protocol, so an h2 profile cannot be served faithfully.
        "h2" | "http" => {
            ctx.warn(
                format!("{path}.network"),
                "the h2/HTTP transport was removed from Xray and XHTTP is a different protocol; the proxy dials plain TCP and will not reach the server",
            );
            ("raw", None)
        }
        other => {
            ctx.warn(
                format!("{path}.network"),
                format!("transport `{other}` has no Segue equivalent; the proxy dials plain TCP"),
            );
            ("raw", None)
        }
    }
}

fn trojan_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let sni = string(map, "sni")
        .or_else(|| string(map, "servername"))
        .map(str::to_owned);
    let alpn = string_list(map.get("alpn"));
    let fingerprint = string(map, "client-fingerprint").map(str::to_owned);
    let mut tls = tls_object(
        sni.as_deref(),
        &alpn,
        fingerprint.as_deref(),
        boolean(map, "skip-cert-verify"),
        ctx,
        path,
    );
    tls["kind"] = json!("tls");
    let (network, transport) = convert_transport(map, path, ctx);
    let stream = stream_settings(network, Some(tls), transport);
    let settings = json!({"address": server, "port": proxy_port, "password": password});
    Some(outbound(name, "trojan", settings, stream))
}

fn ss_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(method) = string(map, "cipher").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.cipher"), "missing cipher");
        return None;
    };
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    if let Some(plugin) = string(map, "plugin").filter(|plugin| !plugin.is_empty()) {
        ctx.warn(
            format!("{path}.plugin"),
            format!("Shadowsocks plugin `{plugin}` is unsupported; the proxy was dropped"),
        );
        return None;
    }
    if boolean(map, "udp-over-tcp") {
        ctx.warn(
            format!("{path}.udp-over-tcp"),
            "UDP-over-TCP is unsupported; UDP is sent as native Shadowsocks datagrams",
        );
    }
    // Segue supports the 2022 ciphers and the four AEAD ones only; catching a
    // mismatch here drops just this proxy instead of failing the whole import.
    if segue_proxy::shadowsocks::Method::new(method, password).is_err() {
        ctx.warn(
            format!("{path}.cipher"),
            format!("Shadowsocks method `{method}` is unsupported or its password is invalid for it; the proxy was dropped"),
        );
        return None;
    }
    let settings = json!({
        "address": server,
        "port": proxy_port,
        "method": method,
        "password": password,
    });
    Some(outbound(name, "shadowsocks", settings, None))
}

fn hysteria2_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let sni = string(map, "sni")
        .or_else(|| string(map, "servername"))
        .map(str::to_owned);
    let mut tls = tls_object(
        sni.as_deref(),
        &["h3".to_owned()],
        // Hysteria uses stock QUIC TLS; the parser refuses a fingerprint.
        None,
        boolean(map, "skip-cert-verify"),
        ctx,
        path,
    );
    tls["kind"] = json!("tls");
    tls["alpn"] = json!(["h3"]);

    let mut udp_masks: Vec<Value> = Vec::new();
    if let Some(obfs) = string(map, "obfs").filter(|obfs| !obfs.is_empty()) {
        if obfs.eq_ignore_ascii_case("salamander") {
            match string(map, "obfs-password") {
                Some(obfs_password) if (4..=4096).contains(&obfs_password.len()) => {
                    udp_masks.push(
                        json!({"type": "salamander", "settings": {"password": obfs_password}}),
                    );
                }
                _ => ctx.warn(
                    format!("{path}.obfs-password"),
                    "Salamander needs a password of 4..=4096 bytes; the mask was dropped",
                ),
            }
        } else {
            ctx.warn(
                format!("{path}.obfs"),
                format!("obfs `{obfs}` is unsupported; the mask was dropped"),
            );
        }
    }
    if let Some(ports) = string(map, "ports").filter(|ports| !ports.is_empty()) {
        match crate::parser::parse_quic_udp_hop_ports(ports) {
            Ok(parsed) if !parsed.is_empty() => {
                udp_masks.push(json!({"type": "udphop", "settings": {
                    "mode": "intervalLocal,intervalRemote",
                    "remotePorts": ports,
                }}));
            }
            _ => ctx.warn(
                format!("{path}.ports"),
                format!("port hopping list `{ports}` is invalid; it was dropped"),
            ),
        }
    }
    let mut stream = stream_settings("hysteria", Some(tls), None).unwrap_or_else(|| json!({}));
    stream["hysteriaSettings"] = json!({"version": 2, "auth": password});
    if !udp_masks.is_empty() {
        stream["finalmask"] = json!({"udp": udp_masks});
    }
    let settings = json!({"version": 2, "address": server, "port": proxy_port});
    Some(outbound(name, "hysteria", settings, Some(stream)))
}

fn anytls_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let sni = string(map, "sni")
        .or_else(|| string(map, "servername"))
        .map(str::to_owned);
    let alpn = string_list(map.get("alpn"));
    let fingerprint = string(map, "client-fingerprint").map(str::to_owned);
    let mut tls = tls_object(
        sni.as_deref(),
        &alpn,
        fingerprint.as_deref(),
        boolean(map, "skip-cert-verify"),
        ctx,
        path,
    );
    tls["kind"] = json!("tls");
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(proxy_port));
    settings.insert("password".into(), json!(password));
    if let Some(metadata) = string(map, "client-metadata").filter(|value| !value.is_empty()) {
        settings.insert("client_metadata".into(), json!(metadata));
    }
    for (key, field) in [
        ("idle-session-check-interval", "idle_session_check_interval"),
        ("idle-session-timeout", "idle_session_timeout"),
    ] {
        if let Some(seconds) = map.get(key).and_then(Value::as_u64).filter(|v| *v > 0) {
            settings.insert(field.into(), json!(format!("{seconds}s")));
        }
    }
    if let Some(min) = map.get("min-idle-session").and_then(Value::as_u64) {
        if min > 8 {
            ctx.warn(
                format!("{path}.min-idle-session"),
                "the AnyTLS pool keeps at most 8 idle sessions; the value was clamped",
            );
        }
        settings.insert("min_idle_session".into(), json!(min.min(8)));
    }
    let stream = stream_settings("raw", Some(tls), None);
    Some(outbound(name, "anytls", Value::Object(settings), stream))
}

fn wireguard_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(secret_key) = string(map, "private-key").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.private-key"), "missing private key");
        return None;
    };
    let mut peer_list: Vec<&Map<String, Value>> = Vec::new();
    if let Some(entries) = map.get("peers").and_then(Value::as_array) {
        for entry in entries {
            if let Some(entry) = entry.as_object() {
                peer_list.push(entry);
            }
        }
    }
    if peer_list.is_empty() {
        // The single-peer form keeps server/public-key beside the proxy.
        peer_list.push(map);
    }
    let mut peers = Vec::new();
    for (index, peer) in peer_list.iter().enumerate() {
        let Some(public_key) = string(peer, "public-key").filter(|value| !value.is_empty()) else {
            ctx.warn(
                format!("{path}.peers[{index}].public-key"),
                "missing public key",
            );
            continue;
        };
        let server = string(peer, "server")
            .or_else(|| string(map, "server"))
            .unwrap_or_default();
        let Some(peer_port) = port(peer.get("port")).or_else(|| port(map.get("port"))) else {
            ctx.warn(format!("{path}.peers[{index}].port"), "missing port");
            continue;
        };
        let mut entry = Map::new();
        entry.insert("publicKey".into(), json!(public_key));
        if let Some(psk) = string(peer, "pre-shared-key").filter(|value| !value.is_empty()) {
            entry.insert("preSharedKey".into(), json!(psk));
        }
        let endpoint = if server.contains(':') && !server.starts_with('[') {
            format!("[{server}]:{peer_port}")
        } else {
            format!("{server}:{peer_port}")
        };
        entry.insert("endpoint".into(), json!(endpoint));
        let allowed = string_list(peer.get("allowed-ips"));
        if !allowed.is_empty() {
            entry.insert("allowedIPs".into(), json!(allowed));
        }
        peers.push(Value::Object(entry));
    }
    if peers.is_empty() {
        ctx.warn(path, "WireGuard has no usable peer; the proxy was dropped");
        return None;
    }

    let mut settings = Map::new();
    settings.insert("secretKey".into(), json!(secret_key));
    settings.insert("peers".into(), Value::Array(peers));
    let mut addresses = Vec::new();
    if let Some(ip) = string(map, "ip").filter(|value| !value.is_empty()) {
        addresses.push(ip.to_owned());
    }
    if let Some(ipv6) = string(map, "ipv6").filter(|value| !value.is_empty()) {
        addresses.push(ipv6.to_owned());
    }
    if !addresses.is_empty() {
        settings.insert("address".into(), json!(addresses));
    }
    let mtu = map.get("mtu").and_then(Value::as_u64).unwrap_or(0);
    if mtu != 0 {
        if (1280..=1420).contains(&mtu) {
            settings.insert("mtu".into(), json!(mtu));
        } else {
            ctx.warn(
                format!("{path}.mtu"),
                format!("MTU {mtu} is outside Segue's 1280..=1420 window; 1420 was used"),
            );
        }
    }
    let dns: Vec<String> = string_list(map.get("dns"))
        .into_iter()
        .filter(|entry| entry.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if !dns.is_empty() {
        settings.insert("remoteDNS".into(), json!(dns));
    }
    Some(outbound(name, "wireguard", Value::Object(settings), None))
}

fn socks_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(proxy_port));
    match (
        string(map, "username").filter(|value| !value.is_empty()),
        string(map, "password"),
    ) {
        (Some(user), Some(pass)) => {
            settings.insert("user".into(), json!(user));
            settings.insert("pass".into(), json!(pass));
        }
        (Some(_), None) => ctx.warn(
            format!("{path}.password"),
            "a username without a password was dropped; the proxy dials unauthenticated",
        ),
        _ => {}
    }
    Some(outbound(name, "socks", Value::Object(settings), None))
}

fn http_outbound(
    name: &str,
    map: &Map<String, Value>,
    path: &str,
    server: &str,
    proxy_port: u16,
    ctx: &mut Ctx,
) -> Option<Value> {
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(proxy_port));
    match (
        string(map, "username").filter(|value| !value.is_empty()),
        string(map, "password"),
    ) {
        (Some(user), Some(pass)) => {
            settings.insert("user".into(), json!(user));
            settings.insert("pass".into(), json!(pass));
        }
        (Some(user), None) => {
            settings.insert("user".into(), json!(user));
        }
        _ => {}
    }
    if boolean(map, "tls") {
        let mut tls = tls_object(
            string(map, "sni"),
            &string_list(map.get("alpn")),
            string(map, "client-fingerprint"),
            boolean(map, "skip-cert-verify"),
            ctx,
            path,
        );
        tls["kind"] = json!("tls");
        let stream = stream_settings("raw", Some(tls), None);
        return Some(outbound(name, "http", Value::Object(settings), stream));
    }
    Some(outbound(name, "http", Value::Object(settings), None))
}
