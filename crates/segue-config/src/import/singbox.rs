//! sing-box JSON conversion.
//!
//! Field names follow sing-box's `json:"..."` tags (`option/*.go`). Outbounds,
//! `route.rules` (including local `.srs` rule-sets) and `dns.servers` are
//! carried; everything else is reported as a warning.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use super::{
    base_config, block_outbound, boolean, direct_outbound, dns_object, dns_server_string,
    fake_ip_object, fake_ip_pool, grpc_settings, header_pairs, host_header, httpupgrade_settings,
    object, outbound, plaintext_server_exempt, port, reality_object, stream_settings, string,
    string_list, tls_object, ws_settings, Ctx, ImportError,
};

pub(super) fn convert(bytes: &[u8], ctx: &mut Ctx) -> Result<Value, ImportError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|_| ImportError::Syntax("sing-box JSON"))?;
    let Some(root) = root.as_object() else {
        return Err(ImportError::Syntax("sing-box JSON"));
    };

    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: HashSet<String> = HashSet::new();
    for (index, entry) in array(root.get("outbounds")).iter().enumerate() {
        let path = format!("outbounds[{index}]");
        let Some(map) = entry.as_object() else {
            ctx.warn(path.as_str(), "outbound is not an object and was dropped");
            continue;
        };
        // Selector and urltest outbounds become balancers below.
        if matches!(
            string(map, "type").unwrap_or_default(),
            "selector" | "urltest"
        ) {
            continue;
        }
        let tag = string(map, "tag").unwrap_or_default().to_owned();
        if tag.is_empty() {
            ctx.warn(path.as_str(), "outbound without a tag was dropped");
            continue;
        }
        if tags.contains(&tag) {
            ctx.warn(
                format!("{path}.tag"),
                format!("duplicate outbound tag `{tag}` was dropped"),
            );
            continue;
        }
        match convert_outbound(&tag, map, &path, ctx) {
            Some(outbound) => {
                tags.insert(tag);
                outbounds.push(outbound);
            }
            None => ctx.warn(path, format!("outbound `{tag}` was dropped")),
        }
    }

    // Endpoints (WireGuard, Tailscale, ...) are outbounds in sing-box 1.11+.
    for (index, entry) in array(root.get("endpoints")).iter().enumerate() {
        let path = format!("endpoints[{index}]");
        let Some(map) = entry.as_object() else {
            continue;
        };
        let tag = string(map, "tag").unwrap_or_default().to_owned();
        let kind = string(map, "type").unwrap_or_default();
        if kind == "wireguard" && !tag.is_empty() && !tags.contains(&tag) {
            if let Some(outbound) = wireguard_endpoint(&tag, map, &path, ctx) {
                tags.insert(tag);
                outbounds.push(outbound);
                continue;
            }
        }
        ctx.warn(
            path,
            format!("endpoint type `{kind}` is unsupported and was dropped"),
        );
    }

    // Groups become balancers.
    let mut balancers: Vec<Value> = Vec::new();
    let mut group_tags: HashSet<String> = HashSet::new();
    let mut group_members: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut observatory_selectors: Vec<String> = Vec::new();
    let mut probe_url: Option<String> = None;
    let mut probe_interval: Option<u64> = None;
    for (index, entry) in array(root.get("outbounds")).iter().enumerate() {
        let Some(map) = entry.as_object() else {
            continue;
        };
        let kind = string(map, "type").unwrap_or_default();
        if !matches!(kind, "selector" | "urltest") {
            continue;
        }
        let path = format!("outbounds[{index}]");
        let tag = string(map, "tag").unwrap_or_default().to_owned();
        if tag.is_empty() || group_tags.contains(&tag) {
            continue;
        }
        let mut members: Vec<String> = Vec::new();
        for member in string_list(map.get("outbounds")) {
            if group_tags.contains(&member) {
                // A balancer's selector only expands against leaf outbounds,
                // so a nested group is flattened into its own members.
                let nested = group_members.get(&member).cloned().unwrap_or_default();
                ctx.warn(
                    format!("{path}.outbounds"),
                    format!("member `{member}` is another group; its members were inlined"),
                );
                for leaf in nested {
                    if !members.contains(&leaf) {
                        members.push(leaf);
                    }
                }
                continue;
            }
            if !tags.contains(&member) {
                ctx.warn(
                    format!("{path}.outbounds"),
                    format!("member `{member}` names no outbound and was dropped"),
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
                format!("group `{tag}` has no usable member and was dropped"),
            );
            continue;
        }
        let strategy = if kind == "urltest" {
            if let Some(url) = string(map, "url").filter(|url| !url.is_empty()) {
                if probe_url.is_none() {
                    probe_url = Some(url.to_owned());
                }
            }
            if let Some(interval) = duration_seconds(map.get("interval")) {
                if interval >= 1 {
                    probe_interval = Some(probe_interval.map_or(interval, |v| v.min(interval)));
                }
            }
            observatory_selectors.extend(members.iter().cloned());
            json!({"type": "leastPing"})
        } else {
            ctx.warn(
                format!("{path}.type"),
                "`selector` has no manual choice in a static config; the group becomes a random balancer, and the selector can be overridden at runtime",
            );
            json!({"type": "random"})
        };
        let mut balancer = Map::new();
        balancer.insert("tag".into(), json!(tag));
        balancer.insert("selector".into(), json!(members));
        balancer.insert("strategy".into(), strategy);
        balancers.push(Value::Object(balancer));
        group_members.insert(tag.clone(), members);
        group_tags.insert(tag);
    }

    // Route rules and the final outbound.
    let route = root.get("route").and_then(Value::as_object);
    // Local `.srs` rule-sets become `ext-srs:` references by their path; a
    // rule naming a set that is not one is dropped.
    let mut rule_sets: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(sets) = route
        .and_then(|route| route.get("rule_set"))
        .and_then(Value::as_array)
    {
        for (index, entry) in sets.iter().enumerate() {
            let path = format!("route.rule_set[{index}]");
            let Some(map) = entry.as_object() else {
                continue;
            };
            let tag = string(map, "tag").unwrap_or_default();
            let kind = string(map, "type").unwrap_or_default();
            let local_path = string(map, "path").unwrap_or_default();
            // Segue resolves `ext-srs:` paths relative to a geodata directory
            // and refuses `.`/`..` components, so a leading `./` is stripped.
            let local_path = local_path.strip_prefix("./").unwrap_or(local_path);
            if tag.is_empty() {
                ctx.warn(path, "rule-set without a tag was dropped");
            } else if kind == "local" && local_path.ends_with(".srs") {
                rule_sets.insert(tag.to_owned(), local_path.to_owned());
            } else {
                ctx.warn(
                    path,
                    format!(
                        "rule-set `{tag}` is not a local `.srs` file; rules using it match nothing"
                    ),
                );
            }
        }
    }
    let mut rules: Vec<Value> = Vec::new();
    let mut final_rule: Option<Value> = None;
    if let Some(route) = route {
        for (index, entry) in array(route.get("rules")).iter().enumerate() {
            let path = format!("route.rules[{index}]");
            let Some(map) = entry.as_object() else {
                ctx.warn(path.as_str(), "rule is not an object and was dropped");
                continue;
            };
            match convert_rule(map, &path, &tags, &group_tags, &rule_sets, ctx) {
                RuleTarget::Rule(rule) => rules.push(rule),
                RuleTarget::Final(rule) => {
                    if final_rule.is_some() {
                        ctx.warn(path, "a second final rule was dropped");
                    } else {
                        final_rule = Some(rule);
                    }
                }
                RuleTarget::Dropped => {}
            }
        }
        if let Some(final_tag) = string(route, "final").filter(|tag| !tag.is_empty()) {
            if tags.contains(final_tag) || group_tags.contains(final_tag) {
                let mut rule = Map::new();
                rule.insert("network".into(), json!(["tcp", "udp"]));
                if group_tags.contains(final_tag) {
                    rule.insert("balancerTag".into(), json!(final_tag));
                } else {
                    rule.insert("outboundTag".into(), json!(final_tag));
                }
                if final_rule.is_some() {
                    ctx.warn(
                        "route.final",
                        "a final rule was already present; `route.final` was dropped",
                    );
                } else {
                    final_rule = Some(Value::Object(rule));
                }
            } else {
                ctx.warn(
                    "route.final",
                    format!("`route.final` names `{final_tag}`, which is not an imported outbound"),
                );
            }
        }
        for key in [
            "geoip",
            "geosite",
            "auto_detect_interface",
            "default_interface",
            "default_mark",
            "find_process",
            "find_neighbor",
        ] {
            if route.get(key).is_some() {
                ctx.warn(
                    format!("route.{key}"),
                    "this route setting has no direct equivalent and was dropped",
                );
            }
        }
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
    for key in ["inbounds", "experimental", "log", "ntp", "services"] {
        if root.get(key).is_some() {
            ctx.warn(
                key,
                "this top-level section has no Xray equivalent and was dropped",
            );
        }
    }
    Ok(config)
}

fn array(value: Option<&Value>) -> &[Value] {
    value
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// A sing-box duration: a Go duration string, or a number of nanoseconds.
fn duration_seconds(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::String(text) => {
            let text = text.trim();
            let (number, unit) = text.split_at(
                text.char_indices()
                    .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
                    .map_or(text.len(), |(index, _)| index),
            );
            let number = number.parse::<f64>().ok()?;
            let multiplier = match unit {
                "ns" => 1e-9,
                "us" | "µs" | "μs" => 1e-6,
                "ms" => 1e-3,
                "s" | "" => 1.0,
                "m" => 60.0,
                "h" => 3600.0,
                _ => return None,
            };
            Some((number * multiplier) as u64)
        }
        Value::Number(number) => number.as_u64().map(|nanos| nanos / 1_000_000_000),
        _ => None,
    }
}

enum RuleTarget {
    Rule(Value),
    Final(Value),
    Dropped,
}

fn convert_rule(
    map: &Map<String, Value>,
    path: &str,
    outbounds: &HashSet<String>,
    groups: &HashSet<String>,
    rule_sets: &std::collections::HashMap<String, String>,
    ctx: &mut Ctx,
) -> RuleTarget {
    if string(map, "type").is_some_and(|kind| kind == "logical") {
        ctx.warn(
            path,
            "logical rules (type: logical) are unsupported and were dropped",
        );
        return RuleTarget::Dropped;
    }
    let action = string(map, "action").unwrap_or("route");
    if action != "route" {
        ctx.warn(
            path,
            format!("rule action `{action}` is unsupported and the rule was dropped"),
        );
        return RuleTarget::Dropped;
    }
    let Some(target) = string(map, "outbound").filter(|tag| !tag.is_empty()) else {
        ctx.warn(path, "rule has no `outbound` and was dropped");
        return RuleTarget::Dropped;
    };
    let mut target_map = Map::new();
    if groups.contains(target) {
        target_map.insert("balancerTag".into(), json!(target));
    } else if outbounds.contains(target) {
        target_map.insert("outboundTag".into(), json!(target));
    } else {
        ctx.warn(
            path,
            format!(
                "rule targets `{target}`, which is not an imported outbound; the rule was dropped"
            ),
        );
        return RuleTarget::Dropped;
    }

    let mut rule = Map::new();
    let mut has_condition = false;

    let domains = domain_rules(map);
    if !domains.is_empty() {
        rule.insert("domain".into(), json!(domains));
        has_condition = true;
    }
    let mut ips: Vec<String> = string_list(map.get("ip_cidr"));
    for code in string_list(map.get("geoip")) {
        ips.push(format!("geoip:{code}"));
    }
    if boolean(map, "ip_is_private") {
        ips.push("geoip:private".to_owned());
    }
    if !ips.is_empty() {
        rule.insert("ip".into(), json!(ips));
        has_condition = true;
    }
    let mut source_ips: Vec<String> = string_list(map.get("source_ip_cidr"));
    for code in string_list(map.get("source_geoip")) {
        source_ips.push(format!("geoip:{code}"));
    }
    if !source_ips.is_empty() {
        rule.insert("sourceIP".into(), json!(source_ips));
        has_condition = true;
    }
    let ports = port_list(map, "port", "port_range");
    if !ports.is_empty() {
        rule.insert("port".into(), json!(ports.join(",")));
        has_condition = true;
    }
    let source_ports = port_list(map, "source_port", "source_port_range");
    if !source_ports.is_empty() {
        rule.insert("sourcePort".into(), json!(source_ports.join(",")));
        has_condition = true;
    }
    let networks = string_list(map.get("network"));
    if !networks.is_empty() {
        rule.insert("network".into(), json!(networks));
        has_condition = true;
    }
    let protocols = string_list(map.get("protocol"));
    if !protocols.is_empty() {
        rule.insert("protocol".into(), json!(protocols));
        has_condition = true;
    }
    let inbounds = string_list(map.get("inbound"));
    if !inbounds.is_empty() {
        rule.insert("inboundTag".into(), json!(inbounds));
        has_condition = true;
    }
    let users = string_list(map.get("user"));
    if !users.is_empty() {
        rule.insert("user".into(), json!(users));
        has_condition = true;
    }
    if let Some(rule_set) = map.get("rule_set") {
        let sets = string_list(Some(rule_set));
        if !sets.is_empty() {
            // Local `.srs` files become `ext-srs:` references; the parser
            // resolves them beside the config.
            let mut refs = Vec::new();
            for set in sets {
                match rule_sets.get(&set) {
                    Some(file) => refs.push(format!("ext-srs:{file}")),
                    None => ctx.warn(
                        format!("{path}.rule_set"),
                        format!("rule-set `{set}` is not a local `.srs` file; it matches nothing"),
                    ),
                }
            }
            if refs.is_empty() {
                return RuleTarget::Dropped;
            }
            rule.insert("domain".into(), json!(refs));
            has_condition = true;
        }
    }
    let mut unsupported = false;
    for key in [
        "process_name",
        "process_path",
        "process_path_regex",
        "package_name",
        "package_name_regex",
        "wifi_ssid",
        "wifi_bssid",
        "network_type",
        "network_is_expensive",
        "network_is_constrained",
        "clash_mode",
        "invert",
        "rule_set_ip_cidr_match_source",
    ] {
        if map.get(key).is_some() {
            unsupported = true;
            ctx.warn(
                format!("{path}.{key}"),
                "this match condition has no Xray equivalent and was ignored",
            );
        }
    }

    if !has_condition {
        // A rule with no condition matches everything. That is only sing-box's
        // final when it really had none; a rule whose every condition was
        // dropped must not become a match-all.
        if unsupported {
            ctx.warn(
                path,
                "every condition of this rule was unsupported; the rule was dropped",
            );
            return RuleTarget::Dropped;
        }
        rule.insert("network".into(), json!(["tcp", "udp"]));
        rule.extend(target_map);
        return RuleTarget::Final(Value::Object(rule));
    }
    rule.extend(target_map);
    RuleTarget::Rule(Value::Object(rule))
}

fn domain_rules(map: &Map<String, Value>) -> Vec<String> {
    let mut rules = Vec::new();
    for domain in string_list(map.get("domain")) {
        rules.push(format!("full:{domain}"));
    }
    for suffix in string_list(map.get("domain_suffix")) {
        rules.push(format!("domain:{suffix}"));
    }
    for keyword in string_list(map.get("domain_keyword")) {
        rules.push(format!("keyword:{keyword}"));
    }
    for regex in string_list(map.get("domain_regex")) {
        rules.push(format!("regexp:{regex}"));
    }
    for code in string_list(map.get("geosite")) {
        rules.push(format!("geosite:{code}"));
    }
    rules
}

fn port_list(map: &Map<String, Value>, ports: &str, ranges: &str) -> Vec<String> {
    let mut list = Vec::new();
    if let Some(Value::Array(items)) = map.get(ports) {
        for value in items {
            if let Some(port) = value.as_u64() {
                list.push(port.to_string());
            }
        }
    }
    for range in string_list(map.get(ranges)) {
        list.push(range);
    }
    list
}

fn convert_dns(dns: Option<&Value>, ctx: &mut Ctx) -> Option<Value> {
    let dns = dns?.as_object()?;
    let mut servers = Vec::new();
    let mut fake_ip = None;
    let mut exempt: Option<Vec<String>> = None;
    for (index, entry) in array(dns.get("servers")).iter().enumerate() {
        let path = format!("dns.servers[{index}]");
        let Some(map) = entry.as_object() else {
            ctx.warn(path.as_str(), "DNS server is not an object and was dropped");
            continue;
        };
        let kind = string(map, "type").unwrap_or_default();
        match kind {
            "fakeip" => {
                let range = string(map, "inet4_range").unwrap_or("198.18.0.0/15");
                match fake_ip_pool(range).and_then(|pool| fake_ip_object(&pool, 0)) {
                    Some(object) => fake_ip = Some(object),
                    None => ctx.warn(
                        format!("{path}.inet4_range"),
                        format!("fake-IP range `{range}` is not a usable IPv4 CIDR; fake IP was disabled"),
                    ),
                }
            }
            "udp" | "tcp" | "tls" | "https" | "quic" | "h3" | "" => {
                let Some(server) = string(map, "server").filter(|server| !server.is_empty()) else {
                    ctx.warn(format!("{path}.server"), "DNS server has no address");
                    continue;
                };
                let server_port = port(map.get("server_port"));
                let scheme = match kind {
                    "tcp" => "tcp://",
                    "tls" => "tls://",
                    "https" => "https://",
                    "quic" | "h3" => "quic+local://",
                    _ => "",
                };
                let address = match server_port {
                    Some(port) if !scheme.is_empty() => format!("{scheme}{server}:{port}"),
                    Some(port) => format!("{server}:{port}"),
                    None if !scheme.is_empty() => format!("{scheme}{server}"),
                    None => server.to_owned(),
                };
                if let Some(server) = dns_server_string(&address, ctx, &path) {
                    servers.push(server);
                }
            }
            "local" | "hosts" | "dhcp" | "mdns" | "resolved" => {
                ctx.warn(
                    path,
                    format!("DNS server type `{kind}` is unsupported and was dropped"),
                );
            }
            other => {
                ctx.warn(
                    path,
                    format!("DNS server type `{other}` is unsupported and was dropped"),
                );
            }
        }
    }
    // `dns.rules` with `domain_suffix`/`domain` and a `server` action become
    // fake-IP exemptions when they point at the fakeip server.
    if let Some(rules) = dns.get("rules").and_then(Value::as_array) {
        let mut list = Vec::new();
        for rule in rules {
            let Some(rule) = rule.as_object() else {
                continue;
            };
            if string(rule, "action").is_some_and(|action| action != "route") {
                continue;
            }
            if string(rule, "server").is_none() {
                continue;
            }
            for suffix in string_list(rule.get("domain_suffix")) {
                list.push(format!("domain:{suffix}"));
            }
            for domain in string_list(rule.get("domain")) {
                list.push(format!("full:{domain}"));
            }
        }
        if !list.is_empty() {
            exempt = Some(list);
        }
    }
    for key in ["final", "strategy", "independent_cache", "reverse_mapping"] {
        if dns.get(key).is_some() {
            ctx.warn(
                format!("dns.{key}"),
                "this DNS setting has no direct equivalent and was dropped",
            );
        }
    }
    dns_object(servers, fake_ip, exempt, ctx)
}

fn convert_outbound(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let kind = string(map, "type")?.to_ascii_lowercase();
    match kind.as_str() {
        "direct" => Some(direct_outbound(tag)),
        "block" => Some(block_outbound(tag)),
        "vless" => vless_outbound(tag, map, path, false, ctx),
        "vmess" => vless_outbound(tag, map, path, true, ctx),
        "trojan" => trojan_outbound(tag, map, path, ctx),
        "shadowsocks" => ss_outbound(tag, map, path, ctx),
        "hysteria2" => hysteria2_outbound(tag, map, path, ctx),
        "anytls" => anytls_outbound(tag, map, path, ctx),
        "socks" => socks_outbound(tag, map, path, ctx),
        "http" => http_outbound(tag, map, path, ctx),
        "wireguard" => wireguard_endpoint(tag, map, path, ctx),
        "selector" | "urltest" => None,
        "tuic" => {
            ctx.warn(
                path,
                "TUIC is not supported by Segue's config model; the outbound was dropped",
            );
            None
        }
        other => {
            ctx.warn(
                path,
                format!("unsupported outbound type `{other}`; the outbound was dropped"),
            );
            None
        }
    }
}

fn server_of(map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<(String, u16)> {
    let Some(server) = string(map, "server").filter(|server| !server.is_empty()) else {
        ctx.warn(format!("{path}.server"), "missing server address");
        return None;
    };
    let Some(server_port) = port(map.get("server_port")) else {
        ctx.warn(
            format!("{path}.server_port"),
            "missing or invalid server port",
        );
        return None;
    };
    Some((server.to_owned(), server_port))
}

/// The TLS/REALITY security object from sing-box's `tls` block.
fn security_of(map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<Value> {
    let tls = object(map, "tls")?;
    if !boolean(tls, "enabled") {
        return None;
    }
    let server_name = string(tls, "server_name").map(str::to_owned);
    let alpn = string_list(tls.get("alpn"));
    let insecure = boolean(tls, "insecure");
    let utls = object(tls, "utls");
    let fingerprint = utls
        .and_then(|utls| utls.get("fingerprint"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(reality) = object(tls, "reality") {
        if boolean(reality, "enabled") {
            let public_key = string(reality, "public_key").unwrap_or_default();
            let short_id = string(reality, "short_id").unwrap_or_default();
            let mut reality = reality_object(
                server_name.as_deref(),
                public_key,
                short_id,
                fingerprint.as_deref(),
                ctx,
                path,
            );
            reality["kind"] = json!("reality");
            return Some(reality);
        }
    }
    let mut tls_object = tls_object(
        server_name.as_deref(),
        &alpn,
        fingerprint.as_deref(),
        insecure,
        ctx,
        path,
    );
    tls_object["kind"] = json!("tls");
    Some(tls_object)
}

fn vless_outbound(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    vmess: bool,
    ctx: &mut Ctx,
) -> Option<Value> {
    let protocol = if vmess { "vmess" } else { "vless" };
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let Some(credential) = string(map, "uuid").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.uuid"), "missing UUID");
        return None;
    };
    let security = security_of(map, path, ctx);
    // Segue refuses a plaintext VLESS outbound to a public server; VMess has
    // no such rule.
    if !vmess && security.is_none() && !plaintext_server_exempt(&server) {
        ctx.warn(
            path,
            "VLESS without TLS to a public server is refused by Segue; the outbound was dropped",
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
    settings.insert("port".into(), json!(server_port));
    settings.insert("id".into(), json!(credential));
    if vmess {
        // sing-box also names `none`, `zero` and the stream ciphers, which
        // AEAD-only VMess refuses; `auto` is Xray's default for those.
        let security = string(map, "security").filter(|security| {
            matches!(
                security.to_ascii_lowercase().as_str(),
                "" | "auto" | "aes-128-gcm" | "chacha20-poly1305"
            )
        });
        if security.is_none() && map.get("security").is_some() {
            ctx.warn(
                format!("{path}.security"),
                "only auto, aes-128-gcm and chacha20-poly1305 VMess ciphers are supported; `auto` was used",
            );
        }
        settings.insert("security".into(), json!(security.unwrap_or("auto")));
        let alter_id = map.get("alter_id").and_then(Value::as_u64).unwrap_or(0);
        if alter_id != 0 {
            ctx.warn(
                format!("{path}.alter_id"),
                "legacy VMess alterId is unsupported; it was written as 0",
            );
        }
        if boolean(map, "authenticated_length") {
            settings.insert("experiments".into(), json!("AuthenticatedLength"));
        }
    } else {
        settings.insert("encryption".into(), json!("none"));
        if let Some(flow) = string(map, "flow").filter(|flow| !flow.is_empty()) {
            settings.insert("flow".into(), json!(flow));
        }
    }
    Some(outbound(tag, protocol, Value::Object(settings), stream))
}

fn convert_transport(
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> (&'static str, Option<(&'static str, Value)>) {
    let Some(transport) = object(map, "transport") else {
        return ("raw", None);
    };
    let kind = string(transport, "type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    match kind.as_str() {
        "" => ("raw", None),
        "ws" => {
            let path_value = string(transport, "path").unwrap_or("");
            let headers = header_pairs(transport.get("headers"));
            let host = host_header(&headers).map(str::to_owned);
            let rest: Vec<(String, String)> = headers
                .into_iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                .collect();
            (
                "ws",
                Some((
                    "wsSettings",
                    ws_settings(path_value, host.as_deref(), &rest),
                )),
            )
        }
        "grpc" => {
            let service = string(transport, "service_name").unwrap_or("");
            ("grpc", Some(("grpcSettings", grpc_settings(service))))
        }
        "httpupgrade" => {
            let path_value = string(transport, "path").unwrap_or("");
            let host = string(transport, "host");
            (
                "httpupgrade",
                Some((
                    "httpupgradeSettings",
                    httpupgrade_settings(path_value, host),
                )),
            )
        }
        // Xray removed the h2 and QUIC transports, and XHTTP is a different
        // wire protocol from either, so these cannot be carried faithfully.
        "http" | "quic" => {
            ctx.warn(
                format!("{path}.transport"),
                format!("the `{kind}` transport was removed from Xray; the outbound dials plain TCP and will not reach the server"),
            );
            ("raw", None)
        }
        other => {
            ctx.warn(
                format!("{path}.transport"),
                format!(
                    "transport `{other}` has no Segue equivalent; the outbound dials plain TCP"
                ),
            );
            ("raw", None)
        }
    }
}

fn trojan_outbound(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let Some(security) = security_of(map, path, ctx) else {
        ctx.warn(
            path,
            "Trojan requires TLS or REALITY; the outbound was dropped",
        );
        return None;
    };
    let (network, transport) = convert_transport(map, path, ctx);
    let stream = stream_settings(network, Some(security), transport);
    let settings = json!({"address": server, "port": server_port, "password": password});
    Some(outbound(tag, "trojan", settings, stream))
}

fn ss_outbound(tag: &str, map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let Some(method) = string(map, "method").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.method"), "missing method");
        return None;
    };
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    if let Some(plugin) = string(map, "plugin").filter(|plugin| !plugin.is_empty()) {
        ctx.warn(
            format!("{path}.plugin"),
            format!("Shadowsocks plugin `{plugin}` is unsupported; the outbound was dropped"),
        );
        return None;
    }
    // Segue supports the 2022 ciphers and the four AEAD ones only; catching a
    // mismatch here drops just this outbound instead of failing the import.
    if segue_proxy::shadowsocks::Method::new(method, password).is_err() {
        ctx.warn(
            format!("{path}.method"),
            format!("Shadowsocks method `{method}` is unsupported or its password is invalid for it; the outbound was dropped"),
        );
        return None;
    }
    let settings = json!({
        "address": server,
        "port": server_port,
        "method": method,
        "password": password,
    });
    Some(outbound(tag, "shadowsocks", settings, None))
}

fn hysteria2_outbound(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let mut tls = security_of(map, path, ctx).unwrap_or_else(|| json!({}));
    tls["kind"] = json!("tls");
    tls["alpn"] = json!(["h3"]);
    // Hysteria uses stock QUIC TLS; the parser refuses a shaping fingerprint.
    if let Some(tls) = tls.as_object_mut() {
        tls.remove("fingerprint");
    }

    let mut udp_masks: Vec<Value> = Vec::new();
    if let Some(obfs) = object(map, "obfs") {
        let kind = string(obfs, "type").unwrap_or_default();
        if kind.eq_ignore_ascii_case("salamander") {
            match string(obfs, "password") {
                Some(password) if (4..=4096).contains(&password.len()) => {
                    udp_masks
                        .push(json!({"type": "salamander", "settings": {"password": password}}));
                }
                _ => ctx.warn(
                    format!("{path}.obfs.password"),
                    "Salamander needs a password of 4..=4096 bytes; the mask was dropped",
                ),
            }
        } else {
            ctx.warn(
                format!("{path}.obfs"),
                format!("obfs `{kind}` is unsupported; the mask was dropped"),
            );
        }
    }
    let ports = string_list(map.get("server_ports"));
    if !ports.is_empty() {
        // sing-box writes ranges as `from:to`; Xray's udphop reads `from-to`.
        let joined = ports
            .iter()
            .map(|range| range.replace(':', "-"))
            .collect::<Vec<_>>()
            .join(",");
        match crate::parser::parse_quic_udp_hop_ports(&joined) {
            Ok(parsed) if !parsed.is_empty() => {
                udp_masks.push(json!({"type": "udphop", "settings": {
                    "mode": "intervalLocal,intervalRemote",
                    "remotePorts": joined,
                }}));
            }
            _ => ctx.warn(
                format!("{path}.server_ports"),
                format!("port hopping list `{joined}` is invalid; it was dropped"),
            ),
        }
    }
    let mut stream = stream_settings("hysteria", Some(tls), None).unwrap_or_else(|| json!({}));
    stream["hysteriaSettings"] = json!({"version": 2, "auth": password});
    if !udp_masks.is_empty() {
        stream["finalmask"] = json!({"udp": udp_masks});
    }
    let settings = json!({"version": 2, "address": server, "port": server_port});
    Some(outbound(tag, "hysteria", settings, Some(stream)))
}

fn anytls_outbound(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let Some(password) = string(map, "password").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.password"), "missing password");
        return None;
    };
    let Some(security) = security_of(map, path, ctx) else {
        ctx.warn(path, "AnyTLS requires TLS; the outbound was dropped");
        return None;
    };
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(server_port));
    settings.insert("password".into(), json!(password));
    if let Some(metadata) = string(map, "client_metadata").filter(|value| !value.is_empty()) {
        settings.insert("client_metadata".into(), json!(metadata));
    }
    for (key, field) in [
        ("idle_session_check_interval", "idle_session_check_interval"),
        ("idle_session_timeout", "idle_session_timeout"),
    ] {
        if let Some(seconds) = duration_seconds(map.get(key)).filter(|v| *v > 0) {
            settings.insert(field.into(), json!(format!("{seconds}s")));
        }
    }
    if let Some(min) = map.get("min_idle_session").and_then(Value::as_u64) {
        if min > 8 {
            ctx.warn(
                format!("{path}.min_idle_session"),
                "the AnyTLS pool keeps at most 8 idle sessions; the value was clamped",
            );
        }
        settings.insert("min_idle_session".into(), json!(min.min(8)));
    }
    let stream = stream_settings("raw", Some(security), None);
    Some(outbound(tag, "anytls", Value::Object(settings), stream))
}

fn socks_outbound(tag: &str, map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(server_port));
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
            "a username without a password was dropped; the outbound dials unauthenticated",
        ),
        _ => {}
    }
    Some(outbound(tag, "socks", Value::Object(settings), None))
}

fn http_outbound(tag: &str, map: &Map<String, Value>, path: &str, ctx: &mut Ctx) -> Option<Value> {
    let Some((server, server_port)) = server_of(map, path, ctx) else {
        return None;
    };
    let mut settings = Map::new();
    settings.insert("address".into(), json!(server));
    settings.insert("port".into(), json!(server_port));
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
    let security = security_of(map, path, ctx);
    let stream = stream_settings("raw", security, None);
    Some(outbound(tag, "http", Value::Object(settings), stream))
}

fn wireguard_endpoint(
    tag: &str,
    map: &Map<String, Value>,
    path: &str,
    ctx: &mut Ctx,
) -> Option<Value> {
    let Some(secret_key) = string(map, "private_key").filter(|value| !value.is_empty()) else {
        ctx.warn(format!("{path}.private_key"), "missing private key");
        return None;
    };
    let mut peers = Vec::new();
    for (index, peer) in array(map.get("peers")).iter().enumerate() {
        let Some(peer) = peer.as_object() else {
            continue;
        };
        let Some(public_key) = string(peer, "public_key").filter(|value| !value.is_empty()) else {
            ctx.warn(
                format!("{path}.peers[{index}].public_key"),
                "missing public key",
            );
            continue;
        };
        let Some(server) = string(peer, "address").filter(|value| !value.is_empty()) else {
            ctx.warn(format!("{path}.peers[{index}].address"), "missing address");
            continue;
        };
        let Some(peer_port) = port(peer.get("port")) else {
            ctx.warn(format!("{path}.peers[{index}].port"), "missing port");
            continue;
        };
        let mut entry = Map::new();
        entry.insert("publicKey".into(), json!(public_key));
        if let Some(psk) = string(peer, "pre_shared_key").filter(|value| !value.is_empty()) {
            entry.insert("preSharedKey".into(), json!(psk));
        }
        let endpoint = if server.contains(':') && !server.starts_with('[') {
            format!("[{server}]:{peer_port}")
        } else {
            format!("{server}:{peer_port}")
        };
        entry.insert("endpoint".into(), json!(endpoint));
        let allowed = string_list(peer.get("allowed_ips"));
        if !allowed.is_empty() {
            entry.insert("allowedIPs".into(), json!(allowed));
        }
        peers.push(Value::Object(entry));
    }
    if peers.is_empty() {
        ctx.warn(
            path,
            "WireGuard has no usable peer; the outbound was dropped",
        );
        return None;
    }
    let mut settings = Map::new();
    settings.insert("secretKey".into(), json!(secret_key));
    settings.insert("peers".into(), Value::Array(peers));
    let addresses = string_list(map.get("address"));
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
    Some(outbound(tag, "wireguard", Value::Object(settings), None))
}
