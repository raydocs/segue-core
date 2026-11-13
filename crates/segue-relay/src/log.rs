//! Structured logs: one JSON object per line on stderr. Callers pass only
//! non-secret fields; tickets, resume secrets and SOCKS credentials have no
//! logging path (their Debug impls redact).

use std::io::Write as _;

pub fn event(level: &str, msg: &str, fields: &[(&str, serde_json::Value)]) {
    let mut m = serde_json::Map::new();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    m.insert("ts_ms".into(), ts.into());
    m.insert("level".into(), level.into());
    m.insert("msg".into(), msg.into());
    for (k, v) in fields {
        m.insert((*k).into(), v.clone());
    }
    let line = serde_json::Value::Object(m).to_string();
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

#[macro_export]
macro_rules! log {
    ($level:literal, $msg:expr $(, $k:literal = $v:expr)* $(,)?) => {
        $crate::log::event($level, $msg, &[$(($k, serde_json::json!($v))),*])
    };
}
