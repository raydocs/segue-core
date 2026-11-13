//! IP prefixes: the shared implementation in `segue-policy`, so the AI
//! CIDR set and the SSRF guard match addresses exactly as the client does.

pub use segue_policy::cidr::{any_contains, canon, Cidr};
