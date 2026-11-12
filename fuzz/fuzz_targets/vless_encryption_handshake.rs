#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| segue_vless_encryption::fuzzing::handshake(data));
