#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| elo::net::fuzz::frame(data));
