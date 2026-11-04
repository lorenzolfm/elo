#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| elo::fuzz::headers(data));
