#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    solana_ledger::{shred::Shred, shredder::ReedSolomonCache},
};

// Fuzz target for Turbine erasure-coding RECOVERY: given an adversarial,
// possibly malformed/insufficient/mismatched set of shreds (each individually
// valid per `Shred::new_from_serialized_shred`, but combined in ways an
// attacker controls), drive the actual Reed-Solomon reconstruction path
// (`shred::merkle::recover`, via the `recover_for_fuzzing` helper) and make
// sure it never panics, overflows, or reads out of bounds - regardless of
// how broken/adversarial the input shred set is.
//
// Input format: a sequence of u16-length-prefixed byte chunks. Each chunk
// that successfully parses as a `Shred` is kept; chunks that fail to parse
// are simply skipped (so most of the fuzzer's random mutations still
// contribute meaningfully instead of being thrown away as one unit).
fuzz_target!(|data: &[u8]| {
    let mut shreds = Vec::new();
    let mut offset = 0usize;
    while offset + 2 <= data.len() && shreds.len() < 256 {
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + len > data.len() {
            break;
        }
        let chunk = &data[offset..offset + len];
        offset += len;
        if let Ok(shred) = Shred::new_from_serialized_shred(chunk.to_vec()) {
            shreds.push(shred);
        }
    }

    if shreds.len() < 2 {
        return;
    }

    let cache = ReedSolomonCache::default();
    let _ = solana_ledger::shred::recover_for_fuzzing(shreds, &cache);
});
