#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    solana_ledger::shred::Shred,
    solana_pubkey::Pubkey,
};

fuzz_target!(|data: &[u8]| {
    let Ok(shred) = Shred::new_from_serialized_shred(data.to_vec()) else {
        return;
    };

    let _ = shred.slot();
    let _ = shred.index();
    let _ = shred.version();
    let _ = shred.fec_set_index();
    let _ = shred.id();
    let _ = shred.signature();
    let _ = shred.shred_type();
    let _ = shred.is_data();
    let _ = shred.is_code();
    let _ = shred.last_in_slot();
    let _ = shred.data_complete();
    let _ = shred.payload();

    let _ = shred.sanitize();
    let _ = shred.merkle_root();
    let _ = shred.chained_merkle_root();
    let _ = shred.retransmitter_signature_offset();

    let _ = shred.data();
    let _ = shred.parent();

    let dummy_pubkey = Pubkey::new_from_array([0u8; 32]);
    let _ = shred.verify(&dummy_pubkey);
});
