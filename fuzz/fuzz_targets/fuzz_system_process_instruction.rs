#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    solana_account::AccountSharedData,
    solana_instruction::{AccountMeta, Instruction},
    solana_program_runtime::{
        invoke_context::mock_compile_message, loaded_programs::ProgramCacheForTxBatch,
        program_cache_entry::ProgramCacheEntry, with_mock_invoke_context_with_feature_set,
    },
    solana_pubkey::Pubkey,
    solana_sdk_ids::{native_loader, system_program},
    solana_svm_feature_set::SVMFeatureSet,
    solana_svm_timings::ExecuteTimings,
    solana_svm_type_overrides::sync::Arc,
    solana_system_program::system_processor::Entrypoint,
};

// Fuzz target for the System Program's actual on-chain instruction
// processor (`process_instruction`) - the Solana analogue of fuzzing a
// smart contract's function dispatcher. This is the code that directly
// handles lamport transfers, account creation, and account
// allocation/assignment for every SOL-moving transaction on the network.
//
// Drives `SystemInstruction` deserialization + handling with adversarial
// raw instruction bytes against a fixed two-account setup (a funded
// "from" signer and an empty "to" account, both owned by the system
// program), and makes sure it never panics/overflows/UB's - regardless
// of how malformed the instruction data is. We intentionally do NOT use
// the crate's own `mock_process_instruction` test helper here because it
// hard-`assert_eq!`s the result against an expected value (fine for a
// unit test with one exact input, useless/misleading for fuzzing, since
// almost every random input legitimately returns some `Err(..)` rather
// than crashing) - so this replicates the same real setup it uses
// internally, minus that assertion, and just discards the `Result`.
fuzz_target!(|data: &[u8]| {
    let program_id = system_program::id();

    let from_key = Pubkey::new_unique();
    let to_key = Pubkey::new_unique();

    let from_account = AccountSharedData::new(10_000_000_000, 0, &program_id);
    let to_account = AccountSharedData::new(0, 0, &program_id);

    let accounts: Vec<(Pubkey, AccountSharedData)> =
        vec![(from_key, from_account), (to_key, to_account)];

    let instruction_account_metas =
        vec![AccountMeta::new(from_key, true), AccountMeta::new(to_key, false)];

    let instruction = Instruction::new_with_bytes(program_id, data, instruction_account_metas);
    let Ok((sanitized_message, transaction_accounts)) = std::panic::catch_unwind(|| {
        mock_compile_message(&instruction, &accounts, &program_id, &native_loader::id())
    }) else {
        return;
    };

    let program_owner = accounts
        .iter()
        .find(|(key, _)| key == &program_id)
        .map(|(_, acct)| *acct.owner())
        .unwrap_or_else(native_loader::id);
    let is_builtin = native_loader::check_id(&program_owner);

    let feature_set = SVMFeatureSet::all_enabled();

    with_mock_invoke_context_with_feature_set!(
        invoke_context,
        transaction_context,
        feature_set,
        1,
        transaction_accounts,
        &accounts
    );

    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    program_cache_for_tx_batch.replenish(
        if is_builtin { program_id } else { program_owner },
        Arc::new(ProgramCacheEntry::new_builtin(Entrypoint::register)),
    );
    invoke_context.program_cache_for_tx_batch = &mut program_cache_for_tx_batch;

    if invoke_context
        .prepare_top_level_instructions(&sanitized_message)
        .is_err()
    {
        return;
    }

    let _ = invoke_context.process_instruction(&mut 0, &mut ExecuteTimings::default());
});
