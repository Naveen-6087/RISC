#![no_main]

use risc0_zkvm::guest::env;
use core::{ClaimInput, ClaimOutput, PublicInputs, compute_leaf, compute_nullifier, verify_merkle_proof};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read private inputs (user's claim data)
    let claim_input: ClaimInput = env::read();
    
    // Read public inputs (expected root and epoch)
    let public_inputs: PublicInputs = env::read();

    // Step 1: Compute the leaf hash from the user's address
    let leaf = compute_leaf(&claim_input.user_address);

    // Step 2: Verify the Merkle proof
    let is_valid = verify_merkle_proof(
        &leaf,
        &claim_input.merkle_proof,
        claim_input.leaf_index,
        &public_inputs.merkle_root,
    );

    // Step 3: Assert the proof is valid
    assert!(is_valid, "Invalid Merkle proof");

    // Step 4: Verify epoch matches
    assert_eq!(
        claim_input.epoch_id, public_inputs.epoch_id,
        "Epoch ID mismatch"
    );

    // Step 5: Compute nullifier (prevents double-claiming)
    let nullifier = compute_nullifier(&claim_input.user_address, claim_input.epoch_id);

    // Step 6: Create output to commit to journal
    let output = ClaimOutput {
        merkle_root: public_inputs.merkle_root,
        nullifier,
        epoch_id: claim_input.epoch_id,
    };

    // Step 7: Commit output to journal (makes it public)
    env::commit(&output);
}
