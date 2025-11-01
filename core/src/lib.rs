use serde::{Deserialize, Serialize};

/// Input data for a claim proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimInput {
    /// User's address (20 bytes for Ethereum address)
    pub user_address: [u8; 20],
    /// Merkle proof path (array of 32-byte hashes)
    pub merkle_proof: Vec<[u8; 32]>,
    /// Position of the leaf in the tree
    pub leaf_index: u32,
    /// Epoch identifier for this airdrop round
    pub epoch_id: u64,
}

/// Output data committed to the journal
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimOutput {
    /// The verified Merkle root
    pub merkle_root: [u8; 32],
    /// Nullifier to prevent double-claiming
    pub nullifier: [u8; 32],
    /// Epoch ID that was verified
    pub epoch_id: u64,
}

/// Public inputs that will be committed to the journal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The expected Merkle root
    pub merkle_root: [u8; 32],
    /// Current epoch ID
    pub epoch_id: u64,
}

/// Compute a leaf hash from an Ethereum address
pub fn compute_leaf(address: &[u8; 20]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(address);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute intermediate hash for Merkle tree
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    index: u32,
    root: &[u8; 32],
) -> bool {
    let mut computed_hash = *leaf;
    let mut current_index = index;

    for proof_element in proof {
        if current_index % 2 == 0 {
            // Current node is left child
            computed_hash = hash_pair(&computed_hash, proof_element);
        } else {
            // Current node is right child
            computed_hash = hash_pair(proof_element, &computed_hash);
        }
        current_index /= 2;
    }

    computed_hash == *root
}

/// Compute nullifier from address and epoch
pub fn compute_nullifier(address: &[u8; 20], epoch_id: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(address);
    hasher.update(&epoch_id.to_le_bytes());
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = hash_pair(&left, &right);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_compute_nullifier() {
        let address = [1u8; 20];
        let epoch_id = 1u64;
        let nullifier = compute_nullifier(&address, epoch_id);
        assert_ne!(nullifier, [0u8; 32]);
        
        // Same inputs should produce same nullifier
        let nullifier2 = compute_nullifier(&address, epoch_id);
        assert_eq!(nullifier, nullifier2);
        
        // Different epoch should produce different nullifier
        let nullifier3 = compute_nullifier(&address, 2u64);
        assert_ne!(nullifier, nullifier3);
    }
}
