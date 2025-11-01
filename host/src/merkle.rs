use core::{compute_leaf, hash_pair};

/// A Merkle tree for storing addresses
pub struct MerkleTree {
    /// All leaves in the tree
    pub leaves: Vec<[u8; 32]>,
    /// The Merkle root
    pub root: [u8; 32],
}

impl MerkleTree {
    /// Build a Merkle tree from a list of addresses
    pub fn new(addresses: &[[u8; 20]]) -> Self {
        assert!(!addresses.is_empty(), "Cannot build tree from empty list");

        // Compute leaves
        let leaves: Vec<[u8; 32]> = addresses.iter().map(|addr| compute_leaf(addr)).collect();

        // Build tree
        let root = Self::compute_root(&leaves);

        MerkleTree { leaves, root }
    }

    /// Compute the Merkle root from leaves
    fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    // Hash pair
                    let hash = hash_pair(&current_level[i], &current_level[i + 1]);
                    next_level.push(hash);
                } else {
                    // Odd number of nodes, hash with itself
                    let hash = hash_pair(&current_level[i], &current_level[i]);
                    next_level.push(hash);
                }
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Get the Merkle proof for a given index
    pub fn get_proof(&self, index: usize) -> Vec<[u8; 32]> {
        assert!(index < self.leaves.len(), "Index out of bounds");

        let mut proof = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut current_index = index;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                if i + 1 < current_level.len() {
                    let hash = hash_pair(&current_level[i], &current_level[i + 1]);
                    next_level.push(hash);

                    // Add sibling to proof
                    if i == current_index {
                        proof.push(current_level[i + 1]);
                    } else if i + 1 == current_index {
                        proof.push(current_level[i]);
                    }
                } else {
                    let hash = hash_pair(&current_level[i], &current_level[i]);
                    next_level.push(hash);

                    if i == current_index {
                        proof.push(current_level[i]);
                    }
                }
            }

            current_level = next_level;
            current_index /= 2;
        }

        proof
    }

    /// Get the root hash
    pub fn root(&self) -> [u8; 32] {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single() {
        let addresses = vec![[1u8; 20]];
        let tree = MerkleTree::new(&addresses);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let addresses = vec![[1u8; 20], [2u8; 20], [3u8; 20], [4u8; 20]];
        let tree = MerkleTree::new(&addresses);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof() {
        let addresses = vec![[1u8; 20], [2u8; 20], [3u8; 20], [4u8; 20]];
        let tree = MerkleTree::new(&addresses);

        for i in 0..addresses.len() {
            let proof = tree.get_proof(i);
            let leaf = compute_leaf(&addresses[i]);
            let is_valid =
                core::verify_merkle_proof(&leaf, &proof, i as u32, &tree.root());
            assert!(is_valid, "Proof for index {} should be valid", i);
        }
    }
}
