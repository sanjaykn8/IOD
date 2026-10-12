//! Binary Poseidon Merkle tree with fixed depth, plus standalone witness
//! verification usable by a drone that only ever stores its own
//! (root, index, siblings, path_indices) — never the full tree (spec
//! requirement: "Drones must not need the entire membership tree").
//!
//! Storage layout: a complete binary tree stored as a flat 1-indexed
//! array (`nodes[1]` = root; children of `nodes[i]` are `nodes[2i]` and
//! `nodes[2i+1]`; leaves occupy `nodes[2^depth .. 2^(depth+1))`). Empty
//! (unassigned/revoked) leaf slots hold `Digest::ZERO` as a sentinel — a
//! legitimately computed leaf (`identity::leaf::compute_leaf`) collides
//! with `Digest::ZERO` only with cryptographically negligible probability,
//! so this is a safe and standard "sparse-tree-via-zero-sentinel"
//! simplification for a research prototype.
//!
//! `path_indices[i] == 1` means "the current node is the RIGHT child at
//! this level" (so the correct hash order is `hash(sibling, current)`);
//! `0` means LEFT child (`hash(current, sibling)`). This matches the
//! `PositionSwitcher` convention in the specification's Circom-style
//! circuit (`s == 1` swaps the pair).



use crate::zkhash::{node_hash, Digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleWitness {
    pub siblings: Vec<Digest>,
    pub path_indices: Vec<u8>,
    pub leaf_index: usize,
}

pub struct MerkleTree {
    depth: usize,
    nodes: Vec<Digest>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let size = 1usize << (depth + 1);
        MerkleTree {
            depth,
            nodes: vec![Digest::ZERO; size],
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    fn leaf_node_index(&self, leaf_index: usize) -> usize {
        (1usize << self.depth) + leaf_index
    }

    pub fn leaf(&self, leaf_index: usize) -> Digest {
        self.nodes[self.leaf_node_index(leaf_index)]
    }

    /// Insert/overwrite a leaf value and recompute all ancestor hashes
    /// up to the root. Used both for initial registration and for
    /// revocation (revocation calls this with `Digest::ZERO`).
    pub fn set_leaf(&mut self, leaf_index: usize, value: Digest) {
        assert!(
            leaf_index < self.capacity(),
            "leaf index {leaf_index} out of range for tree capacity {}",
            self.capacity()
        );
        let mut idx = self.leaf_node_index(leaf_index);
        self.nodes[idx] = value;
        while idx > 1 {
            let parent = idx / 2;
            let left = self.nodes[parent * 2];
            let right = self.nodes[parent * 2 + 1];
            self.nodes[parent] = node_hash(&left, &right);
            idx = parent;
        }
    }

    pub fn root(&self) -> Digest {
        self.nodes[1]
    }

    pub fn witness(&self, leaf_index: usize) -> MerkleWitness {
        assert!(leaf_index < self.capacity());
        let mut idx = self.leaf_node_index(leaf_index);
        let mut siblings = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);
        while idx > 1 {
            let is_right = (idx & 1) == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(self.nodes[sibling_idx]);
            path_indices.push(is_right as u8);
            idx /= 2;
        }
        MerkleWitness {
            siblings,
            path_indices,
            leaf_index,
        }
    }
}

/// Standalone verification: reconstruct the root from `leaf` + `witness`
/// and compare against the (independently known, e.g. from `CredResp`)
/// expected root. This is exactly what a drone holding only its own
/// witness (not the full tree) can and does run.
pub fn verify_witness(expected_root: Digest, leaf: Digest, witness: &MerkleWitness) -> bool {
    if witness.siblings.len() != witness.path_indices.len() {
        return false;
    }
    let mut cur = leaf;
    for (sibling, &is_right) in witness.siblings.iter().zip(witness.path_indices.iter()) {
        cur = if is_right == 1 {
            node_hash(sibling, &cur)
        } else {
            node_hash(&cur, sibling)
        };
    }
    cur == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(x: u64) -> Digest {
        Digest([x as u32, 1, 2, 3, 4, 5, 6, 7])
    }

    #[test]
    fn empty_tree_root_is_stable() {
        let t1 = MerkleTree::new(4);
        let t2 = MerkleTree::new(4);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn insert_changes_root_and_witness_verifies() {
        let mut t = MerkleTree::new(4);
        let leaf = d(12345);
        t.set_leaf(3, leaf);
        let w = t.witness(3);
        assert!(verify_witness(t.root(), leaf, &w));
    }

    #[test]
    fn witness_fails_for_wrong_leaf() {
        let mut t = MerkleTree::new(4);
        t.set_leaf(3, d(12345));
        let w = t.witness(3);
        assert!(!verify_witness(t.root(), d(99999), &w));
    }

    #[test]
    fn witness_fails_after_root_changes_elsewhere() {
        let mut t = MerkleTree::new(4);
        t.set_leaf(3, d(12345));
        let w = t.witness(3);
        let old_root = t.root();
        // Insert a different member in another slot -> root changes.
        t.set_leaf(7, d(999));
        assert_ne!(old_root, t.root());
        // Old witness against the NEW root must now fail (this is
        // exactly "stale witness" — the higher-level membership manager
        // must refresh witnesses for other members after any tree
        // mutation, which is exercised in `merkle::group_tree` tests).
        assert!(!verify_witness(t.root(), d(12345), &w));
        // But it still verifies fine against the (now-stale) old root.
        assert!(verify_witness(old_root, d(12345), &w));
    }

    #[test]
    fn revocation_zeroes_leaf_and_changes_root() {
        let mut t = MerkleTree::new(4);
        t.set_leaf(2, d(555));
        let root_before = t.root();
        t.set_leaf(2, Digest::ZERO); // revoke
        assert_ne!(root_before, t.root());
        let w = t.witness(2);
        assert!(verify_witness(t.root(), Digest::ZERO, &w));
        assert!(!verify_witness(t.root(), d(555), &w));
    }

    #[test]
    fn many_members_all_verify_against_final_root() {
        let mut t = MerkleTree::new(6); // capacity 64
        let mut leaves = vec![];
        for i in 0..30u64 {
            let leaf = d(1000 + i);
            t.set_leaf(i as usize, leaf);
            leaves.push(leaf);
        }
        for i in 0..30usize {
            let w = t.witness(i);
            assert!(verify_witness(t.root(), leaves[i], &w));
        }
    }
}
