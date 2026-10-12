//! Group-level membership management wrapping one `MerkleTree` per
//! group (spec requirement: "one Merkle tree per group; GCS maintains
//! the full tree; each drone stores only [root, version, own witness]").
//!
//! Every mutation (register / revoke / move) increments `version`
//! (`V_G`), which the authentication protocol binds into the signed
//! transcript — this is what makes "stale membership information"
//! detectable rather than merely theoretically bad (spec requirement:
//! "Version MUST be bound into the authentication state").

use super::tree::{verify_witness, MerkleTree, MerkleWitness};
use crate::zkhash::Digest;
use std::collections::HashMap;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum GroupError {
    #[error("drone '{0}' is already an active member of this group")]
    AlreadyMember(String),
    #[error("drone '{0}' is not an active member of this group")]
    NotAMember(String),
    #[error("group Merkle tree is full (capacity {0} reached)")]
    TreeFull(usize),
}

pub struct GroupMembershipTree {
    pub group_id: String,
    pub version: u64,
    tree: MerkleTree,
    next_free_index: usize,
    /// drone_id -> leaf index, for currently ACTIVE members only.
    member_index: HashMap<String, usize>,
    /// drone_id -> leaf index, for members ever registered (including
    /// revoked), so that revoked slots are never silently reused for a
    /// different drone identity (avoids identity confusion in the demo).
    all_index: HashMap<String, usize>,
}

impl GroupMembershipTree {
    pub fn new(group_id: impl Into<String>, depth: usize) -> Self {
        GroupMembershipTree {
            group_id: group_id.into(),
            version: 0,
            tree: MerkleTree::new(depth),
            next_free_index: 0,
            member_index: HashMap::new(),
            all_index: HashMap::new(),
        }
    }

    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    pub fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    pub fn is_active(&self, drone_id: &str) -> bool {
        self.member_index.contains_key(drone_id)
    }

    pub fn active_members(&self) -> Vec<String> {
        self.member_index.keys().cloned().collect()
    }

    pub fn leaf_index_of(&self, drone_id: &str) -> Option<usize> {
        self.member_index.get(drone_id).copied()
    }

    pub fn register(&mut self, drone_id: &str, leaf: Digest) -> Result<usize, GroupError> {
        if self.member_index.contains_key(drone_id) {
            return Err(GroupError::AlreadyMember(drone_id.to_string()));
        }
        let index = if let Some(&existing) = self.all_index.get(drone_id) {
            existing // re-registration of a previously revoked drone reuses its slot
        } else {
            let idx = self.next_free_index;
            if idx >= self.capacity() {
                return Err(GroupError::TreeFull(self.capacity()));
            }
            self.next_free_index += 1;
            idx
        };
        self.tree.set_leaf(index, leaf);
        self.member_index.insert(drone_id.to_string(), index);
        self.all_index.insert(drone_id.to_string(), index);
        self.version += 1;
        Ok(index)
    }

    pub fn revoke(&mut self, drone_id: &str) -> Result<(), GroupError> {
        let index = self
            .member_index
            .remove(drone_id)
            .ok_or_else(|| GroupError::NotAMember(drone_id.to_string()))?;
        self.tree.set_leaf(index, Digest::ZERO);
        self.version += 1;
        Ok(())
    }

    pub fn witness_for(&self, drone_id: &str) -> Option<MerkleWitness> {
        let idx = self.member_index.get(drone_id)?;
        Some(self.tree.witness(*idx))
    }

    /// Recompute witnesses for every currently-active member. Called by
    /// the higher-level simulation/API layer after any mutation so that
    /// each drone can be handed a fresh witness (spec requirement:
    /// "regenerate affected witnesses"). Witnesses are computed on
    /// demand from the authoritative tree, so there is no separate
    /// incremental-update bug surface — a witness is either freshly
    /// derived from the current tree (always correct) or a
    /// previously-issued copy a drone is still holding (which may now be
    /// stale; staleness is caught by the version check in the
    /// authentication protocol, not by anything in this module).
    pub fn refresh_all_witnesses(&self) -> HashMap<String, MerkleWitness> {
        self.member_index
            .keys()
            .map(|id| (id.clone(), self.witness_for(id).unwrap()))
            .collect()
    }

    pub fn verify(&self, leaf: Digest, witness: &MerkleWitness) -> bool {
        verify_witness(self.root(), leaf, witness)
    }

    /// Produce a serializable snapshot for persistence (see `storage`
    /// module). Rather than serializing the tree's internal flat node
    /// array directly, we snapshot the (index -> leaf value) pairs that
    /// have actually been set and replay them through `set_leaf` on
    /// load — simpler to reason about and just as exact, since the tree
    /// is a pure function of its leaves.
    pub fn snapshot(&self) -> GroupTreeSnapshot {
        let leaves = self
            .all_index
            .values()
            .map(|&idx| (idx, self.tree.leaf(idx)))
            .collect();
        GroupTreeSnapshot {
            group_id: self.group_id.clone(),
            depth: self.tree.depth(),
            version: self.version,
            next_free_index: self.next_free_index,
            member_index: self.member_index.clone(),
            all_index: self.all_index.clone(),
            leaves,
        }
    }

    pub fn from_snapshot(s: GroupTreeSnapshot) -> Self {
        let mut tree = MerkleTree::new(s.depth);
        for (idx, leaf_val) in &s.leaves {
            tree.set_leaf(*idx, *leaf_val);
        }
        GroupMembershipTree {
            group_id: s.group_id,
            version: s.version,
            tree,
            next_free_index: s.next_free_index,
            member_index: s.member_index,
            all_index: s.all_index,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupTreeSnapshot {
    pub group_id: String,
    pub depth: usize,
    pub version: u64,
    pub next_free_index: usize,
    pub member_index: HashMap<String, usize>,
    pub all_index: HashMap<String, usize>,
    pub leaves: Vec<(usize, Digest)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_revoke_lifecycle() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        assert_eq!(g.version, 0);
        g.register("drone-1", Digest([111, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        assert_eq!(g.version, 1);
        assert!(g.is_active("drone-1"));
        let w = g.witness_for("drone-1").unwrap();
        assert!(g.verify(Digest([111, 0, 0, 0, 0, 0, 0, 0]), &w));

        g.register("drone-2", Digest([222, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        assert_eq!(g.version, 2);

        g.revoke("drone-1").unwrap();
        assert_eq!(g.version, 3);
        assert!(!g.is_active("drone-1"));

        // drone-1's old witness is now stale against the new root:
        assert!(!g.verify(Digest([111, 0, 0, 0, 0, 0, 0, 0]), &w));
    }

    #[test]
    fn double_registration_rejected() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        g.register("drone-1", Digest([1, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        assert_eq!(
            g.register("drone-1", Digest([2, 0, 0, 0, 0, 0, 0, 0])),
            Err(GroupError::AlreadyMember("drone-1".to_string()))
        );
    }

    #[test]
    fn revoke_unknown_member_rejected() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        assert_eq!(
            g.revoke("ghost"),
            Err(GroupError::NotAMember("ghost".to_string()))
        );
    }

    #[test]
    fn other_members_witness_refresh_after_mutation() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        g.register("drone-1", Digest([1, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        g.register("drone-2", Digest([2, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        let old_w2 = g.witness_for("drone-2").unwrap();

        g.revoke("drone-1").unwrap(); // changes the tree, so drone-2's witness may go stale

        let stale_ok = g.verify(Digest([2, 0, 0, 0, 0, 0, 0, 0]), &old_w2);
        let refreshed = g.refresh_all_witnesses();
        let new_w2 = refreshed.get("drone-2").unwrap();
        assert!(g.verify(Digest([2, 0, 0, 0, 0, 0, 0, 0]), new_w2), "refreshed witness must always verify");
        // whether or not the *old* witness happened to still verify
        // (siblings outside the revoked subtree can remain unaffected),
        // the refreshed one is always guaranteed correct:
        let _ = stale_ok;
    }

    #[test]
    fn tree_full_is_rejected_cleanly() {
        let mut g = GroupMembershipTree::new("tiny", 2); // capacity 4
        for i in 0..4 {
            g.register(&format!("d{i}"), Digest([i as u32, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        }
        assert_eq!(g.register("d4", Digest([4, 0, 0, 0, 0, 0, 0, 0])), Err(GroupError::TreeFull(4)));
    }

    #[test]
    fn re_registration_reuses_original_slot() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        g.register("drone-1", Digest([111, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        let idx1 = g.leaf_index_of("drone-1").unwrap();
        g.revoke("drone-1").unwrap();
        g.register("drone-1", Digest([999, 0, 0, 0, 0, 0, 0, 0])).unwrap(); // reactivation with a fresh leaf
        let idx2 = g.leaf_index_of("drone-1").unwrap();
        assert_eq!(idx1, idx2);
        let w = g.witness_for("drone-1").unwrap();
        assert!(g.verify(Digest([999, 0, 0, 0, 0, 0, 0, 0]), &w));
    }

    #[test]
    fn snapshot_round_trip_preserves_root_and_membership() {
        let mut g = GroupMembershipTree::new("alpha", 4);
        g.register("drone-1", Digest([111, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        g.register("drone-2", Digest([222, 0, 0, 0, 0, 0, 0, 0])).unwrap();
        g.revoke("drone-1").unwrap();
        g.register("drone-3", Digest([333, 0, 0, 0, 0, 0, 0, 0])).unwrap();

        let snap = g.snapshot();
        let bytes = serde_json::to_vec(&snap).unwrap();
        let restored_snap: GroupTreeSnapshot = serde_json::from_slice(&bytes).unwrap();
        let restored = GroupMembershipTree::from_snapshot(restored_snap);

        assert_eq!(restored.root(), g.root());
        assert_eq!(restored.version, g.version);
        assert!(restored.is_active("drone-2"));
        assert!(!restored.is_active("drone-1"));
        let w = restored.witness_for("drone-2").unwrap();
        assert!(restored.verify(Digest([222, 0, 0, 0, 0, 0, 0, 0]), &w));
    }
}
