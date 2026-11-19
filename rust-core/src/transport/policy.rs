//! Operational patch-algorithm policy (docs/patchwise-transport.md section 5a).
//!
//! The educational workbench always exposes all ten algorithms. Operational transmissions are
//! restricted by a named policy:
//!
//! * `low_detectability` (default): DCT, DWT and DCT-SVD are excluded by rule pending an independent
//!   evaluation; LSB replacement is excluded because the versioned risk table `risk-table-1` (built on
//!   validation seeds only, never on the test split; `python-service/src/stego/kb/risk_table.json`) puts it
//!   in the high tier (AUC >= 0.80, threshold fixed before measuring). The remaining algorithms (LSB matching,
//!   PVD, edge-adaptive LSB, HUGO-, WOW- and S-UNIWARD-variants) are *candidates*, not "safe" algorithms;
//!   within feasible plans the selector prefers lower measured risk, then lower distortion, then lower cost.
//! * `all_algorithms`: every algorithm may be selected (comparison / research runs only).
//!
//! `IOD_STEGO_ALGORITHM_ALLOW` may restrict a policy further (comma list); it can never add an
//! algorithm the policy excludes. If no permitted plan fits, the transmission is rejected
//! (`NO_ELIGIBLE_ALGORITHM` / `PATCH_CAPACITY_INSUFFICIENT`); there is no fallback to an excluded
//! algorithm. Rust re-checks every planned manifest against the policy (`POLICY_VIOLATION`).

use crate::transport::backend::ALGS;
use crate::transport::error::{stage, StegoError};
use crate::transport::manifest::Manifest;
use serde_json::{json, Value};

pub const DEFAULT_POLICY: &str = "low_detectability";
pub const POLICIES: [&str; 2] = ["low_detectability", "all_algorithms"];
/// Excluded by rule (prompted by the baseline evaluation) until independently evaluated.
pub const TRANSFORM_EXCLUDED: [&str; 3] = ["dct", "dwt", "dct_svd"];
/// Excluded by the risk table `risk-table-1` (validation split): the high-tier algorithms not already
/// excluded by rule. A test checks this list against the table file.
pub const RISK_EXCLUDED: [&str; 1] = ["lsb_replacement"];
pub const RISK_TABLE_VERSION: &str = "risk-table-1";

#[derive(Clone, Debug, PartialEq)]
pub struct AlgorithmPolicy {
    pub name: String,
    pub allowed: Vec<String>,
}

impl AlgorithmPolicy {
    pub fn named(name: &str) -> Option<Self> {
        let allowed: Vec<String> = match name {
            "low_detectability" => ALGS.iter().filter(|a| !TRANSFORM_EXCLUDED.contains(a) && !RISK_EXCLUDED.contains(a)).map(|a| a.to_string()).collect(),
            "all_algorithms" => ALGS.iter().map(|a| a.to_string()).collect(),
            _ => return None,
        };
        Some(AlgorithmPolicy { name: name.to_string(), allowed })
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let name = get("IOD_STEGO_ALGORITHM_POLICY").map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| DEFAULT_POLICY.into());
        let mut p = Self::named(&name).ok_or_else(|| format!("IOD_STEGO_ALGORITHM_POLICY: unknown policy '{name}' (expected one of {POLICIES:?})"))?;
        if let Some(list) = get("IOD_STEGO_ALGORITHM_ALLOW").filter(|v| !v.trim().is_empty()) {
            let want: Vec<String> = list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            for a in &want {
                if !ALGS.contains(&a.as_str()) {
                    return Err(format!("IOD_STEGO_ALGORITHM_ALLOW: unknown algorithm '{a}'"));
                }
                if !p.allowed.contains(a) {
                    return Err(format!("IOD_STEGO_ALGORITHM_ALLOW: '{a}' is excluded by policy '{}' and cannot be added", p.name));
                }
            }
            p.allowed.retain(|a| want.contains(a));
            if p.allowed.is_empty() {
                return Err("IOD_STEGO_ALGORITHM_ALLOW leaves no algorithm".into());
            }
        }
        Ok(p)
    }

    pub fn excluded(&self) -> Vec<Value> {
        ALGS.iter()
            .filter(|a| !self.allowed.iter().any(|x| x == *a))
            .map(|a| {
                let why = if TRANSFORM_EXCLUDED.contains(a) && self.name == "low_detectability" {
                    "excluded by rule pending independent evaluation (strong single-algorithm detectability in the baseline)"
                } else if RISK_EXCLUDED.contains(a) && self.name == "low_detectability" {
                    "excluded by risk-table-1: high tier on the validation split"
                } else {
                    "not in IOD_STEGO_ALGORITHM_ALLOW"
                };
                json!({"algorithm": a, "reason": why})
            })
            .collect()
    }

    pub fn to_json(&self) -> Value {
        json!({"name": self.name, "allowed": self.allowed})
    }

    pub fn public_view(&self) -> Value {
        json!({"name": self.name, "allowed": self.allowed, "excluded": self.excluded(), "available_policies": POLICIES,
               "note": "operational policy only; the educational workbench always offers all ten algorithms"})
    }

    /// Defence in depth: the service applies the policy, Rust verifies the result.
    pub fn check(&self, man: &Manifest) -> Result<(), StegoError> {
        for (i, p) in man.used() {
            let name = ALGS[p.alg_id as usize - 1];
            if !self.allowed.iter().any(|a| a == name) {
                return Err(StegoError::new("POLICY_VIOLATION", stage::PLAN, 502, format!("patch {i} uses '{name}', which policy '{}' excludes", self.name))
                    .with_details(json!({"patch": i, "algorithm": name, "policy": self.name})));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Result<AlgorithmPolicy, String> {
        let v: Vec<(String, String)> = pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        AlgorithmPolicy::from_lookup(move |k| v.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone()))
    }

    #[test]
    fn default_policy_excludes_the_transform_and_high_risk_variants() {
        let p = env(&[]).unwrap();
        assert_eq!(p.name, "low_detectability");
        assert_eq!(p.allowed, vec!["lsb_matching", "pvd", "edge_adaptive_lsb", "hugo", "wow", "s_uniward"]);
        for a in ["dct", "dwt", "dct_svd", "lsb_replacement"] {
            assert!(!p.allowed.iter().any(|x| x == a), "{a}");
        }
        assert_eq!(p.excluded().len(), 4);
        assert_eq!(env(&[("IOD_STEGO_ALGORITHM_POLICY", "all_algorithms")]).unwrap().allowed.len(), 10);
    }

    #[test]
    fn the_allow_list_can_only_restrict() {
        let p = env(&[("IOD_STEGO_ALGORITHM_ALLOW", "wow, s_uniward")]).unwrap();
        assert_eq!(p.allowed, vec!["wow", "s_uniward"]);
        assert!(env(&[("IOD_STEGO_ALGORITHM_ALLOW", "dct")]).is_err());
        assert!(env(&[("IOD_STEGO_ALGORITHM_ALLOW", "nope")]).is_err());
        assert!(env(&[("IOD_STEGO_ALGORITHM_POLICY", "fastest")]).is_err());
        assert_eq!(env(&[("IOD_STEGO_ALGORITHM_POLICY", "all_algorithms"), ("IOD_STEGO_ALGORITHM_ALLOW", "dct")]).unwrap().allowed, vec!["dct"]);
    }

    #[test]
    fn manifests_using_an_excluded_algorithm_are_refused() {
        let p = AlgorithmPolicy::named("low_detectability").unwrap();
        let ok = crate::transport::manifest::sample(64, 64, 1, 100, &[(2, 0), (9, 8)]);
        assert!(p.check(&ok).is_ok());
        let bad = crate::transport::manifest::sample(64, 64, 1, 100, &[(2, 0), (6, 4)]);
        assert_eq!(p.check(&bad).unwrap_err().code, "POLICY_VIOLATION");
        assert!(AlgorithmPolicy::named("all_algorithms").unwrap().check(&bad).is_ok());
        let lsbr = crate::transport::manifest::sample(64, 64, 1, 100, &[(1, 0)]);
        assert_eq!(p.check(&lsbr).unwrap_err().code, "POLICY_VIOLATION");
    }

    #[test]
    fn the_risk_exclusions_match_the_versioned_risk_table() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../python-service/src/stego/kb/risk_table.json");
        let t: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("risk table present in the repository")).unwrap();
        assert_eq!(t["version"], RISK_TABLE_VERSION);
        let mut high: Vec<&str> = ALGS.iter().copied()
            .filter(|a| t["algorithms"][*a]["tier"] == "high" && !TRANSFORM_EXCLUDED.contains(a)).collect();
        high.sort();
        let mut want = RISK_EXCLUDED.to_vec();
        want.sort();
        assert_eq!(high, want, "RISK_EXCLUDED must be exactly the high-tier algorithms of the table that are not excluded by rule");
        for a in ALGS {
            assert!(t["algorithms"][a]["tier"].is_string(), "{a} missing from the risk table");
        }
    }
}
