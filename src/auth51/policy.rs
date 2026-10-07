use super::*;
use regex::RegexBuilder;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GuardStrength {
    Free,
    Ordered,
    ValueBound,
    Approval,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TierRule {
    pub name: String,
    pub rank: i64,
    pub guards: BTreeMap<String, GuardStrength>,
    pub floor: GuardStrength,
    #[serde(default)]
    pub risk_values: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub name_patterns: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TierPolicy {
    pub tiers: Vec<TierRule>,
    pub default_tier: String,
    pub read_pattern: String,
    pub min_support: u64,
    pub unknown_floor: String,
    pub value_caps: Value,
}
impl Default for TierPolicy {
    fn default() -> Self {
        serde_json::from_str(include_str!("default-policy.json"))
            .expect("Auth51 default policy fixture")
    }
}
impl TierPolicy {
    pub fn classify(&self, action: &str, tags: &[String], risk: &str) -> Result<String> {
        let matches = |pattern: &str| -> Result<bool> {
            Ok(RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|_| Error::Invalid("tier classification regex"))?
                .is_match(action))
        };
        let read = matches(&self.read_pattern)?;
        let tags: Vec<_> = tags.iter().map(|t| t.trim().to_lowercase()).collect();
        let mut best: Option<&TierRule> = None;
        for t in &self.tiers {
            let mut matched = t.tags.iter().any(|s| tags.contains(s));
            if !matched && !read {
                for p in &t.name_patterns {
                    if matches(p)? {
                        matched = true;
                        break;
                    }
                }
            }
            if matched && best.is_none_or(|b| t.rank > b.rank) {
                best = Some(t);
            }
        }
        let risk = risk.trim().to_lowercase();
        for t in &self.tiers {
            if !risk.is_empty()
                && t.risk_values.contains(&risk)
                && best.is_none_or(|b| t.rank > b.rank)
            {
                best = Some(t);
            }
        }
        Ok(best
            .map(|t| t.name.clone())
            .unwrap_or_else(|| self.default_tier.clone()))
    }
    pub fn guard_for(&self, tier: &str, evidence: &str) -> GuardStrength {
        self.tiers
            .iter()
            .find(|t| t.name == tier)
            .map(|t| t.guards.get(evidence).copied().unwrap_or(t.floor))
            .unwrap_or(GuardStrength::Free)
    }
    pub fn floor_for(&self, tier: &str) -> GuardStrength {
        self.tiers
            .iter()
            .find(|t| t.name == tier)
            .map(|t| t.floor)
            .unwrap_or(GuardStrength::Free)
    }
    pub fn validate_workflow(
        &self,
        w: &Dag,
        mut tier_of: impl FnMut(&str, &str) -> Option<String>,
    ) -> Result<()> {
        let approvals: Vec<_> = w
            .steps
            .iter()
            .filter(|(_, s)| s.approval_gate)
            .map(|(n, _)| n)
            .collect();
        for s in w.steps.values().filter(|s| !s.approval_gate) {
            let Some(tier) = tier_of(&s.agent, &s.action) else {
                continue;
            };
            let strength =
                if s.requires_approval || s.dependencies.iter().any(|d| approvals.contains(&d)) {
                    GuardStrength::Approval
                } else if s.value_bound {
                    GuardStrength::ValueBound
                } else if !s.dependencies.is_empty() {
                    GuardStrength::Ordered
                } else {
                    GuardStrength::Free
                };
            if strength < self.floor_for(&tier)
                || (s.value_bound && s.value_bounds.iter().any(|b| !valid_bound(b)))
            {
                return Err(Error::Policy(400, "workflow guard floor violation".into()));
            }
        }
        Ok(())
    }
}
