use super::*;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

/// One authenticated app's in-process policy state. Separate instances isolate
/// apps/tenants. Mutators are trusted host operations, never MCP tools.
pub struct LocalAuthority {
    issuer: String,
    app_id: String,
    key: Arc<IssuerKey>,
    agents: BTreeMap<String, RegisteredAgent>,
    workflows: BTreeMap<String, Dag>,
    executions: BTreeMap<String, Execution>,
    pub policy: TierPolicy,
    tiers: BTreeMap<(String, String), String>,
    verifier: ResourceVerifier,
    reservations: BTreeMap<String, String>,
}
impl LocalAuthority {
    pub fn new(issuer: &str, app_id: &str, key: Arc<IssuerKey>) -> Result<Self> {
        if issuer.is_empty() || app_id.is_empty() {
            return Err(Error::Invalid("issuer and app required"));
        }
        let mut verifier = ResourceVerifier::new(issuer, key.jwks());
        verifier.reject_replay = true;
        Ok(Self {
            issuer: issuer.into(),
            app_id: app_id.into(),
            key,
            agents: BTreeMap::new(),
            workflows: BTreeMap::new(),
            executions: BTreeMap::new(),
            policy: TierPolicy::default(),
            tiers: BTreeMap::new(),
            verifier,
            reservations: BTreeMap::new(),
        })
    }
    pub fn jwks(&self) -> Value {
        self.key.jwks()
    }
    pub fn register_agent(&mut self, components: &Components, grant: Grant) -> Result<String> {
        let mut checksums = vec![
            components.checksum_v1()?,
            components.checksum_v2()?,
            components.checksum_v3()?,
            components.checksum_v4()?,
        ];
        let v5 = components.checksum_v5()?;
        checksums.push(v5);
        let id = random_id();
        let subagents = components
            .tools
            .iter()
            .filter(|t| t["is_agent"] == true)
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect();
        self.provision(RegisteredAgent {
            agent_id: components.agent_id.clone(),
            registration_id: id.clone(),
            checksums,
            subagents,
            public_jwk: None,
            grant: Some(grant),
        });
        Ok(id)
    }
    /// Trusted provisioning for persisted Auth51 registrations; agents cannot
    /// supply their own registered checksums or grant envelopes at mint.
    pub fn provision(&mut self, agent: RegisteredAgent) {
        self.agents.insert(agent.agent_id.clone(), agent);
    }
    pub fn revoke_agent(&mut self, id: &str) {
        self.agents.remove(id);
    }
    pub fn set_tier(&mut self, agent: &str, action: &str, tier: &str) {
        self.tiers
            .insert((agent.into(), action.into()), tier.into());
    }
    pub fn register_workflow(&mut self, w: Dag) -> Result<&'static str> {
        if w.workflow_type != "dag" {
            return Err(Error::Invalid("workflow type"));
        }
        if let Some(old) = self.workflows.get(&w.workflow_id) {
            if workflow_fingerprint(old)? == workflow_fingerprint(&w)? {
                return Ok("skipped");
            }
        }
        self.policy.validate_workflow(&w, |a, act| {
            self.tiers.get(&(a.into(), act.into())).cloned()
        })?;
        let status = if self.workflows.contains_key(&w.workflow_id) {
            "superseded"
        } else {
            "registered"
        };
        self.workflows.insert(w.workflow_id.clone(), w);
        Ok(status)
    }
    pub fn remove_workflow(&mut self, id: &str) {
        self.workflows.remove(id);
    }
    pub fn open_execution(&mut self, hint: Option<&str>, mode: Mode) -> Execution {
        let mut candidates: Vec<_> = self.workflows.keys().cloned().collect();
        let mut bound = None;
        if let Some(hint) = hint.filter(|s| !s.is_empty()) {
            if self.workflows.contains_key(hint) {
                bound = Some(hint.into());
                candidates = vec![hint.into()];
            } else {
                candidates.clear();
            }
        } else if candidates.len() == 1 {
            bound = Some(candidates[0].clone());
        }
        let e = Execution {
            execution_id: format!("exec_{}", random_id()),
            app_id: self.app_id.clone(),
            workflow_id: bound,
            candidate_workflow_ids: candidates,
            mode,
        };
        self.executions.insert(e.execution_id.clone(), e.clone());
        e
    }
    pub fn execution(&self, id: &str) -> Option<&Execution> {
        self.executions.get(id)
    }
    pub fn restore_execution(&mut self, e: Execution) -> Result<()> {
        if e.app_id != self.app_id {
            return Err(Error::Policy(
                403,
                "execution belongs to another app".into(),
            ));
        }
        self.executions.insert(e.execution_id.clone(), e);
        Ok(())
    }
    pub fn close_execution(&mut self, id: &str) {
        self.executions.remove(id);
    }

    pub fn evaluate(
        &mut self,
        req: &MintRequest,
        caller_scopes: &[String],
        now: u64,
    ) -> Result<Value> {
        if req.grant_type != "agent_checksum" {
            return Err(Error::Policy(400, "unsupported grant type".into()));
        }
        let agent = self
            .agents
            .get(&req.agent_id)
            .ok_or(Error::Policy(401, "unknown agent".into()))?;
        if !agent.checksums.contains(&req.computed_checksum) {
            return Err(Error::Policy(401, "checksum mismatch".into()));
        }
        let execution = req
            .execution_id
            .as_ref()
            .and_then(|id| self.executions.get(id));
        let exec_mode = execution.map(|e| e.mode);
        let grant = agent
            .grant
            .as_ref()
            .filter(|g| g.expires_at.is_none_or(|t| t > now))
            .ok_or(Error::Policy(403, "no active grant".into()))?;
        let outside = req
            .requested_scopes
            .iter()
            .any(|s| !grant.allowed_scopes.contains(s) && !grant.step_up_scopes.contains(s));
        let step_up = req
            .requested_scopes
            .iter()
            .any(|s| grant.step_up_scopes.contains(s));
        if exec_mode.unwrap_or(grant.mode) == Mode::Enforce && (outside || step_up) {
            return Err(Error::Policy(
                403,
                "outside grant or step-up required".into(),
            ));
        }
        let delegation = req.delegation_context.clone().unwrap_or_default();
        let ids: Vec<_> = delegation.chain.iter().map(hop_id).collect();
        let structural = ids.len() <= 1
            || (ids.len() <= 8
                && ids.last().copied() == Some(req.agent_id.as_str())
                && ids.iter().all(|id| self.agents.contains_key(*id))
                && ids.windows(2).all(|w| {
                    self.agents
                        .get(w[0])
                        .is_some_and(|a| a.subagents.iter().any(|s| s == w[1]))
                }));
        if !structural && exec_mode.unwrap_or(grant.mode) == Mode::Enforce {
            return Err(Error::Policy(403, "delegation chain rejected".into()));
        }
        let custody = req.execution_id.as_ref().is_some_and(|s| !s.is_empty())
            || delegation
                .chain
                .iter()
                .any(|h| h.get("checksum").is_some_and(truthy));
        for hop in &delegation.chain {
            let id = hop_id(hop);
            if id == req.agent_id {
                continue;
            }
            let checksum = hop["checksum"].as_str().filter(|s| !s.is_empty());
            match checksum {
                None if custody => {
                    return Err(Error::Policy(401, "chain-of-custody downgrade".into()));
                }
                Some(checksum)
                    if !self
                        .agents
                        .get(id)
                        .is_some_and(|a| a.checksums.iter().any(|c| c == checksum)) =>
                {
                    return Err(Error::Policy(401, "chain checksum mismatch".into()));
                }
                _ => {}
            }
        }
        let current = req.workflow_step.as_ref().unwrap_or(&Value::Null);
        let candidates: Vec<Dag> = if let Some(e) = execution {
            let names = e
                .workflow_id
                .as_ref()
                .map(|w| vec![w.clone()])
                .unwrap_or_else(|| e.candidate_workflow_ids.clone());
            names
                .iter()
                .filter_map(|id| self.workflows.get(id).cloned())
                .collect()
        } else {
            let entry = ids
                .first()
                .copied()
                .or_else(|| {
                    delegation
                        .completed_steps
                        .first()
                        .and_then(|c| c["agent_id"].as_str())
                })
                .or_else(|| current["agent_id"].as_str());
            self.workflows
                .values()
                .filter(|w| {
                    w.steps
                        .values()
                        .any(|s| Some(s.agent.as_str()) == entry && s.dependencies.is_empty())
                })
                .cloned()
                .collect()
        };
        let mut scopes = caller_scopes.to_vec();
        scopes.extend(req.requested_scopes.clone());
        let resolution =
            resolve_workflow(&candidates, &delegation.completed_steps, current, &scopes);
        let effective = exec_mode.unwrap_or(resolution.mode);
        if resolution.governed && !resolution.authorised && effective == Mode::Enforce {
            return Err(Error::Policy(403, "workflow step denied".into()));
        }
        let registration = agent.registration_id.clone();
        let public_jwk = agent.public_jwk.clone();
        if let Some(e) = req
            .execution_id
            .as_ref()
            .and_then(|id| self.executions.get_mut(id))
        {
            if e.workflow_id.is_none() && resolution.workflow_id.is_some() {
                e.workflow_id = resolution.workflow_id.clone();
            }
        }
        let mut binding = None;
        if resolution.governed
            && resolution.authorised
            && resolution.value_bound
            && !resolution.value_bounds.is_empty()
        {
            let operation = if resolution.action.is_empty() {
                current["tool_name"].as_str().unwrap_or("")
            } else {
                &resolution.action
            };
            let args = req.action_args.as_ref().unwrap_or(&Value::Null);
            let frozen = freeze_bounds(
                &resolution.value_bounds,
                operation,
                args,
                &self.policy.value_caps,
                &json!({}),
                &resolution.tier,
            );
            match frozen {
                Ok(b) if evaluate_binding(&b, args) => binding = Some(b),
                _ if effective == Mode::Enforce => {
                    return Err(Error::Policy(403, "value binding violated".into()));
                }
                _ => {}
            }
        }
        let mut chain: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        if chain.is_empty() {
            chain.push(req.agent_id.clone());
        }
        let repr = req
            .workflow_step
            .as_ref()
            .filter(|v| truthy(v))
            .map(python_repr)
            .transpose()?;
        let completed = delegation
            .completed_steps
            .iter()
            .map(python_str)
            .collect::<Result<Vec<_>>>()?;
        let workflow_step = resolution
            .step_name
            .as_ref()
            .map(|n| json!(n))
            .unwrap_or_else(|| current.clone());
        let mut claims = json!({"iss":self.issuer,"aud":req.audience,"sub":req.agent_id,
            "exp":now.checked_add(300).ok_or(Error::Invalid("timestamp overflow"))?,"iat":now,"jti":format!("token_{}",random_id()),
            "scope":req.requested_scopes.join(" "),"intent":{"workflow_id":resolution.workflow_id,"workflow_step":workflow_step,
            "executed_by":req.agent_id,"execution_id":req.execution_id,"delegation_chain":sequence_hash(&chain,repr.as_deref()),
            "step_sequence_hash":sequence_hash(&completed,repr.as_deref())},
            "agent_proof":{"agent_checksum":req.computed_checksum,"registration_id":registration}});
        if let Some(jkt) = req.cnf_jkt.as_ref().filter(|s| !s.is_empty()) {
            claims["cnf"] = json!({"jkt":jkt});
        } else if let Some(jwk) = public_jwk {
            claims["cnf"] = json!({"jwk":jwk});
        }
        if let Some(b) = binding {
            claims["vb"] = serde_json::to_value(b)?;
        }
        Ok(claims)
    }
    pub fn mint(
        &mut self,
        req: &MintRequest,
        caller_scopes: &[String],
        now: u64,
    ) -> Result<IntentToken> {
        if !caller_scopes.iter().any(|s| s == "generate:intent-token") {
            return Err(Error::Policy(403, "caller lacks mint capability".into()));
        }
        let claims = self.evaluate(req, caller_scopes, now)?;
        Ok(IntentToken {
            access_token: self.key.sign(&claims)?,
            token_type: "Bearer".into(),
            expires_in: 300,
            scope: req.requested_scopes.clone(),
        })
    }
    /// Additional trusted-executor reservation, separate from Auth51's offline
    /// resource verdict. Durable file receipts remain the replay authority.
    pub fn authorize(
        &mut self,
        token: &str,
        request: &ResourceRequest<'_>,
        now: u64,
    ) -> Result<LocalPermit> {
        let claims = self.verifier.verify(token, request, now, |_| {
            Err(Error::Policy(403, "reference provider unavailable".into()))
        })?;
        let execution = claims["intent"]["execution_id"]
            .as_str()
            .ok_or(Error::Credential)?;
        if !self.executions.contains_key(execution)
            || self.reservations.values().any(|v| v == execution)
        {
            return Err(Error::Credential);
        }
        let reservation = random_id();
        self.reservations
            .insert(reservation.clone(), execution.into());
        Ok(LocalPermit {
            reservation,
            execution: execution.into(),
        })
    }
    pub fn finish(&mut self, permit: LocalPermit, succeeded: bool) -> Result<()> {
        if self.reservations.remove(&permit.reservation).as_deref() != Some(&permit.execution) {
            return Err(Error::Credential);
        }
        if succeeded {
            self.close_execution(&permit.execution);
        }
        Ok(())
    }
}

#[must_use = "finish the operation to release its reservation"]
pub struct LocalPermit {
    reservation: String,
    execution: String,
}

fn hop_id(v: &Value) -> &str {
    v.as_str().or_else(|| v["agent_id"].as_str()).unwrap_or("")
}

/// Python str of a JSON trace value (object insertion order matters).
pub fn python_str(v: &Value) -> Result<String> {
    if let Some(s) = v.as_str() {
        Ok(s.into())
    } else {
        python_repr(v)
    }
}
pub fn python_repr(v: &Value) -> Result<String> {
    match v {
        Value::Null => Ok("None".into()),
        Value::Bool(b) => Ok(if *b { "True" } else { "False" }.into()),
        Value::String(s) => {
            use unicode_general_category::{GeneralCategory as C, get_general_category};
            let quote = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::from(quote);
            for c in s.chars() {
                if c == quote || c == '\\' {
                    out.push('\\');
                    out.push(c);
                } else if c == '\n' {
                    out.push_str("\\n");
                } else if c == '\r' {
                    out.push_str("\\r");
                } else if c == '\t' {
                    out.push_str("\\t");
                } else if c != ' '
                    && matches!(
                        get_general_category(c),
                        C::Control
                            | C::Format
                            | C::PrivateUse
                            | C::Surrogate
                            | C::Unassigned
                            | C::LineSeparator
                            | C::ParagraphSeparator
                            | C::SpaceSeparator
                    )
                {
                    let n = c as u32;
                    out.push_str(&if n <= 255 {
                        format!("\\x{n:02x}")
                    } else if n <= 65535 {
                        format!("\\u{n:04x}")
                    } else {
                        format!("\\U{n:08x}")
                    });
                } else {
                    out.push(c);
                }
            }
            out.push(quote);
            Ok(out)
        }
        Value::Array(a) => Ok(format!(
            "[{}]",
            a.iter()
                .map(python_repr)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Object(m) => Ok(format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| Ok(format!("{}: {}", python_repr(&json!(k))?, python_repr(v)?)))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        v => super::identity::python_json(v),
    }
}

pub fn bump_registration_version(
    previous: Option<(&str, Option<&str>, Option<&str>)>,
    new_v3: Option<&str>,
    new_v4: Option<&str>,
) -> String {
    let Some((version, old_v3, old_v4)) = previous else {
        return "1.0.0".into();
    };
    let nums: Option<Vec<u64>> = version.split('.').map(|n| n.parse().ok()).collect();
    let Some(n) = nums.filter(|n| n.len() == 3) else {
        return "1.0.0".into();
    };
    if new_v3
        .zip(old_v3)
        .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a != b)
    {
        format!("{}.0.0", n[0].saturating_add(1))
    } else if new_v4
        .zip(old_v4)
        .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a != b)
    {
        format!("{}.{}.0", n[0], n[1].saturating_add(1))
    } else {
        format!("{}.{}.{}", n[0], n[1], n[2].saturating_add(1))
    }
}
