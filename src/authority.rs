use std::collections::{BTreeMap, HashMap, HashSet};
use subtle::ConstantTimeEq;

use crate::{crypto, identity::identifier, *};

struct Client {
    key: PublicKey,
    active: bool,
}
struct Agent {
    client_id: String,
    checksum: String,
    registration_id: String,
    key: PublicKey,
    policy: AgentPolicy,
    active: bool,
}
struct Run {
    workflow: Workflow,
    owner: String,
    next: usize,
    approvals: HashSet<String>,
    in_flight: Option<String>,
    active: bool,
}

/// Trusted in-memory reference authorization server and resource enforcement state.
///
/// Hold this behind a single lock if used concurrently. Administrative registration,
/// approval and completion methods MUST only be called by trusted host code.
/// Agent code should only receive signed-grant and proof construction capabilities.
pub struct Authority {
    issuer: String,
    key: KeyPair,
    kid: String,
    clients: HashMap<String, Client>,
    agents: HashMap<String, Agent>,
    workflows: HashMap<String, Workflow>,
    runs: HashMap<String, Run>,
    replay: BTreeMap<(String, String), u64>,
    last_time: u64,
}

/// An opaque, single-use reservation for an authorized operation.
/// Dropping it leaves the run blocked; the host must explicitly finish it.
#[must_use = "finish the authorized operation to release its workflow reservation"]
pub struct Permit {
    run_id: String,
    reservation: String,
    step: usize,
}

impl Authority {
    pub fn new(issuer: &str) -> Result<Self> {
        let url = url::Url::parse(issuer).map_err(|_| Error::Invalid("issuer"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Invalid("HTTPS issuer required"));
        }
        Ok(Self {
            issuer: issuer.into(),
            key: KeyPair::generate(),
            kid: crypto::id(),
            clients: HashMap::new(),
            agents: HashMap::new(),
            workflows: HashMap::new(),
            runs: HashMap::new(),
            replay: BTreeMap::new(),
            last_time: 0,
        })
    }

    pub fn issuer_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Administrative provisioning. Existing IDs are never silently overwritten.
    pub fn register_client(&mut self, id: &str, key: PublicKey) -> Result<()> {
        identifier(id)?;
        key.validate()?;
        if self.clients.contains_key(id) {
            return Err(Error::Invalid("duplicate client"));
        }
        if self.clients.values().any(|c| c.key == key) || self.agents.values().any(|a| a.key == key)
        {
            return Err(Error::Invalid("duplicate principal key"));
        }
        self.clients.insert(id.into(), Client { key, active: true });
        Ok(())
    }

    /// Administrative registration: recompute the checksum from the full specification.
    pub fn register_agent(
        &mut self,
        client_id: &str,
        spec: &AgentSpec,
        key: PublicKey,
        policy: AgentPolicy,
    ) -> Result<String> {
        self.client(client_id)?;
        key.validate()?;
        if self.agents.contains_key(&spec.agent_id) {
            return Err(Error::Invalid("duplicate agent"));
        }
        if policy.scopes.is_empty() || policy.audiences.is_empty() {
            return Err(Error::Policy);
        }
        for audience in &policy.audiences {
            let url = url::Url::parse(audience).map_err(|_| Error::Policy)?;
            if url.scheme() != "https" || url.origin().ascii_serialization() != *audience {
                return Err(Error::Policy);
            }
        }
        let checksum = spec.checksum()?;
        // Keys must differ across principals, including the application client.
        if self.clients.values().any(|c| c.key == key)
            || self
                .agents
                .values()
                .any(|a| a.key == key || a.checksum == checksum)
        {
            return Err(Error::Invalid("duplicate agent key or checksum"));
        }
        let registration_id = crypto::id();
        self.agents.insert(
            spec.agent_id.clone(),
            Agent {
                client_id: client_id.into(),
                checksum,
                registration_id: registration_id.clone(),
                key,
                policy,
                active: true,
            },
        );
        Ok(registration_id)
    }

    /// Administrative approval of an immutable plan, including permitted delegation edges.
    pub fn register_workflow(&mut self, workflow: Workflow) -> Result<()> {
        identifier(&workflow.id)?;
        if self.workflows.contains_key(&workflow.id)
            || workflow.steps.is_empty()
            || workflow.steps.len() > 32
        {
            return Err(Error::Invalid("duplicate, empty or overly deep workflow"));
        }
        let mut steps = HashSet::new();
        let mut agents = HashSet::new();
        for step in &workflow.steps {
            identifier(&step.id)?;
            if !steps.insert(&step.id) || !agents.insert(&step.agent_id) {
                return Err(Error::Invalid("duplicate step or cyclic agent path"));
            }
            step.action.validate()?;
            self.check_policy(self.agent(&step.agent_id)?, step)?;
        }
        self.workflows.insert(workflow.id.clone(), workflow);
        Ok(())
    }

    /// Trusted host records authenticated resource-owner intent for one execution.
    pub fn start_run(&mut self, workflow_id: &str, resource_owner: &str) -> Result<String> {
        if resource_owner.is_empty() || resource_owner.len() > 256 {
            return Err(Error::Invalid("resource owner"));
        }
        let workflow = self
            .workflows
            .get(workflow_id)
            .ok_or(Error::Workflow)?
            .clone();
        for step in &workflow.steps {
            self.agent(&step.agent_id)?;
        }
        let id = crypto::id();
        self.runs.insert(
            id.clone(),
            Run {
                workflow,
                owner: resource_owner.into(),
                next: 0,
                approvals: HashSet::new(),
                in_flight: None,
                active: true,
            },
        );
        Ok(id)
    }

    /// Host-only approval, bound to run, current step and its immutable exact action.
    pub fn approve(&mut self, run_id: &str, step_id: &str, resource_owner: &str) -> Result<()> {
        let run = self.runs.get_mut(run_id).ok_or(Error::Workflow)?;
        let step = run.workflow.steps.get(run.next).ok_or(Error::Workflow)?;
        if !run.active
            || run.in_flight.is_some()
            || step.id != step_id
            || run.owner != resource_owner
            || !step.requires_approval
        {
            return Err(Error::Approval);
        }
        run.approvals.insert(step_id.into());
        Ok(())
    }

    /// Convenience for the shim: construct a request from trusted current execution state.
    /// It is still untrusted input until `issue` authenticates and validates it.
    pub fn request_for(&self, run_id: &str, spec: &AgentSpec) -> Result<TokenRequest> {
        let run = self.run(run_id)?;
        let step = &run.workflow.steps[run.next];
        Ok(TokenRequest {
            grant_type: GRANT_TYPE.into(),
            agent_id: spec.agent_id.clone(),
            computed_checksum: spec.checksum()?,
            workflow_id: run.workflow.id.clone(),
            workflow_step: step.id.clone(),
            workflow_enabled: true,
            requested_scopes: vec![step.action.scope.clone()],
            audience: step.audience.clone(),
            delegation_context: Self::context(run),
            run_id: run_id.into(),
        })
    }

    /// Authenticate both client and agent, enforce workflow state, then mint an intent JWT.
    pub fn issue(&mut self, grant: &SignedGrant, now: u64) -> Result<TokenResponse> {
        self.tick(now)?;
        fresh(grant.iat, now)?;
        if grant.issuer != self.issuer || grant.jti.is_empty() || grant.jti.len() > 128 {
            return Err(Error::Policy);
        }
        let request = &grant.request;
        if request.grant_type != GRANT_TYPE && request.grant_type != "agent_checksum" {
            return Err(Error::GrantType);
        }
        let client = self.client(&grant.client_id)?;
        let agent = self.agent(&request.agent_id)?;
        if agent.client_id != grant.client_id {
            return Err(Error::Identity);
        }
        let client_input = grant.signing_input("client")?;
        if client_input.len() > 32_768 {
            return Err(Error::Invalid("grant too large"));
        }
        client.key.verify(&client_input, &grant.client_signature)?;
        agent
            .key
            .verify(&grant.signing_input("agent")?, &grant.agent_signature)?;
        let replay_key = (format!("grant:{}", grant.client_id), grant.jti.clone());
        if self.replay.contains_key(&replay_key) {
            return Err(Error::Replay);
        }
        if request.computed_checksum.len() != agent.checksum.len()
            || !bool::from(
                request
                    .computed_checksum
                    .as_bytes()
                    .ct_eq(agent.checksum.as_bytes()),
            )
        {
            return Err(Error::Checksum);
        }
        let run = self.run(&request.run_id)?;
        let step = &run.workflow.steps[run.next];
        if !request.workflow_enabled
            || request.workflow_id != run.workflow.id
            || request.workflow_step != step.id
            || request.agent_id != step.agent_id
            || request.delegation_context != Self::context(run)
        {
            return Err(Error::Workflow);
        }
        self.check_path(run)?;
        self.check_policy(agent, step)?;
        if request.audience != step.audience
            || request.requested_scopes != vec![step.action.scope.clone()]
        {
            return Err(Error::Policy);
        }
        if step.requires_approval && !run.approvals.contains(&step.id) {
            return Err(Error::Approval);
        }
        let claims = IntentClaims {
            iss: self.issuer.clone(),
            aud: step.audience.clone(),
            sub: step.agent_id.clone(),
            iat: now,
            exp: now.checked_add(TOKEN_LIFETIME).ok_or(Error::Time)?,
            jti: crypto::id(),
            scope: step.action.scope.clone(),
            cnf: Confirmation {
                jwk: agent.key.clone(),
            },
            intent: Self::intent(&request.run_id, run),
            agent_proof: AgentProof {
                agent_checksum: agent.checksum.clone(),
                registration_id: agent.registration_id.clone(),
            },
        };
        let access_token = crypto::encode(&claims, &self.key, TOKEN_TYPE, &self.kid)?;
        self.replay.insert(
            replay_key,
            now.checked_add(PROOF_LIFETIME).ok_or(Error::Time)?,
        );
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: TOKEN_LIFETIME,
            scope: claims.scope,
        })
    }

    /// Verify the issuer signature and temporal claims. This alone is NOT authorization.
    /// Resource handlers must call `authorize`, which also checks proof and live policy.
    pub fn inspect_token(&self, token: &str, now: u64) -> Result<IntentClaims> {
        let claims: IntentClaims =
            crypto::decode(token, &self.issuer_key(), TOKEN_TYPE, &self.kid)?;
        if claims.iss != self.issuer || claims.jti.is_empty() {
            return Err(Error::Policy);
        }
        if claims.iat > now
            || claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > TOKEN_LIFETIME
        {
            return Err(Error::Time);
        }
        Ok(claims)
    }

    /// Resource-server entry point. `actual` MUST be built from the received HTTP method,
    /// URI and body bytes, with `scope` chosen by the resource handler's route policy.
    /// Atomically consumes the proof and reserves the step before returning a permit.
    pub fn authorize(
        &mut self,
        token: &str,
        proof: &str,
        audience: &str,
        actual: &Action,
        now: u64,
    ) -> Result<Permit> {
        self.tick(now)?;
        actual.validate()?;
        let claims = self.inspect_token(token, now)?;
        if claims.aud != audience {
            return Err(Error::Policy);
        }
        let agent = self.agent(&claims.sub)?;
        if claims.cnf.jwk != agent.key
            || claims.agent_proof.registration_id != agent.registration_id
            || claims.agent_proof.agent_checksum != agent.checksum
        {
            return Err(Error::Identity);
        }
        let proof: RequestProof = crypto::decode(proof, &agent.key, PROOF_TYPE, &claims.sub)?;
        fresh(proof.iat, now)?;
        if proof.jti.is_empty() || proof.jti.len() > 128 {
            return Err(Error::Invalid("proof ID"));
        }
        if proof.token_sha256 != crypto::hash(token.as_bytes())
            || &proof.action != actual
            || &claims.intent.action != actual
        {
            return Err(Error::Action);
        }
        let replay_key = (format!("proof:{}", claims.sub), proof.jti);
        if self.replay.contains_key(&replay_key) {
            return Err(Error::Replay);
        }
        let run = self.run(&claims.intent.run_id)?;
        let step = &run.workflow.steps[run.next];
        self.check_path(run)?;
        self.check_policy(agent, step)?;
        if claims.intent != Self::intent(&claims.intent.run_id, run)
            || claims.sub != step.agent_id
            || claims.scope != step.action.scope
            || claims.aud != step.audience
        {
            return Err(Error::Workflow);
        }
        if step.requires_approval && !run.approvals.contains(&step.id) {
            return Err(Error::Approval);
        }
        let permit = Permit {
            run_id: claims.intent.run_id.clone(),
            reservation: crypto::id(),
            step: run.next,
        };
        self.replay.insert(
            replay_key,
            proof.iat.checked_add(PROOF_LIFETIME).ok_or(Error::Time)?,
        );
        self.runs
            .get_mut(&permit.run_id)
            .ok_or(Error::Workflow)?
            .in_flight = Some(permit.reservation.clone());
        Ok(permit)
    }

    /// Trusted resource host reports the actual operation outcome. Success advances the
    /// workflow; failure releases it for a retry with a fresh proof. Never call this from
    /// agent-supplied `completed_steps`. A real service needs durable execution receipts.
    pub fn finish(&mut self, permit: Permit, succeeded: bool) -> Result<()> {
        let run = self.runs.get_mut(&permit.run_id).ok_or(Error::Workflow)?;
        if run.next != permit.step || run.in_flight.as_ref() != Some(&permit.reservation) {
            return Err(Error::Workflow);
        }
        run.in_flight = None;
        if succeeded {
            run.next += 1;
        }
        Ok(())
    }

    pub fn is_complete(&self, run_id: &str) -> Result<bool> {
        let run = self.runs.get(run_id).ok_or(Error::Workflow)?;
        Ok(run.active && run.next == run.workflow.steps.len())
    }

    pub fn revoke_agent(&mut self, agent_id: &str) -> Result<()> {
        self.agents.get_mut(agent_id).ok_or(Error::Identity)?.active = false;
        Ok(())
    }

    pub fn revoke_client(&mut self, client_id: &str) -> Result<()> {
        self.clients
            .get_mut(client_id)
            .ok_or(Error::Identity)?
            .active = false;
        Ok(())
    }

    pub fn revoke_run(&mut self, run_id: &str) -> Result<()> {
        self.runs.get_mut(run_id).ok_or(Error::Workflow)?.active = false;
        Ok(())
    }

    fn client(&self, id: &str) -> Result<&Client> {
        self.clients
            .get(id)
            .filter(|c| c.active)
            .ok_or(Error::Identity)
    }

    fn agent(&self, id: &str) -> Result<&Agent> {
        let agent = self
            .agents
            .get(id)
            .filter(|a| a.active)
            .ok_or(Error::Identity)?;
        self.client(&agent.client_id)?;
        Ok(agent)
    }

    fn run(&self, id: &str) -> Result<&Run> {
        self.runs
            .get(id)
            .filter(|r| r.active && r.next < r.workflow.steps.len() && r.in_flight.is_none())
            .ok_or(Error::Workflow)
    }

    fn context(run: &Run) -> DelegationContext {
        DelegationContext {
            chain: run.workflow.steps[..=run.next]
                .iter()
                .map(|s| s.agent_id.clone())
                .collect(),
            completed_steps: run.workflow.steps[..run.next]
                .iter()
                .map(|s| s.id.clone())
                .collect(),
        }
    }

    fn intent(run_id: &str, run: &Run) -> Intent {
        let step = &run.workflow.steps[run.next];
        let context = Self::context(run);
        let mut sequence = context.completed_steps;
        sequence.push(step.id.clone());
        Intent {
            workflow_id: run.workflow.id.clone(),
            workflow_step: step.id.clone(),
            executed_by: step.agent_id.clone(),
            delegation_chain: sequence_hash(&context.chain),
            step_sequence_hash: sequence_hash(&sequence),
            run_id: run_id.into(),
            resource_owner: run.owner.clone(),
            action: step.action.clone(),
        }
    }

    fn check_path(&self, run: &Run) -> Result<()> {
        for step in &run.workflow.steps[..=run.next] {
            self.agent(&step.agent_id)?;
        }
        Ok(())
    }

    fn check_policy(&self, agent: &Agent, step: &Step) -> Result<()> {
        let url = url::Url::parse(&step.action.uri).map_err(|_| Error::Policy)?;
        if !agent.policy.scopes.contains(&step.action.scope)
            || !agent.policy.audiences.contains(&step.audience)
            || url.origin().ascii_serialization() != step.audience
        {
            return Err(Error::Policy);
        }
        Ok(())
    }

    fn tick(&mut self, now: u64) -> Result<()> {
        // Caller supplies trusted server time. Refuse clock rollback after cache pruning.
        if now < self.last_time {
            return Err(Error::Time);
        }
        self.last_time = now;
        self.replay.retain(|_, expires| *expires > now);
        Ok(())
    }
}
