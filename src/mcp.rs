//! Bounded stdio MCP adapter and a separate approval CLI.
mod files;
mod store;
mod transport;
mod workspace;

use crate::{crypto, *};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

type McpResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_FILE: usize = 8192;
const ISSUER: &str = "https://agentic-mcp.invalid";
const AUDIENCE: &str = "https://files.agentic-mcp.invalid";
const APPROVAL_TYPE: &str = "ajwt-file-approval+jwt";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    id: String,
    root: String,
    owner: String,
    path: String,
    before_sha256: String,
    replacement: String,
    expires_at: u64,
}

struct FileServer {
    data: files::DataDir,
    owner: String,
    approver: PublicKey,
    store: store::Store,
}

fn now() -> McpResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn read_limited(path: &Path, limit: usize) -> McpResult<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds size limit".into());
    }
    Ok(bytes)
}

fn filename(name: &str) -> McpResult<()> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(
            "path must be a top-level ASCII filename, without directories or a leading dot".into(),
        );
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || (1..=9).any(|i| stem == format!("COM{i}") || stem == format!("LPT{i}"))
    {
        return Err("reserved filename".into());
    }
    Ok(())
}

fn create_file(path: &Path, bytes: &[u8], private: bool) -> McpResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

impl FileServer {
    fn new(root: &Path, state_dir: &Path, owner: String, approver: PublicKey) -> McpResult<Self> {
        if owner.is_empty() || owner.len() > 256 {
            return Err("invalid owner".into());
        }
        approver.validate()?;
        let data = files::DataDir::open(root)?;
        let store = store::Store::open(state_dir, &data.path, &owner)?;
        Ok(Self {
            data,
            owner,
            approver,
            store,
        })
    }

    fn authorize(
        &self,
        proposal: &Proposal,
    ) -> McpResult<(auth51::LocalAuthority, auth51::LocalPermit)> {
        Self::authorize_proposal(proposal)
    }

    fn authorize_proposal(
        proposal: &Proposal,
    ) -> McpResult<(auth51::LocalAuthority, auth51::LocalPermit)> {
        // Tokens never leave this trusted adapter. A fresh ephemeral authority is
        // sufficient per execution; durable replay/idempotency is enforced in SQLite.
        use auth51::*;
        use std::sync::{Arc, OnceLock};
        static ISSUER_KEY: OnceLock<Arc<IssuerKey>> = OnceLock::new();
        let key = if let Some(key) = ISSUER_KEY.get() {
            key.clone()
        } else {
            let key = Arc::new(IssuerKey::generate()?);
            let _ = ISSUER_KEY.set(key.clone());
            ISSUER_KEY.get().cloned().unwrap_or(key)
        };
        let mut authority = LocalAuthority::new(ISSUER, "mcp-adapter", key)?;
        let holder = ProofKey::generate();
        let spec = Components {
            agent_id: "mcp-file-executor".into(),
            prompt_template: "Execute only the exact independently approved file replacement."
                .into(),
            tools: vec![
                json!({"name":"apply_approved_patch", "description":"Replace an approved file",
                "parameters":{"type":"object","properties":{"proposal_sha256":{"type":"string"}}}}),
            ],
            configuration: json!({"adapter":"stdio-durable-v1", "root":proposal.root, "owner":proposal.owner}),
        };
        let uri = format!("{AUDIENCE}/proposals/{}", proposal.id);
        let scope = derive_scope(
            "files.agentic-mcp.invalid",
            "PUT",
            &format!("/proposals/{}", proposal.id),
        )?;
        authority.register_agent(
            &spec,
            Grant {
                allowed_scopes: vec![scope.clone()],
                step_up_scopes: vec![],
                mode: Mode::Enforce,
                expires_at: Some(proposal.expires_at),
            },
        )?;
        authority.set_tier(&spec.agent_id, "apply_approved_patch", "DESTRUCTIVE");
        let proposal_hash = crypto::hash(&crypto::canonical(proposal)?);
        // This host-only function is called after the full independent approval
        // receipt has been verified against the persisted proposal.
        authority.register_workflow(Dag {workflow_id:proposal.id.clone(),workflow_type:"dag".into(),mode:Mode::Enforce,control:Control::Strict,
            steps:[("approval".into(),WorkflowStep {agent:"human-approver".into(),action:"ApproveHighConsequence".into(),approval_gate:true,..Default::default()}),
                ("z_apply".into(),WorkflowStep {agent:spec.agent_id.clone(),action:"apply_approved_patch".into(),scopes:vec![scope.clone()],dependencies:vec!["approval".into()],requires_approval:true,value_bound:true,
                    value_bounds:vec![json!({"target":"self.in.proposal_sha256","op":"==","operand":{"lit":proposal_hash}})],..Default::default()})].into()})?;
        let execution = authority.open_execution(Some(&proposal.id), Mode::Enforce);
        let time = now()?;
        let values = json!({"proposal_sha256":proposal_hash});
        let request = MintRequest {
            grant_type: "agent_checksum".into(),
            agent_id: spec.agent_id.clone(),
            computed_checksum: spec.checksum_v4()?,
            requested_scopes: vec![scope.clone()],
            audience: AUDIENCE.into(),
            execution_id: Some(execution.execution_id),
            workflow_id: None,
            workflow_enabled: true,
            workflow_step: Some(
                json!({"agent_id":spec.agent_id,"tool_name":"apply_approved_patch"}),
            ),
            action_args: Some(values.clone()),
            delegation_context: Some(Delegation {
                chain: vec![json!(spec.agent_id)],
                completed_steps: vec![
                    json!({"agent_id":"human-approver","tool_name":"ApproveHighConsequence"}),
                ],
            }),
            cnf_jkt: Some(holder.thumbprint()?),
        };
        let token = authority.mint(&request, &["generate:intent-token".into()], time)?;
        let proof = holder.proof("PUT", &uri, Some(&token.access_token), None, time)?;
        let scopes = vec![scope];
        let resource = ResourceRequest {
            method: "PUT",
            uri: &uri,
            audience: Some(AUDIENCE),
            scopes: &scopes,
            proof: Some(&proof),
            legacy_pop: None,
            legacy_timestamp: None,
            values: &values,
        };
        let permit = authority.authorize(&token.access_token, &resource, time)?;
        Ok((authority, permit))
    }

    fn read(&self, path: &str) -> McpResult<Vec<u8>> {
        self.data.read(path)
    }

    fn propose(&mut self, path: String, before: String, replacement: String) -> McpResult<Value> {
        self.store.check_file_available(&path)?;
        if replacement.len() > MAX_FILE {
            return Err("replacement exceeds 8192 bytes".into());
        }
        let original = self.read(&path)?;
        std::str::from_utf8(&original)?;
        if crypto::hash(&original) != before {
            return Err("file changed: inspect it again before proposing".into());
        }
        let id = crypto::id();
        let proposal = Proposal {
            id: id.clone(),
            root: self.data.path.to_str().ok_or("invalid root")?.into(),
            owner: self.owner.clone(),
            path,
            before_sha256: before,
            replacement,
            expires_at: now()?.checked_add(600).ok_or("time overflow")?,
        };
        let body = crypto::canonical(&proposal)?;
        if body.len() > 16_384 {
            return Err("encoded proposal exceeds approval token limit".into());
        }
        let result = json!({"proposal":proposal, "proposal_sha256":crypto::hash(&body), "status":"pending_approval"});
        self.store.insert(&proposal)?;
        Ok(result)
    }

    fn apply(&mut self, id: &str, receipt: &str) -> McpResult<Value> {
        let approved: Proposal =
            crypto::decode(receipt, &self.approver, APPROVAL_TYPE, "approver")?;
        let (proposal, status) = self.store.get(id)?;
        if status != "pending" {
            return Err("proposal is not pending; inspect status or contact the operator".into());
        }
        if approved != proposal
            || approved.owner != self.owner
            || Path::new(&approved.root) != self.data.path
        {
            return Err("approval does not match the stored proposal".into());
        }
        self.store.check_file_available(&approved.path)?;
        let time = now()?;
        if approved.expires_at <= time {
            return Err("proposal approval expired".into());
        }
        if crypto::hash(&self.read(&approved.path)?) != approved.before_sha256 {
            return Err("file changed since proposal; create a new proposal".into());
        }
        let (mut authority, permit) = self.authorize(&approved)?;
        self.store.reserve(id, receipt)?;
        let outcome = self.data.replace(&approved);
        authority.finish(permit, outcome.is_ok())?;
        // Any failure after durable reservation is ambiguous. Never blindly retry it.
        self.store.finish(
            id,
            if outcome.is_ok() {
                "applied"
            } else {
                "uncertain"
            },
        )?;
        if outcome.is_err() {
            return Err("execution outcome requires operator recovery; do not retry".into());
        }
        Ok(
            json!({"proposal_id":id,"status":"applied","path":approved.path,"sha256":crypto::hash(approved.replacement.as_bytes())}),
        )
    }

    fn call(&mut self, name: &str, arguments: Value) -> McpResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Inspect {
            path: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Propose {
            path: String,
            before_sha256: String,
            replacement: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Status {
            proposal_id: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Apply {
            proposal_id: String,
            approval: String,
        }
        match name {
            "inspect_file" => {
                let args: Inspect = serde_json::from_value(arguments)?;
                let bytes = self.read(&args.path)?;
                Ok(
                    json!({"path":args.path,"content":std::str::from_utf8(&bytes)?,"sha256":crypto::hash(&bytes)}),
                )
            }
            "propose_patch" => {
                let args: Propose = serde_json::from_value(arguments)?;
                self.propose(args.path, args.before_sha256, args.replacement)
            }
            "proposal_status" => {
                let args: Status = serde_json::from_value(arguments)?;
                let (proposal, status) = self.store.get(&args.proposal_id)?;
                Ok(
                    json!({"proposal":proposal,"status":if status == "pending" {if proposal.expires_at <= now()? {"expired"} else {"pending_approval"}} else {&status}}),
                )
            }
            "apply_approved_patch" => {
                let args: Apply = serde_json::from_value(arguments)?;
                self.apply(&args.proposal_id, &args.approval)
            }
            _ => Err("unknown tool".into()),
        }
    }
}

fn load_proposal(path: &Path, workspace: bool) -> McpResult<Proposal> {
    let value: Value = serde_json::from_slice(&read_limited(path, 131072)?)?;
    let proposal: Proposal =
        serde_json::from_value(value.get("proposal").cloned().unwrap_or(value))?;
    if workspace {
        workspace::validate_path(&proposal.path)?;
    } else {
        filename(&proposal.path)?;
    }
    if proposal.replacement.len() > MAX_FILE || proposal.expires_at <= now()? {
        return Err("oversized or expired proposal".into());
    }
    Ok(proposal)
}

/// Entry point for `agentic-mcp serve|keygen|review|approve`.
pub fn cli(args: Vec<String>) -> McpResult<()> {
    if args
        .first()
        .is_some_and(|command| command == "serve-workspace" || command == "check-workspace")
    {
        return workspace::cli(&args[1..], args[0] == "check-workspace");
    }
    if args.is_empty() || args == ["--help"] {
        println!(
            "agentic-mcp serve --root DIR --state-dir STATE --approver PUBLIC.json --owner NAME\nagentic-mcp audit --root DIR --state-dir STATE --approver PUBLIC.json --owner NAME\nagentic-mcp backup --root DIR --state-dir STATE --approver PUBLIC.json --owner NAME --output BACKUP.sqlite3\nagentic-mcp resolve --root DIR --state-dir STATE --approver PUBLIC.json --owner NAME --proposal-id ID --outcome applied|aborted\nagentic-mcp keygen --private SECRET.key --public PUBLIC.json\nagentic-mcp review --proposal PROPOSAL.json\nagentic-mcp approve --proposal PROPOSAL.json --private SECRET.key --digest REVIEWED_SHA256 --output RECEIPT.txt\n\nLinux service: data/state directories must be private (0700). Stop active sessions before admin commands. MCP exposes no approval or recovery tools."
        );
        return Ok(());
    }
    let command = &args[0];
    let allowed: &[&str] = match command.as_str() {
        "serve" | "audit" => &["--root", "--state-dir", "--approver", "--owner"],
        "backup" => &["--root", "--state-dir", "--approver", "--owner", "--output"],
        "resolve" => &[
            "--root",
            "--state-dir",
            "--approver",
            "--owner",
            "--proposal-id",
            "--outcome",
        ],
        "keygen" => &["--private", "--public"],
        "review" | "review-workspace" => &["--proposal"],
        "approve" | "approve-workspace" => &["--proposal", "--private", "--digest", "--output"],
        _ => return Err("unknown command; use --help".into()),
    };
    let mut flags = HashMap::new();
    for pair in args[1..].chunks(2) {
        if pair.len() != 2
            || !allowed.contains(&pair[0].as_str())
            || flags.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("unknown, duplicate, or missing command option".into());
        }
    }
    if flags.len() != allowed.len() {
        return Err("missing required option; use --help".into());
    }
    match command.as_str() {
        "serve" | "audit" | "backup" | "resolve" => {
            let approver_path = Path::new(flags["--approver"]);
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = fs::symlink_metadata(approver_path)?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o022 != 0
                    || (metadata.uid() != 0
                        && metadata.uid() != rustix::process::geteuid().as_raw())
                {
                    return Err("approver configuration must be a protected regular file owned by root or the service".into());
                }
            }
            let approver: PublicKey = serde_json::from_slice(&read_limited(approver_path, 4096)?)?;
            let mut server = FileServer::new(
                Path::new(flags["--root"]),
                Path::new(flags["--state-dir"]),
                flags["--owner"].into(),
                approver,
            )?;
            let config_path = approver_path.canonicalize()?;
            if config_path.starts_with(&server.data.path)
                || config_path.starts_with(Path::new(flags["--state-dir"]).canonicalize()?)
            {
                return Err(
                    "approver configuration must be outside data and state directories".into(),
                );
            }
            match command.as_str() {
                "serve" => {
                    eprintln!(
                        "{}",
                        json!({"event":"service_started","owner":server.owner,"version":env!("CARGO_PKG_VERSION")})
                    );
                    transport::serve(
                        &mut server,
                        std::io::stdin().lock(),
                        std::io::stdout().lock(),
                    )?;
                }
                "audit" => println!("{}", serde_json::to_string_pretty(&server.store.audit()?)?),
                "backup" => server.store.backup(Path::new(flags["--output"]))?,
                "resolve" => {
                    let id = flags["--proposal-id"];
                    let outcome = flags["--outcome"];
                    if server.store.get(id)?.1 != "uncertain" {
                        return Err("only uncertain executions may be resolved".into());
                    }
                    let proposal = server.store.approved(id, &server.approver)?;
                    let expected = match outcome {
                        "applied" => crypto::hash(proposal.replacement.as_bytes()),
                        "aborted" => proposal.before_sha256.clone(),
                        _ => return Err("outcome must be applied or aborted".into()),
                    };
                    if crypto::hash(&server.read(&proposal.path)?) != expected {
                        return Err("file does not match the selected outcome; investigate before resolving".into());
                    }
                    server.store.finish(id, outcome)?;
                    println!("{}", json!({"proposal_id":id,"status":outcome}));
                }
                _ => unreachable!(),
            }
        }
        "keygen" => {
            let key = KeyPair::generate();
            create_file(
                Path::new(flags["--private"]),
                B64.encode(key.secret_bytes()).as_bytes(),
                true,
            )?;
            create_file(
                Path::new(flags["--public"]),
                &serde_json::to_vec_pretty(&key.public_key())?,
                false,
            )?;
            println!(
                "Created approver keys. Protect the private key with OS permissions; never give it to the MCP client."
            );
        }
        "review" | "review-workspace" => {
            let proposal = load_proposal(
                Path::new(flags["--proposal"]),
                command == "review-workspace",
            )?;
            // JSON escaping prevents untrusted file contents from emitting terminal controls.
            println!(
                "{}\nProposal SHA-256: {}",
                serde_json::to_string_pretty(&proposal)?,
                crypto::hash(&crypto::canonical(&proposal)?)
            );
        }
        "approve" | "approve-workspace" => {
            let proposal = load_proposal(
                Path::new(flags["--proposal"]),
                command == "approve-workspace",
            )?;
            if crypto::hash(&crypto::canonical(&proposal)?) != flags["--digest"] {
                return Err("reviewed digest does not match proposal".into());
            }
            let private_path = Path::new(flags["--private"]);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = fs::symlink_metadata(private_path)?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(
                        "approval key must be a private regular file (0600), without links".into(),
                    );
                }
            }
            let secret = zeroize::Zeroizing::new(read_limited(private_path, 128)?);
            let decoded =
                zeroize::Zeroizing::new(B64.decode(std::str::from_utf8(&secret)?.trim())?);
            let bytes: [u8; 32] = decoded
                .as_slice()
                .try_into()
                .map_err(|_| "invalid private key length")?;
            let bytes = zeroize::Zeroizing::new(bytes);
            let key = KeyPair::from_secret(&bytes);
            let receipt = crypto::encode(&proposal, &key, APPROVAL_TYPE, "approver")?;
            create_file(Path::new(flags["--output"]), receipt.as_bytes(), false)?;
            println!(
                "Approval receipt written. Only this exact proposal is authorized until {}.",
                proposal.expires_at
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}
