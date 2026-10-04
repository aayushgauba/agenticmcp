//! Local desktop workspace profile. Uses normal OS user permissions, not the
//! hardened Linux service's descriptor/ownership boundary. No approval endpoint.
use super::{McpResult, Proposal, PublicKey, crypto, now, store};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};

pub(super) fn validate_path(path: &str) -> McpResult<()> {
    if path.is_empty() || path.len() > 2048 || path.contains('\\') {
        return Err("use a relative workspace path with forward slashes".into());
    }
    for part in path.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|c| c.is_control() || "<>:\"|?*".contains(c))
            || [".git", ".codex", ".agents"]
                .iter()
                .any(|p| part.eq_ignore_ascii_case(p))
        {
            return Err("invalid or protected workspace path".into());
        }
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (1..=9).any(|i| stem == format!("COM{i}") || stem == format!("LPT{i}"))
        {
            return Err("reserved workspace filename".into());
        }
    }
    Ok(())
}

struct Workspace {
    root: PathBuf,
    owner: String,
    approver: PublicKey,
    store: store::Store,
}

impl Workspace {
    fn target(&self, relative: &str) -> McpResult<PathBuf> {
        validate_path(relative)?;
        let mut path = self.root.clone();
        let parts: Vec<_> = relative.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            path.push(part);
            match fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err("links are not supported".into());
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        if meta.file_attributes() & 0x400 != 0 {
                            return Err("reparse points are not supported".into());
                        }
                    }
                    if i < parts.len() - 1 && !meta.is_dir() {
                        return Err("parent is not a directory".into());
                    }
                    if i == parts.len() - 1 && !meta.is_file() {
                        return Err("target must be a regular file".into());
                    }
                    #[cfg(unix)]
                    if i == parts.len() - 1 {
                        use std::os::unix::fs::MetadataExt;
                        if meta.nlink() != 1 {
                            return Err("hard links are not supported".into());
                        }
                    }
                    if !path.canonicalize()?.starts_with(&self.root) {
                        return Err("path leaves workspace".into());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(path)
    }

    fn read(&self, relative: &str) -> McpResult<Option<Vec<u8>>> {
        let target = self.target(relative)?;
        let file = match fs::File::open(target) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(super::MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > super::MAX_FILE || bytes.contains(&0) {
            return Err("workspace text exceeds 8192 bytes or contains binary data".into());
        }
        std::str::from_utf8(&bytes)?;
        Ok(Some(bytes))
    }

    fn hash(&self, relative: &str) -> McpResult<String> {
        Ok(self
            .read(relative)?
            .map_or(String::new(), |b| crypto::hash(&b)))
    }

    fn replace(&self, proposal: &Proposal) -> McpResult<()> {
        let target = self.target(&proposal.path)?;
        // Missing parent directories are created only during signed execution.
        fs::create_dir_all(target.parent().ok_or("missing parent")?)?;
        self.target(&proposal.path)?;
        let temporary = target
            .parent()
            .ok_or("missing parent")?
            .join(format!(".ajwt-{}.tmp", crypto::id()));
        let result = (|| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(proposal.replacement.as_bytes())?;
            if let Ok(metadata) = fs::metadata(&target) {
                file.set_permissions(metadata.permissions())?;
            }
            file.sync_all()?;
            drop(file);
            if self.hash(&proposal.path)? != proposal.before_sha256 {
                return Err("file changed during execution".into());
            }
            self.target(&proposal.path)?;
            fs::rename(&temporary, &target)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn call(&mut self, name: &str, args: &Value) -> McpResult<Value> {
        let string = |field: &str| {
            args[field]
                .as_str()
                .ok_or_else(|| -> Box<dyn std::error::Error> { format!("missing {field}").into() })
        };
        match name {
            "inspect_file" => {
                let path = string("path")?;
                match self.read(path)? {
                    Some(bytes) => Ok(
                        json!({"path":path,"exists":true,"content":std::str::from_utf8(&bytes)?,"sha256":crypto::hash(&bytes)}),
                    ),
                    None => Ok(json!({"path":path,"exists":false,"content":"","sha256":null})),
                }
            }
            "propose_patch" => {
                let path = string("path")?;
                let replacement = string("replacement")?;
                if replacement.len() > super::MAX_FILE || replacement.contains('\0') {
                    return Err("replacement exceeds 8192 bytes or contains binary data".into());
                }
                let before = match args.get("before_sha256") {
                    Some(Value::Null) => "",
                    Some(Value::String(before))
                        if before.len() == 64 && before.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        before
                    }
                    _ => return Err("before_sha256 must be null or a SHA-256".into()),
                };
                self.store.check_file_available(path)?;
                if self.hash(path)? != before {
                    return Err("file changed; inspect again".into());
                }
                let proposal = Proposal {
                    id: crypto::id(),
                    root: self.root.to_str().ok_or("invalid root")?.into(),
                    owner: self.owner.clone(),
                    path: path.into(),
                    before_sha256: before.into(),
                    replacement: replacement.into(),
                    expires_at: now()?.checked_add(600).ok_or("time overflow")?,
                };
                let body = crypto::canonical(&proposal)?;
                if body.len() > 16384 {
                    return Err("proposal exceeds approval size limit".into());
                }
                self.store.insert(&proposal)?;
                Ok(
                    json!({"proposal":proposal,"proposal_sha256":crypto::hash(&body),"status":"pending_approval"}),
                )
            }
            "proposal_status" => {
                let (proposal, status) = self.store.get(string("proposal_id")?)?;
                Ok(
                    json!({"proposal":proposal,"status":if status == "pending" { if proposal.expires_at <= now()? {"expired"} else {"pending_approval"} } else {&status}}),
                )
            }
            "apply_approved_patch" => {
                let id = string("proposal_id")?;
                let receipt = string("approval")?;
                let approved: Proposal =
                    crypto::decode(receipt, &self.approver, super::APPROVAL_TYPE, "approver")?;
                let (proposal, status) = self.store.get(id)?;
                if status != "pending"
                    || proposal != approved
                    || approved.root != self.root.to_str().ok_or("invalid root")?
                    || approved.owner != self.owner
                    || approved.expires_at <= now()?
                {
                    return Err("approval is expired, already used, or does not match this workspace proposal".into());
                }
                self.store.check_file_available(&approved.path)?;
                if self.hash(&approved.path)? != approved.before_sha256 {
                    return Err("file changed since proposal".into());
                }
                let (mut authority, permit) = super::FileServer::authorize_proposal(&approved)?;
                self.store.reserve(id, receipt)?;
                let outcome = self.replace(&approved);
                authority.finish(permit, outcome.is_ok())?;
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
            _ => Err("unknown workspace tool".into()),
        }
    }
}

pub(super) fn cli(args: &[String], check_only: bool) -> McpResult<()> {
    let mut flags = HashMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2
            || !["--root", "--state-dir", "--approver", "--owner"].contains(&pair[0].as_str())
            || flags.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("invalid workspace options".into());
        }
    }
    if flags.len() != 4 {
        return Err(
            "workspace service requires root, state-dir, public approver, and owner".into(),
        );
    }
    let root = Path::new(flags["--root"]).canonicalize()?;
    if !root.is_dir() {
        return Err("workspace root must be a directory".into());
    }
    let owner = flags["--owner"].to_owned();
    if owner.is_empty() || owner.len() > 256 {
        return Err("invalid owner".into());
    }
    let approver: PublicKey =
        serde_json::from_slice(&super::read_limited(Path::new(flags["--approver"]), 4096)?)?;
    approver.validate()?;
    if Path::new(flags["--approver"])
        .canonicalize()?
        .starts_with(&root)
    {
        return Err("public key must be outside workspace".into());
    }
    let store = store::Store::open_workspace(Path::new(flags["--state-dir"]), &root, &owner)?;
    let mut workspace = Workspace {
        root,
        owner,
        approver,
        store,
    };
    if check_only {
        println!("{}", json!({"ready":true,"root":workspace.root}));
        return Ok(());
    }
    let mut initialized = false;
    let input = std::io::stdin();
    let mut input = input.lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let count = std::io::Read::take(&mut input, 131073).read_until(b'\n', &mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        if count > 131072 {
            return Err("MCP message too large".into());
        }
        let message: Value = serde_json::from_slice(&bytes)?;
        let Some(id) = message.get("id") else {
            if message["method"] == "notifications/initialized" {
                initialized = true;
            }
            continue;
        };
        let result = match message["method"].as_str() {
            Some("initialize") => {
                json!({"protocolVersion":message["params"]["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"agentic-jwt-workspace","version":env!("CARGO_PKG_VERSION")}})
            }
            Some("ping") => json!({}),
            Some("tools/call") if initialized => match workspace.call(
                message["params"]["name"].as_str().unwrap_or_default(),
                &message["params"]["arguments"],
            ) {
                Ok(value) => {
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                }
                Err(error) => {
                    json!({"content":[{"type":"text","text":error.to_string()}],"isError":true})
                }
            },
            _ => {
                serde_json::to_writer(
                    &mut output,
                    &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"unsupported workspace method"}}),
                )?;
                output.write_all(b"\n")?;
                output.flush()?;
                continue;
            }
        };
        serde_json::to_writer(
            &mut output,
            &json!({"jsonrpc":"2.0","id":id,"result":result}),
        )?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}
