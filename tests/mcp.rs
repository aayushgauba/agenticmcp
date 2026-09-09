#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_agentic-mcp");

struct Server {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    dir: PathBuf,
    owner: String,
}

impl Server {
    fn new() -> Self {
        Self::new_for("alice")
    }

    fn new_for(owner: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ajwt-mcp-test-{}", rand::random::<u64>()));
        fs::create_dir_all(dir.join("files")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("files"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("files/example.txt"), "original\n").unwrap();
        let result = Command::new(BIN)
            .arg("keygen")
            .arg("--private")
            .arg(dir.join("approver.key"))
            .arg("--public")
            .arg(dir.join("approver.json"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut child = Command::new(BIN)
            .arg("serve")
            .arg("--root")
            .arg(dir.join("files"))
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--approver")
            .arg(dir.join("approver.json"))
            .args(["--owner", owner])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
            dir,
            owner: owner.into(),
        }
    }

    fn command(&self, name: &str) -> Command {
        let mut command = Command::new(BIN);
        command
            .arg(name)
            .arg("--root")
            .arg(self.dir.join("files"))
            .arg("--state-dir")
            .arg(self.dir.join("state"))
            .arg("--approver")
            .arg(self.dir.join("approver.json"))
            .args(["--owner", &self.owner]);
        command
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn restart(&mut self) {
        self.stop();
        let mut child = self
            .command("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.input = child.stdin.take().unwrap();
        self.output = BufReader::new(child.stdout.take().unwrap());
        self.child = child;
        self.initialize();
    }

    fn send(&mut self, value: Value) {
        writeln!(self.input, "{value}").unwrap();
        self.input.flush().unwrap();
    }

    fn receive(&mut self) -> Value {
        let mut line = String::new();
        assert!(
            self.output.read_line(&mut line).unwrap() > 0,
            "server unexpectedly exited"
        );
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}));
        self.receive()
    }

    fn initialize(&mut self) {
        let reply = self.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"integration-test","version":"1"}}));
        assert_eq!(reply["result"]["protocolVersion"], "2025-11-25");
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }

    fn propose(&mut self) -> Value {
        let inspected = self.call("inspect_file", json!({"path":"example.txt"}));
        assert_eq!(inspected["result"]["isError"], false);
        let proposed = self.call("propose_patch", json!({"path":"example.txt","before_sha256":inspected["result"]["structuredContent"]["sha256"],"replacement":"approved replacement\n"}));
        assert_eq!(proposed["result"]["isError"], false, "{proposed}");
        proposed["result"]["structuredContent"].clone()
    }

    fn approve(&self, proposal: &Value, label: &str) -> String {
        let file = self.dir.join(format!("{label}.json"));
        let receipt = self.dir.join(format!("{label}.receipt"));
        fs::write(&file, serde_json::to_vec(proposal).unwrap()).unwrap();
        let reviewed = Command::new(BIN)
            .arg("review")
            .arg("--proposal")
            .arg(&file)
            .output()
            .unwrap();
        assert!(reviewed.status.success());
        let output = String::from_utf8(reviewed.stdout).unwrap();
        let digest = output
            .lines()
            .last()
            .unwrap()
            .strip_prefix("Proposal SHA-256: ")
            .unwrap();
        let signed = Command::new(BIN)
            .arg("approve")
            .arg("--proposal")
            .arg(file)
            .arg("--private")
            .arg(self.dir.join("approver.key"))
            .args(["--digest", digest])
            .arg("--output")
            .arg(&receipt)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        fs::read_to_string(receipt).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn mcp_real_file_update_requires_external_approval_and_executes_once() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "original\n"
    );
    let id = &proposal["proposal"]["id"];
    let denied = server.call(
        "apply_approved_patch",
        json!({"proposal_id":id,"approval":""}),
    );
    assert_eq!(denied["result"]["isError"], true);
    let receipt = server.approve(&proposal, "reviewed");
    let args = json!({"proposal_id":id,"approval":receipt});
    let applied = server.call("apply_approved_patch", args.clone());
    assert_eq!(applied["result"]["isError"], false, "{applied}");
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "approved replacement\n"
    );
    assert_eq!(
        server.call("apply_approved_patch", args)["result"]["isError"],
        true
    );
    assert_eq!(
        server.call("proposal_status", json!({"proposal_id":id}))["result"]["structuredContent"]["status"],
        "applied"
    );
}

#[test]
fn mcp_rejects_approval_for_modified_proposal_and_wrong_signer() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let mut altered = proposal.clone();
    altered["proposal"]["replacement"] = json!("different replacement");
    let receipt = server.approve(&altered, "altered");
    assert_eq!(
        server.call(
            "apply_approved_patch",
            json!({"proposal_id":proposal["proposal"]["id"],"approval":receipt})
        )["result"]["isError"],
        true
    );
    let wrong = Server::new();
    let receipt = wrong.approve(&proposal, "wrong-signer");
    assert_eq!(
        server.call(
            "apply_approved_patch",
            json!({"proposal_id":proposal["proposal"]["id"],"approval":receipt})
        )["result"]["isError"],
        true
    );
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn mcp_rejects_file_changed_since_approval() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let receipt = server.approve(&proposal, "approved");
    fs::write(server.dir.join("files/example.txt"), "concurrent edit").unwrap();
    let reply = server.call(
        "apply_approved_patch",
        json!({"proposal_id":proposal["proposal"]["id"],"approval":receipt}),
    );
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "concurrent edit"
    );
}

#[test]
fn mcp_cannot_read_outside_root_or_add_fake_approval_arguments() {
    let mut server = Server::new();
    server.initialize();
    for path in [
        "../approver.key",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        ".env",
        "subdir/file.txt",
        "NUL",
    ] {
        assert_eq!(
            server.call("inspect_file", json!({"path":path}))["result"]["isError"],
            true
        );
    }
    assert_eq!(
        server.call(
            "propose_patch",
            json!({"path":"example.txt","before_sha256":"fake","replacement":"bad","approved":true})
        )["result"]["isError"],
        true
    );
    assert_eq!(server.call("approve", json!({}))["error"]["code"], -32602);
}

#[test]
fn mcp_lifecycle_discovery_and_protocol_errors() {
    let mut server = Server::new();
    assert_eq!(
        server.request("tools/list", json!({}))["error"]["code"],
        -32600
    );
    writeln!(server.input, "not-json").unwrap();
    server.input.flush().unwrap();
    assert_eq!(server.receive()["error"]["code"], -32700);
    server.initialize();
    let listed = server.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    assert!(!tools.iter().any(|t| t["name"] == "approve"));
    assert_eq!(
        server.request("unknown", json!({}))["error"]["code"],
        -32601
    );
    server.send(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}),
    );
    assert_eq!(server.request("ping", json!({}))["result"], json!({}));
}

#[test]
fn mcp_approval_is_bound_to_tenant_and_proposal() {
    let mut first = Server::new();
    first.initialize();
    let proposal = first.propose();
    let receipt = first.approve(&proposal, "approved");
    let mut other = Server::new();
    other.initialize();
    let different = other.propose();
    assert_eq!(
        other.call(
            "apply_approved_patch",
            json!({"proposal_id":different["proposal"]["id"],"approval":receipt})
        )["result"]["isError"],
        true
    );
    // Even a valid receipt for this authority cannot be reused for another stored proposal.
    let another = first.propose();
    assert_eq!(
        first.call(
            "apply_approved_patch",
            json!({"proposal_id":another["proposal"]["id"],"approval":receipt})
        )["result"]["isError"],
        true
    );
}

#[cfg(unix)]
#[test]
fn mcp_rejects_symlink_and_hardlink_files() {
    let mut server = Server::new();
    std::os::unix::fs::symlink(
        server.dir.join("approver.key"),
        server.dir.join("files/link.txt"),
    )
    .unwrap();
    fs::hard_link(
        server.dir.join("files/example.txt"),
        server.dir.join("files/hard.txt"),
    )
    .unwrap();
    server.initialize();
    for path in ["link.txt", "hard.txt"] {
        assert_eq!(
            server.call("inspect_file", json!({"path":path}))["result"]["isError"],
            true
        );
    }
}

#[test]
fn approval_cli_requires_the_exact_reviewed_digest() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let file = server.dir.join("proposal.json");
    let output = server.dir.join("should-not-exist.txt");
    fs::write(&file, proposal.to_string()).unwrap();
    let result = Command::new(BIN)
        .arg("approve")
        .arg("--proposal")
        .arg(file)
        .arg("--private")
        .arg(server.dir.join("approver.key"))
        .args(["--digest", "wrong"])
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn mcp_rejects_oversized_files_replacements_and_encoded_proposals() {
    let mut server = Server::new();
    server.initialize();
    let inspected = server.call("inspect_file", json!({"path":"example.txt"}));
    let hash = inspected["result"]["structuredContent"]["sha256"].clone();
    for replacement in ["x".repeat(8193), "\u{0001}".repeat(8192)] {
        assert_eq!(
            server.call(
                "propose_patch",
                json!({"path":"example.txt","before_sha256":hash,"replacement":replacement})
            )["result"]["isError"],
            true
        );
    }
    fs::write(server.dir.join("files/large.txt"), vec![b'x'; 8193]).unwrap();
    assert_eq!(
        server.call("inspect_file", json!({"path":"large.txt"}))["result"]["isError"],
        true
    );
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn mcp_closes_session_on_oversized_message() {
    let mut server = Server::new();
    let bytes = vec![b'x'; 131073];
    let _ = server.input.write_all(&bytes);
    let _ = server.input.flush();
    let status = server.child.wait().unwrap();
    assert!(!status.success());
}

#[test]
fn proposals_and_replay_protection_survive_process_restarts() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let receipt = server.approve(&proposal, "durable");
    let args = json!({"proposal_id":proposal["proposal"]["id"],"approval":receipt});
    server.restart();
    let applied = server.call("apply_approved_patch", args.clone());
    assert_eq!(applied["result"]["isError"], false, "{applied}");
    server.restart();
    // Even if an operator restores original content, an old approval cannot run again.
    fs::write(server.dir.join("files/example.txt"), "original\n").unwrap();
    assert_eq!(
        server.call("apply_approved_patch", args)["result"]["isError"],
        true
    );
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn a_second_process_cannot_execute_against_the_same_root() {
    let mut server = Server::new();
    server.initialize();
    let output = server
        .command("serve")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("another service instance"));
}

#[test]
fn database_cannot_be_rebound_to_another_owner() {
    let mut server = Server::new();
    server.initialize();
    server.stop();
    let output = Command::new(BIN)
        .arg("serve")
        .arg("--root")
        .arg(server.dir.join("files"))
        .arg("--state-dir")
        .arg(server.dir.join("state"))
        .arg("--approver")
        .arg(server.dir.join("approver.json"))
        .args(["--owner", "mallory"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("different owner"));
}

#[test]
fn interrupted_execution_requires_explicit_verified_recovery() {
    for after_write in [false, true] {
        let mut server = Server::new();
        server.initialize();
        let proposal = server.propose();
        let receipt = server.approve(&proposal, "crash");
        let id = proposal["proposal"]["id"].as_str().unwrap();
        server.stop();
        // Simulate the exact durable state at the crash boundary, without adding a
        // production environment-variable failpoint an MCP launcher could activate.
        let db = rusqlite::Connection::open(server.dir.join("state/state.sqlite3")).unwrap();
        db.execute(
            "UPDATE proposals SET status='executing',receipt=?1 WHERE id=?2",
            rusqlite::params![receipt, id],
        )
        .unwrap();
        drop(db);
        if after_write {
            fs::write(
                server.dir.join("files/example.txt"),
                "approved replacement\n",
            )
            .unwrap();
        }
        server.restart();
        assert_eq!(
            server.call("proposal_status", json!({"proposal_id":id}))["result"]["structuredContent"]
                ["status"],
            "uncertain"
        );
        assert_eq!(
            server.call(
                "apply_approved_patch",
                json!({"proposal_id":id,"approval":receipt})
            )["result"]["isError"],
            true
        );
        server.stop();
        server.restart();
        let current = server.call("inspect_file", json!({"path":"example.txt"}));
        assert_eq!(server.call("propose_patch", json!({"path":"example.txt", "before_sha256":current["result"]["structuredContent"]["sha256"], "replacement":"must not overwrite recovery evidence"}))["result"]["isError"], true);
        server.stop();
        let wrong = if after_write { "aborted" } else { "applied" };
        assert!(
            !server
                .command("resolve")
                .args(["--proposal-id", id, "--outcome", wrong])
                .output()
                .unwrap()
                .status
                .success()
        );
        let correct = if after_write { "applied" } else { "aborted" };
        let output = server
            .command("resolve")
            .args(["--proposal-id", id, "--outcome", correct])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        server.restart();
        assert_eq!(
            server.call("proposal_status", json!({"proposal_id":id}))["result"]["structuredContent"]
                ["status"],
            correct
        );
    }
}

#[test]
fn audit_and_backup_preserve_records_without_logging_patch_contents() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    server.stop();
    let output = server.command("audit").output().unwrap();
    assert!(output.status.success());
    let logs = String::from_utf8(output.stdout).unwrap();
    assert!(logs.contains(proposal["proposal"]["id"].as_str().unwrap()));
    assert!(!logs.contains("replacement"));
    let backup = server.dir.join("backup.sqlite3");
    let output = server
        .command("backup")
        .arg("--output")
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let db = rusqlite::Connection::open(&backup).unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM proposals", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn insecure_directory_permissions_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let mut server = Server::new();
    server.initialize();
    server.stop();
    fs::set_permissions(server.dir.join("files"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        !server
            .command("serve")
            .stdin(Stdio::null())
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn public_key_rotation_revokes_old_unexecuted_receipts() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let old = server.approve(&proposal, "old");
    server.stop();
    fs::remove_file(server.dir.join("approver.key")).unwrap();
    fs::remove_file(server.dir.join("approver.json")).unwrap();
    assert!(
        Command::new(BIN)
            .arg("keygen")
            .arg("--private")
            .arg(server.dir.join("approver.key"))
            .arg("--public")
            .arg(server.dir.join("approver.json"))
            .output()
            .unwrap()
            .status
            .success()
    );
    server.restart();
    assert_eq!(
        server.call(
            "apply_approved_patch",
            json!({"proposal_id":proposal["proposal"]["id"],"approval":old})
        )["result"]["isError"],
        true
    );
    let fresh = server.approve(&proposal, "new");
    assert_eq!(
        server.call(
            "apply_approved_patch",
            json!({"proposal_id":proposal["proposal"]["id"],"approval":fresh})
        )["result"]["isError"],
        false
    );
}

#[test]
fn stored_content_tampering_does_not_create_a_valid_approval() {
    let mut server = Server::new();
    server.initialize();
    let proposal = server.propose();
    let receipt = server.approve(&proposal, "original-approval");
    server.stop();
    let mut corrupted = proposal["proposal"].clone();
    corrupted["replacement"] = json!("not approved");
    let db = rusqlite::Connection::open(server.dir.join("state/state.sqlite3")).unwrap();
    db.execute("UPDATE proposals SET body=?1", [corrupted.to_string()])
        .unwrap();
    drop(db);
    server.restart();
    assert_eq!(
        server.call(
            "apply_approved_patch",
            json!({"proposal_id":proposal["proposal"]["id"],"approval":receipt})
        )["result"]["isError"],
        true
    );
    assert_eq!(
        fs::read_to_string(server.dir.join("files/example.txt")).unwrap(),
        "original\n"
    );
}

#[test]
fn separate_tenants_can_execute_concurrently() {
    let threads: Vec<_> = (0..4).map(|tenant| std::thread::spawn(move || {
        let mut server = Server::new_for(&format!("tenant-{tenant}"));
        server.initialize();
        for iteration in 0..8 {
            let current = server.call("inspect_file", json!({"path":"example.txt"}));
            let content = format!("tenant-{tenant}-iteration-{iteration}");
            let proposed = server.call("propose_patch", json!({"path":"example.txt", "before_sha256":current["result"]["structuredContent"]["sha256"], "replacement":content}));
            assert_eq!(proposed["result"]["isError"], false, "{proposed}");
            let proposal = &proposed["result"]["structuredContent"];
            let receipt = server.approve(proposal, &format!("load-{iteration}"));
            let applied = server.call("apply_approved_patch", json!({"proposal_id":proposal["proposal"]["id"], "approval":receipt}));
            assert_eq!(applied["result"]["isError"], false, "{applied}");
            assert_eq!(fs::read_to_string(server.dir.join("files/example.txt")).unwrap(), content);
        }
    })).collect();
    for thread in threads {
        thread.join().unwrap();
    }
}
