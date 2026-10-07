# Agentic JWT for Codex

Native Rust workspace tools with a human setup and review page. This Windows package includes the executable, so local use needs no WSL, Rust installation, hand-written connection JSON, or pasted approval JWTs. Node.js 18 or newer must be available to Codex.

## First use

Ask Codex: **“Use Agentic JWT to set up this workspace.”** It calls `setup_workspace` and gives you an **Open setup** link.

1. Open that link, select the managed folder, and click **Enable local review**. The default is the installed plugin folder, as requested. For Django changes, select the Django project's folder instead. These are separate locations.
2. Setup creates the local review key and state directories, verifies the native service, and saves the connection automatically. The assistant never submits this action for you.
3. Return to Codex and retry your file request. The Rust process starts on the first file tool call and is reused until the connection closes.

The setup page requires an existing folder and preserves an already configured external connection. Local keys and state live under `~/.codex/agentic-jwt/`, or the corresponding CODEX_HOME directory, outside the selected workspace. An absolute AGENTIC_JWT_CONFIG may select another connection file.

## Change folder

Open the setup or review link and click **Change folder**, enter an existing absolute folder path, then click **Use this folder**. Codex reconnects automatically on its next file request, after any active call finishes. Each folder retains its own durable proposal history; pending approvals are cleared from the review session when you switch. To resume an earlier proposal after switching back, reopen it with `review_change` and approve it again. External and custom signing connections are preserved.

## Review changes

Ask Codex to inspect a file and propose its replacement. The proposal includes a review link. Open it, inspect the before/after text and exact signed proposal, then click **Approve this exact change** or **Reject**. Tell Codex to apply the approved proposal. Codex passes only its id; the review process supplies the receipt and Rust verifies the signature, workspace, owner, content, expiry, and one-time state before writing.

Approval does not itself write the file. A chat confirmation does not replace the review button. The assistant must never operate setup/approval buttons or access the private key. If you reconnect with a pending proposal, ask Codex to call `review_change` with its id to reopen review.

## Workspace support

- Windows and Linux native workspace mode accepts relative nested paths, including Django templates and application files.
- Missing files use `before_sha256: null`; parent directories are created only when signed file creation is applied.
- UTF-8 text and replacements are limited to 8192 bytes by the current JWT profile.
- Traversal, absolute paths, device filenames, links/junctions, and `.git`, `.codex`, and `.agents` paths are refused. The service verifies the current content hash again before applying.
- Proposal and execution records persist in SQLite. Expired, changed, reused, and mismatched approvals fail. An uncertain execution requires operator investigation; the plugin never blindly replays a failed write.

The local workspace profile runs with your desktop user's normal filesystem permissions. Its same-computer review key and path checks are not an OS sandbox or an isolated external approver. Concurrent hostile filesystem replacement is outside this profile's protection. The hardened Linux service remains separate, with its existing descriptor, ownership, and permission checks.

Codex owns its installed plugin cache and can replace it on updates. Choose that folder only when you intend to edit the plugin installation itself. For normal development select the actual project. State is bound to the configured canonical root.

## Tools

| Tool | Purpose |
| --- | --- |
| `setup_workspace` | Returns configuration status and the human setup link. Cannot generate keys or configure a folder through MCP. |
| `inspect_file` | Reads a file or reports a missing target. |
| `propose_patch` | Stores an exact full-file replacement and returns a review link. |
| `review_change` | Opens the human review page for a pending proposal; cannot approve it. |
| `proposal_status` | Reports durable proposal state. |
| `apply_approved_patch` | Applies once after signed approval. In local mode provide only `proposal_id`. |

## Existing Linux, WSL, and SSH services

Existing `connection.json` configurations are preserved. The examples still support `linux`, `wsl`, and `ssh` modes using the original `agentic-mcp serve` command. Those modes retain top-level existing files, service-owned 0700 directories, a separately provisioned binary/public key, and independently supplied approval receipts. SSH uses the repository's forced-command wrapper and strict host-key checking.

`root: "@plugin"` resolves the installed plugin folder. In WSL it uses `wslpath`; native workspace mode resolves it directly. SSH cannot access this local folder. Windows-mounted WSL folders may fail the hardened Linux permission checks. Local native mode avoids that dependency.

## Development and installation

From the repository root:

```powershell
cargo build --locked --release --bin agentic-mcp
node --test tools/codex-plugin.test.mjs tools/desktop-workflow.test.mjs
node tools/package-codex-plugin.mjs
codex plugin marketplace add .
codex plugin add agentic-jwt@agentic-local
```

Packaging copies the built executable for the current host into the plugin and writes `artifacts/agentic-jwt-0.2.3.zip`. Rebuild on Linux for a Linux executable. The archive includes hidden compatibility manifests and no user keys, receipts, runtime state, or dependency directories. This is a private local plugin, not a public directory submission. Restart Codex or open a new chat after updating.

The source marketplace and install flow follow [OpenAI's plugin packaging guide](https://developers.openai.com/plugins/build/plugins).
