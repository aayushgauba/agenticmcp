# Agentic Workspace MCP

A VS Code extension that gives Copilot and Codex MCP tools for inspecting, proposing, and applying approved changes in the open workspace. Both clients use the same human review UI in VS Code. Runs natively on Windows, macOS, and Linux; no WSL, Rust binary, external keys, or manual MCP root configuration is needed.

This is a separate **VS Code workspace adapter**, not a wrapper around the repository's Linux-only Rust `agentic-mcp` executable. Approval lives in the extension host's memory and comes from a human confirmation in VS Code. It does not issue or accept Rust JWT approval receipts or use the Rust durable audit database.

## Install and use

1. Install the generated `agentic-workspace-0.1.5.vsix` using **Extensions: Install from VSIX...** in the Command Palette, then run **Developer: Reload Window**.
2. Open the repository you want to edit in a trusted VS Code window (VS Code 1.103 or later).
3. Run **Agentic Workspace: Open MCP Servers** (or **MCP: List Servers**), select **Agentic Workspace**, and start/allow the server when prompted. Enable its tools in Copilot's tools picker. Disable the old manually configured `agentic-files` server to avoid confusing the two adapters.
4. Ask Copilot: “Use Agentic Workspace to inspect py/aiwaf/processor.py and propose the required change. Wait for my approval before applying it.”
5. Click **Review Changes** or run **Agentic Workspace: Review Pending Change**. Select the proposal and inspect the read-only before/after diff. Click **Continue Review**, then **Approve** or **Reject**.
6. Tell Copilot to call `apply_approved_patch` with the proposal id. Approval itself does not write the file. Have Copilot inspect the result.

For a new file: “Use Agentic Workspace to inspect notes.txt. If missing, propose creating it with Hello! followed by a newline.” Inspection returns `exists: false` and `sha256: null`; the proposal uses `before_sha256: null`. The parent directory must already exist.

**Agentic Workspace: Show Status** opens a local output channel with proposal ids and statuses. Reload the window after adding/removing workspace folders. The extension installs on the workspace extension host; remote environments are experimental and may need loopback port forwarding. Desktop local workspaces are the initial target. Browser/virtual workspaces are unsupported.

If the server is missing, run **Agentic Workspace: Show Status** in that same window. Version 0.1.1 records startup, skipped folders, registration, and discovery errors. A file-only window has no workspace root: use **File > Open Folder** and reload. Restricted Mode disables the extension; trust the folder only if appropriate. Extension-provided servers do not need an entry in `.vscode/mcp.json`.

## Connect Codex with VS Code review

1. Install the VSIX and run **Developer: Reload Window** to activate the update.
2. Open the intended trusted local workspace and run **Agentic Workspace: Connect Codex** from the Command Palette.
3. The command adds or replaces `[mcp_servers.agentic_workspace]` in the user configuration at `$CODEX_HOME/config.toml` (or `~/.codex/config.toml` when `CODEX_HOME` is unset). It backs up an existing configuration, preserves unrelated settings and comments, and writes the connection directly. No clipboard or manual TOML editing is required.
4. In the **Codex sidebar**, open the gear menu, select **MCP servers**, and use **Restart extension**. The server should appear as `agentic_workspace`. Start a new task if an existing task has not loaded the tools.
5. Ask Codex: "Use agentic_workspace to inspect notes.txt and propose the requested change. Wait for approval in VS Code before applying."
6. Run **Agentic Workspace: Review Pending Change**, inspect the diff, and approve or reject. Have Codex call `apply_approved_patch` after approval.

Keep the VS Code window open. After a reload, a previously connected workspace updates its endpoint automatically. Restart Codex if it attempted to connect before that update finished. The extension does not automatically restart Codex or interrupt its tasks. The server is optional (`required = false`), so closing VS Code does not block unrelated Codex sessions.

Connection details remain private in the user configuration. Each explicit Connect operation backs up the prior configuration next to it; the status output shows the backup path. Automatic refresh does not create repeated backups. The updater validates TOML before writing and refuses unsupported inline `mcp_servers` layouts without changing the file. Standard, quoted, and dotted server tables are supported. Avoid editing the configuration concurrently with setup.

Automatic refresh happens only after this workspace has used Connect Codex and only while its server entry still matches the last saved connection. If another window or a manual edit changed that entry, refresh is skipped. Run Connect Codex explicitly to select the intended window again. Changing workspace folders disconnects the server until the window reloads. Deleting or disabling the server entry stops automatic refresh; reconnect explicitly to enable it again.

**Agentic Workspace: Copy Codex MCP Configuration** remains available for manual setup. It only copies a snippet; it does not install the connection. Its legacy snippet uses `required = true` and must be copied again after a reload. Prefer Connect Codex for normal use.

Codex and VS Code must run on the same host/network namespace. Remote/WSL cross-host connections and Codex cloud are not covered. Codex and Copilot share the same proposal store and one-time approvals; either connected client can apply an approved proposal once. Only the VS Code review UI can approve a proposal.

### Restricting other Codex tools

Connecting this server does **not** disable Codex's other tools. The exported `enabled_tools` list only filters tools from `agentic_workspace`. It does not control built-in editing, shell commands, plugins, or other MCP servers.

For a CLI session with read-only local execution and no sandbox escalation, use:

```sh
codex --sandbox read-only --ask-for-approval never --disable shell_tool
```

The VS Code process performs approved writes independently. Review Codex's effective permissions and separately disable other write-capable MCP servers, apps, and plugins for that session. A read-only sandbox is not a restriction on every external tool. The extension cannot enforce those host settings or prevent the user from changing them. This is an editor review workflow, not an OS sandbox against other local processes.

Official references: [Codex MCP configuration](https://developers.openai.com/codex/mcp), [configuration reference](https://developers.openai.com/codex/config-reference), and [approvals and sandboxing](https://learn.chatgpt.com/docs/agent-approvals-security).

## Tools

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `list_workspaces` | none | Returns folder ids and names. |
| `inspect_file` | `path`, optional `workspace` | Reads saved UTF-8 contents and SHA-256, or reports a missing file. |
| `propose_patch` | `path`, `before_sha256`, `replacement`, optional `workspace` | Stores an exact full-file replacement for ten minutes. |
| `proposal_status` | `proposal_id` | Reports the proposal's current state. |
| `apply_approved_patch` | `proposal_id` | Applies an approved change once, rechecking the current file. |

Paths use forward slashes relative to the chosen workspace folder. In multi-folder workspaces, provide the id from `list_workspaces`. Files and replacements are limited to 1 MiB. Up to 50 proposals are retained, with completed entries removed as needed. Unsaved buffers, invalid UTF-8, binary data, traversal, symlinks/junctions, hard links, and `.git` paths are rejected. Existing folder paths and dotfiles other than `.git` are supported.

## Approval and boundaries

- Only the extension's review UI approves proposals. There is no MCP approval endpoint. The modal confirmation always requires a user choice.
- Approval binds to the stored workspace, path, prior content hash, and exact replacement. Changes are serialized within this extension instance. Changed files, expired proposals, and repeat application are rejected.
- Writes use `vscode.workspace.fs` and are immediately saved, rather than sent through format-on-save participants. Source control can review/revert them; editor undo is not promised. A failed apply may have written bytes: inspect before making a new proposal.
- All proposals and approvals are lost when the extension host reloads. There is no persistent signed receipt or durable execution recovery in this adapter.
- The embedded MCP endpoint uses an ephemeral port on `127.0.0.1`, a random per-window bearer secret, strict host checking, and denies browser-origin requests. It has no terminal/command execution tool.
- This is an editor approval boundary, **not an OS security sandbox**. Other extensions, Copilot's other editing/terminal tools, and local processes retain their existing access. Disable alternative writing tools if you want Copilot to use this review flow consistently. Filesystem checks do not guarantee atomic compare-and-write against concurrent external writers or adversarial path replacement; do not treat this adapter as equivalent to the hardened Rust service.

## Development

```sh
npm ci
npm test
npm run package
```

The VSIX is a local development build under the `agentic-local` publisher name; it is not published to the Marketplace. Open this folder in VS Code and press F5 to launch an Extension Development Host. Open a disposable local workspace there and verify creation, replacement, rejection, stale-file rejection, and approval expiry. Automated tests cover the proposal state machine, path restrictions, MCP transport authentication, and the SDK client flow; they do not replace an interactive VS Code smoke test.

API references: [VS Code MCP providers](https://code.visualstudio.com/api/extension-guides/ai/mcp), [VS Code workspace API](https://code.visualstudio.com/api/references/vscode-api#workspace), [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk).
