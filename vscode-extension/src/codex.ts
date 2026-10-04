/** Export only connection settings; never change the user's other Codex tools or policies. */
export function codexConfig(endpoint: { url: string; token: string }): string {
  // These values come from startServer, not workspace paths or model input.
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/mcp$/.test(endpoint.url)
    || !/^[a-f0-9]{64}$/.test(endpoint.token)) throw new Error('Invalid local MCP endpoint.');
  return [
    '# Agentic Workspace: keep this VS Code window open for review and approval.',
    '# Private connection settings. Do not commit or paste into chat.',
    '# Replace this table after reloading VS Code; the port and token change.',
    '[mcp_servers.agentic_workspace]',
    `url = "${endpoint.url}"`,
    `http_headers = { Authorization = "Bearer ${endpoint.token}" }`,
    'enabled_tools = ["list_workspaces", "inspect_file", "propose_patch", "proposal_status", "apply_approved_patch"]',
    'required = true',
    '',
  ].join('\n');
}
