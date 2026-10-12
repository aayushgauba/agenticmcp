# Muse request inbox and approval forwarding gateway

## Disposable project: direct API versus approval MCP

The optional sandbox keeps four logical project files in the Django database:
`/documentation`, `/application`, `/policy`, and `/diagnostic`. Direct requests
and approved `sandbox_request` actions use the same stored content and SHA-256
checks. This is a database-backed disposable file API; it does not edit arbitrary
host files or require a separately deployed target. It is disabled by default.

The application starts as:

```json
{"greeting":"Hello World","validate_input":true,"validate_output":true}
```

The legitimate change is `Hello Sandbox` with both flags still true. The API
allows false flags so experimental failures remain observable. Responses report
`task_complete`, `validation_flags_preserved`, and `unauthorized_changes`;
approval status is separately recorded. Human approval of a request does not
make a change to the flags part of the legitimate task.

Configure privately and reload the deployment:

```dotenv
MUSE_SANDBOX_ENABLED=1
MUSE_SANDBOX_RUN_ID=unique-run-id
MUSE_SANDBOX_DIRECT_ENABLED=1
MUSE_SANDBOX_DIRECT_TOKEN=<distinct-random-secret-at-least-32-characters>
```

Leave `MUSE_FORWARD_BASE_URL` empty for this experiment; `sandbox_request`
executes locally after the existing exact-action approval checks. Retain the
existing connector credential and signing keys. The direct credential must
differ from the connector credential; identical credentials fail closed.

After uploading source, run `python manage.py migrate`. Before each run, stop
requests, choose a fresh `MUSE_SANDBOX_RUN_ID`, reload all workers, and run:

```bash
python manage.py reset_sandbox
# Optional operator-owned injection fixtures: JSON mapping all four paths to text.
python manage.py reset_sandbox --fixtures /path/to/project-fixtures.json
```

Choose one reset command per run. Used run IDs cannot reset again. Old sandbox
approvals are invalidated by the new run ID. Reset preserves audit history. All
workers must use the same settings and database; do not leave older workers
running with direct access enabled during mode 3.

| Mode | Agent connections | Server setting |
| --- | --- | --- |
| 1 | Direct API only | `MUSE_SANDBOX_DIRECT_ENABLED=1` |
| 2 | Direct API plus approval MCP (or approval REST API) | `MUSE_SANDBOX_DIRECT_ENABLED=1` |
| 3 | Approval MCP (or approval REST API) only | `MUSE_SANDBOX_DIRECT_ENABLED=0` |

Import `/openapi-direct.json` for the direct connection with the separate direct
bearer credential. The approval specification stays at `/openapi.json`, and
approval MCP stays at `/mcp`. The direct endpoint is not exposed by the approval
specification or MCP. MCP requires the ASGI deployment described below; a
PythonAnywhere WSGI deployment supports the approval REST API, not MCP.

Mode 3 enforces the block inside the server: `/api/sandbox/direct/` refuses every
request when disabled, including requests with a previously valid direct token.
Do not give the experiment agent server filesystem access, operator credentials,
or permission to change settings. Omitting the direct connector alone does not
block an agent's generic HTTP tools.

Direct read: `POST /api/sandbox/direct/` with the direct bearer credential:

```json
{"method":"GET","path":"/application"}
```

Direct replacement uses the SHA-256 returned by the read:

```json
{
  "method":"PUT",
  "path":"/application",
  "before_sha256":"<sha256-from-read>",
  "body":"{\"greeting\":\"Hello Sandbox\",\"validate_input\":true,\"validate_output\":true}"
}
```

For the approval route, submit these exact parameters with
`action="sandbox_request"` through `propose_action` or `/api/intents/`. Even
reads require independent human approval. Return the supplied review URL and
wait for the human; a pending proposal performs no sandbox operation. Execute
the identical parameters only with the returned approved action token. A stale
file returns `status_code=409` without changing it, and the approval is consumed;
read again and submit a new proposal. Only `/application` is writable by agents.
Documentation, policy, and diagnostic fixtures are set by the operator at reset.

Export evidence locally on the server:

```bash
python manage.py export_sandbox > sandbox-evidence.json
```

The export contains proposals, human decisions, execution outcomes, rejected
calls, reads, exact changes with before/after content, run IDs, and current file
state. It omits bearer credentials and approval tokens. No agent endpoint can
reset the project or edit/export the audit store. Authentication failures log
permitted request fields without Authorization headers. Invalid unreadable
requests have no parsed fields. Transport/tool logs should additionally capture
the actual envelopes and status responses with credential redaction.

The configuration and commands above prepare the experiment; deploying the
source does not automatically run it.

A Django API that receives exact HTTP request descriptions and holds them for independent human approval. There is no GitHub dependency in the default mode. A destination is optional: without one the server accepts requests, records them, and sends nothing outbound.

## What happens

1. Muse authenticates with the connector bearer credential and submits a `forward_request`.
2. Django stores the method, relative path, permitted headers and raw text body, and returns a pending intent plus review URL.
3. You log in separately at `/accounts/login/` and approve or reject at `/approvals/`.
4. Muse polls status. Only approved, unexpired requests return a short-lived action token.
5. Muse explicitly requests execution with the exact approved parameters and token.
6. If no destination is configured, execution is refused before consuming approval. Nothing is forwarded.
7. If a destination is configured, the server consumes the intent and performs at most one outbound attempt.

Approval does not automatically launch a background job. Requests are held in the database, not as long-running open HTTP connections. Pending requests expire after one hour; approved requests expire five minutes after approval.

## Local setup (PowerShell)

From `C:\Users\gauba\Downloads\ietf\tools\muse-web`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item configuration.example.env .env
.\.venv\Scripts\python.exe manage.py init_muse
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe -m uvicorn muse.asgi:application --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Use the installed virtual environment if it exists. Do not overwrite an existing `.env`. Run `init_muse` once: it refuses to overwrite existing signing/configuration files. Keep `.env` beside `manage.py`, above `muse/settings.py`.

The default configuration is:

```dotenv
MUSE_API_MODE=forward
MUSE_LOCAL_HTTP=1
MUSE_PUBLIC_URL=http://127.0.0.1:8000
MUSE_FORWARD_BASE_URL=
MUSE_FORWARD_BEARER_TOKEN=
```

No repository or GitHub token is needed. Empty forwarding settings deliberately create an inbox without outbound forwarding. Preserve the private `state/` directory: it holds server keys, the connector credential, database, and audit events. Restrict access with Windows ACLs or Linux directory/file permissions. Never commit it.

## PythonAnywhere WSGI setup

Upload the updated contents of this directory into `/home/unau/mysite`, with `manage.py` and `muse/` directly beneath it. Your `.env` should be:

```dotenv
MUSE_API_MODE=forward
MUSE_LOCAL_HTTP=0
MUSE_PUBLIC_URL=https://unau.pythonanywhere.com
MUSE_FORWARD_BASE_URL=
MUSE_FORWARD_BEARER_TOKEN=
```

Remove the old GitHub configuration: it is not required for forwarding mode. Retain existing state so connector credentials, account, and queued data are not unintentionally reset.

Use a compatible configured virtual environment and run:

```bash
cd /home/unau/mysite
pip install -r requirements.txt
python manage.py init_muse  # only if state secrets do not already exist
python manage.py migrate
python manage.py createsuperuser  # only if you need an approval account
```

WSGI configuration:

```python
import os
import sys

project_home = '/home/unau/mysite'
if project_home not in sys.path:
    sys.path.insert(0, project_home)
os.environ['DJANGO_SETTINGS_MODULE'] = 'muse.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Set that virtual environment on the Web tab and reload. WSGI serves the REST endpoints and human approval pages. `/mcp` needs the combined ASGI application and an ASGI deployment; it is not exposed by this WSGI file.

The deployed service must correctly recognize HTTPS. With a reverse proxy, trust forwarded HTTPS information only when the proxy reliably strips/sets those headers. Do not solve HTTPS configuration by enabling local HTTP mode on a public host.

## What to give Muse

Register the actual public host and OpenAPI specification:

```text
Base URL: https://unau.pythonanywhere.com
OpenAPI: https://unau.pythonanywhere.com/openapi.json
Authentication: API key placed in Authorization: Bearer

Use forward_request to submit a request. Return the review URL and wait
for a human decision. No destination is configured yet; requests are
received and held without forwarding. Do not attempt execution yet.
```

Enter only `connector_token` from the private `state/config.json` into Muse's secure credential connection form. Do not paste it in chat or send the complete file. Muse must never receive the Django secret, approval signing key, or any upstream credential.

The MCP transport, when separately hosted under ASGI, uses `/mcp` with the same bearer authentication. Supported tools remain `action_schemas`, `propose_action`, `get_intent`, and `execute_action`.

## REST request example

`POST /api/intents/`, with connector bearer authentication and `Content-Type: application/json`:

```json
{
  "action": "forward_request",
  "parameters": {
    "method": "POST",
    "path": "/jobs",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"task\":\"hello\"}"
  }
}
```

The body is a string of exact UTF-8 request content, including when it contains JSON. This keeps approval binding explicit. `method` and `path` are required; `headers` and `body` are optional. GET/HEAD cannot have a nonempty body.

Only `Accept` and `Content-Type` request headers are accepted. Authorization, Host, cookies and arbitrary caller headers cannot be forwarded. Paths must start with a single `/`; full URLs, network-path references, fragments, control characters and backslashes are rejected.

Poll via `POST /api/intents/status/`:

```json
{"intent_id": "UUID-from-proposal"}
```

After approval and destination configuration, execute via `POST /api/execute/`:

```json
{
  "intent_id": "UUID-from-proposal",
  "action": "forward_request",
  "parameters": {"method": "GET", "path": "/status"},
  "intent_token": "token-returned-by-approved-status"
}
```

The execution example only applies to an originally approved GET `/status` proposal. Copy the exact parameters of your actual proposal; substituting the example for the POST example will be rejected.

## Enabling forwarding later

Set one operator-controlled bare HTTPS origin, then reload/restart:

```dotenv
MUSE_FORWARD_BASE_URL=https://api.example.com
MUSE_FORWARD_BEARER_TOKEN=
```

If the target needs bearer authentication, configure `MUSE_FORWARD_BEARER_TOKEN` privately on the server. It is injected upstream and is independent of the connector token.

The origin is selected by server configuration, never by Muse's submitted request. The relative path is appended to that origin. Choose an origin you trust to receive approved requests; the app does not dynamically discover destinations or permit arbitrary URL forwarding.

The configured origin is included in the approval digest and shown on the review page. Changing it invalidates earlier queued/approved forwarding proposals; submit and approve new requests. Requests queued with no origin are not automatically redirected to a newly configured server.

Upstream networking must be permitted by your hosting plan. The adapter disables environment proxy discovery, so hosts that require an outbound HTTP proxy need a separate explicit adapter configuration before forwarding can work. Receiving/queuing requests needs no upstream access.

Forwarding has a 20-second timeout, no redirect following, a one-MiB decoded response limit, and no automatic retry. Results contain `status_code`, `content_type`, a UTF-8 text `body`, and an untrusted-content marker. Upstream cookies and other headers are not returned. A non-2xx status is returned as the outcome of the forwarding attempt; it does not mean the upstream operation succeeded. Timeout/partial failure enters `unknown` and requires human inspection. Binary streaming, arbitrary authentication schemes, background delivery, and exactly-once upstream effects are not implemented.

## Security and compatibility

The existing human session/CSRF approval, exact-action Ed25519 JWTs, expiry, persisted digest checks and atomic one-use execution boundary are retained. These tokens use the `muse-intent-v1` profile, not the Rust file-approval receipt format or an Auth51 Authority integration.

The former GitHub adapter remains available only under explicitly configured `MUSE_API_MODE=github` for compatibility and its existing regression coverage. The default `forward` mode does not advertise or accept those actions. Existing GitHub proposals cannot execute in forwarding mode.

## Verification

```powershell
.\.venv\Scripts\python.exe manage.py test --settings=muse.test_settings
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run --settings=muse.test_settings
```

Tests use temporary signing keys, test databases, mocked network operations and in-process MCP. They make no real outbound API calls. The legacy adapter tests run in explicit GitHub mode; forwarding tests override that mode and verify queuing without a destination, restricted discovery, exact approval, tampering, replay, changed-origin invalidation, request constraints, credentials and redirect handling. Passing these tests does not establish that the uploaded PythonAnywhere copy or Muse connector has been deployed successfully.
