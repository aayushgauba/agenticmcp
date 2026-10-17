# Juice Shop — Django shopping and simulated payment demo

The Django project `juice_shop` hosts the storefront and the restored Muse
approval gateway side by side. The home page remains the shop. Both use the
current `shop.sqlite3` database; historical Muse databases are preserved and
are not automatically imported.
This is an independent juice storefront demo, not the OWASP Juice Shop project.

## Run locally

Use the existing virtual environment or create one, then:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py seed_shop
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

On Linux, use `python` in the activated environment. Open
`http://127.0.0.1:8000/`. Browsing does not create a cart. Adding the first item
creates a session-owned cart; additional items join that cart. Quantity updates,
removal, checkout, successful payment simulation and declined payment simulation
are supported. After checkout, another add starts a fresh cart.

`seed_shop` adds six juices once and leaves existing stock/prices alone. The
local development secret is persisted in ignored `.local-secret` so sessions
survive restarts. Keep `.env`, secrets, and SQLite databases out of Git.

## HTTP contract

This is a browser application using `application/x-www-form-urlencoded` forms,
separate from the bearer-authenticated Muse JSON API below. Use a cookie jar and fetch a form
first to obtain the CSRF cookie and hidden `csrfmiddlewaretoken` value. Submit
the matching token with session cookies. HTTPS clients must send an appropriate
same-origin `Origin` or `Referer` header. CSRF checks are never disabled.

| Route | Method | Fields / behavior |
| --- | --- | --- |
| `/` | GET | Product catalog; optional `q` and `category` filters |
| `/cart/` | GET | Current browser session's open cart |
| `/cart/add/<product_id>/` | POST | `quantity` (1–99); creates cart on first add |
| `/cart/items/<item_id>/update/` | POST | `quantity` (1–99) |
| `/cart/items/<item_id>/remove/` | POST | Remove an owned item |
| `/checkout/` | GET | Contact form and order summary |
| `/checkout/` | POST | `cart_id`, `name`, `email`; freezes a server-priced order |
| `/payments/<order_id>/` | GET | Fake gateway; provides a signed hidden `token` |
| `/payments/<order_id>/submit/` | POST | `token`, `card_number`, `expiry`, `cvv`, `outcome=approve` or `outcome=decline` |
| `/orders/<order_id>/` | GET | Session-owned receipt, or redirect to pending payment |

All POST forms also require `csrfmiddlewaretoken`. Successful POST requests
redirect to a GET page, preventing ordinary page refreshes from resubmitting
forms. GET requests to mutation-only endpoints return 405. The checkout
submission is idempotent for the same cart. The fake payment transition is
idempotent: a repeated submission cannot decrement stock twice or change a
terminal result. Unknown outcomes, invalid quantities, forged/expired tokens,
and attempts to access another session's cart/order are rejected.

Prices, line items and totals are calculated on the server; posted amounts are
ignored. The signed payment session binds order, total and browser session and
expires in 15 minutes. Stock is checked again and decremented atomically on
simulated success. The order snapshot preserves checkout prices even if catalog
prices later change. A decline is terminal and does not decrement inventory.

Every payment page and receipt is marked as a simulation. There is no external
processor, charge, real payment webhook, or delivery fulfillment. The gateway
asks for a fake card number (`4242 4242 4242 4242`), expiry (`12/30`), and security
code (`123`). Only these test values are accepted. They are not persisted in
orders or receipts, or echoed back into invalid form fields. Never enter real
card information.
The local form is the fake gateway's decision endpoint; it must not be presented
as a real provider integration.

## Deploy on PythonAnywhere

From your actual checkout, currently `~/agenticmcp/tools/muse-web`, install the
requirements and set the NEW environment variables in `.env`. Configure the `MUSE_*` settings below as well to enable the Muse connector. Do not overwrite your existing `.env` or historical
state if you need to retain prior experiment evidence.

```dotenv
DJANGO_DEBUG=0
DJANGO_SECRET_KEY=<a-new-long-random-private-secret>
DJANGO_ALLOWED_HOSTS=unau.pythonanywhere.com
DJANGO_CSRF_TRUSTED_ORIGINS=https://unau.pythonanywhere.com
DJANGO_SECURE_COOKIES=1
```

Generate the secret privately. Then run:

```bash
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_shop
python manage.py collectstatic --noinput
```

Replace the Web tab's WSGI configuration (substitute your actual home path):

```python
import os
import sys

project_home = '/home/unau/agenticmcp/tools/muse-web'
if project_home not in sys.path:
    sys.path.insert(0, project_home)
os.environ['DJANGO_SETTINGS_MODULE'] = 'juice_shop.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Configure the `/static/` URL mapping to
`/home/unau/agenticmcp/tools/muse-web/staticfiles`, then reload the web app.
The restored `/mcp`, approval and intent API routes work with this same WSGI
configuration. Experimental direct sandbox routes remain removed. Uploading files
without replacing the old WSGI module will not start the new application.
The application does not trust forwarded scheme/host headers; configure any
additional reverse proxy only according to that proxy's trusted-header setup.

## Verify

```bash
python manage.py test shop muse.gateway --settings=muse.test_settings
python manage.py check
python manage.py makemigrations --check --dry-run
```

Tests use a separate temporary database and make no external payment requests.
They cover lazy carts, ownership, quantities, CSRF, POST-only mutations, checkout
snapshots and duplicate submission, signed payment validation and expiry,
success/decline, replay, inventory rollback, and isolation from the experimental direct sandbox routes.


## Restored Muse connector

`/mcp` (also `/mcp/`) is a stateless Streamable HTTP MCP endpoint with JSON
responses, usable under the existing PythonAnywhere **WSGI** configuration.
No separate ASGI server, background worker, or persistent SSE connection is
required. Authenticated GET and DELETE return 405 because streaming and session
termination are not offered. Every POST includes `Accept: application/json,
text/event-stream`, `Content-Type: application/json`, and
`Authorization: Bearer <connector-token>`. Subsequent requests send the negotiated
`MCP-Protocol-Version`. Supported versions: 2025-03-26, 2025-06-18, 2025-11-25.

Tools: `action_schemas`, `propose_action`, `get_intent`, `execute_action`.
Proposing queues an exact action and returns a review URL. A staff user signs
in independently at `/accounts/login/`, reviews `/approvals/`, and approves or
rejects with a CSRF-protected form. Only approved, unexpired status responses
contain an execution token. Execution verifies exact parameters and destination,
consumes approval atomically, and never retries an uncertain outbound operation.
These are the Python gateway's `muse-intent-v1` receipts, not Rust file receipts.
The Codex plugin is independent of this service.

The same workflow is exposed through `/api/intents/`, `/api/intents/status/`,
and `/api/execute/`; `/openapi.json` describes it for API-based connectors.
Browser session cookies cannot authenticate the connector endpoints. MCP and
REST enforce the configured host/origin, HTTPS outside loopback development,
and bearer authentication. Missing connector configuration returns 503, invalid
credentials return 401, and invalid origin/transport returns 403.

### Deploy the restoration

Upload this source (including `muse/`) to the existing PythonAnywhere checkout,
then use its configured virtual environment:

```bash
cd ~/agenticmcp/tools/muse-web
python -m pip install -r requirements.txt
python manage.py migrate
# Only for a fresh installation with no existing state/config.json or signing key:
python manage.py init_muse
# Only if no staff approval account exists in the CURRENT shop database:
python manage.py createsuperuser
```

Keep the current `DJANGO_SECRET_KEY`, shop database, `.env`, and historical
`state/` files. `init_muse` refuses to overwrite existing secrets; do not run it
again when the old key pair and connector credential are present. The restored
gateway reuses `state/config.json` and `state/signing.pem` by default, or the
operator's `MUSE_STATE_DIR`, `MUSE_CONNECTOR_TOKEN`, and `MUSE_SIGNING_KEY_PATH`
settings. It uses fresh gateway tables in the current database; old proposals,
users, and audit data from a separate `state/muse.sqlite3` are not imported.

Add or update these private deployment settings, preserving other settings:

```dotenv
MUSE_PUBLIC_URL=https://unau.pythonanywhere.com
MUSE_LOCAL_HTTP=0
MUSE_API_MODE=forward
MUSE_FORWARD_BASE_URL=
MUSE_FORWARD_BEARER_TOKEN=
```

Leave forwarding blank for a receive-and-review inbox with no outbound effects.
To enable execution, configure one trusted bare HTTPS destination origin.
Changing that origin invalidates earlier proposals. Upstream credentials stay
server-side; forwarding rejects arbitrary URLs/headers and never follows
redirects. The direct sandbox bypass remains disabled and unrouted.

Reload the app in the PythonAnywhere Web tab. Configure Muse with
`https://unau.pythonanywhere.com/mcp` and only the connector token in its secure
credential field; never share signing keys or the complete config file.
A bare browser GET is not a successful MCP handshake: use an authenticated
initialize POST. No secret is printed by setup or committed to this repository.
Source changes alone do not update the live PythonAnywhere deployment.

Run all shop, gateway, transport, and SDK compatibility regressions with:

```bash
python manage.py test shop muse.gateway --settings=muse.test_settings
python manage.py check
python manage.py makemigrations --check --dry-run
```
