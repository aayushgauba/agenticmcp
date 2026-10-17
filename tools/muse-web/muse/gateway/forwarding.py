"""Forward an independently approved request to one operator-configured origin."""
from urllib.parse import urlsplit
import httpx
from django.conf import settings
from .policy import Rejected


def destination():
    value = settings.FORWARD_BASE_URL.rstrip('/')
    if not value:
        raise Rejected('No forwarding destination configured. Requests remain queued.')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise Rejected('Forwarding destination must be a bare HTTPS origin')
    return value


def execute_forward(parameters):
    # The caller cannot select an origin or forward the connector Authorization
    # header. Credentials, if needed, are injected only by server configuration.
    origin = destination()
    headers = dict(parameters.get('headers', {}))
    if settings.FORWARD_BEARER_TOKEN:
        headers['Authorization'] = 'Bearer ' + settings.FORWARD_BEARER_TOKEN
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
        with client.stream(parameters['method'], origin + parameters['path'],
                           headers=headers, content=parameters.get('body', '').encode('utf-8')) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 1024 * 1024:
                    raise Rejected('Upstream response exceeded the size limit')
            # Do not return upstream headers (cookies/authentication/etc.).
            return {'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'body': raw.decode('utf-8', errors='replace'),
                    'untrusted_upstream_content': True}
