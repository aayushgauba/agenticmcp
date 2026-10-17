"""Forward exact approved public HTTPS requests without credential leakage."""
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit
from django.conf import settings
from .policy import Rejected


def public_address(value):
    address = ipaddress.ip_address(value)
    mapped = getattr(address, 'ipv4_mapped', None)
    if mapped is not None:
        address = mapped
    return address.is_global and not address.is_multicast


def validate_url(value):
    if (not isinstance(value, str) or not value.isascii() or chr(92) in value or '#' in value
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise Rejected('Use an ASCII HTTPS URL without fragments or controls; percent-encode path and query text.')
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.port == 0):
            raise ValueError
        _ = parsed.port
    except ValueError as error:
        raise Rejected('Use a full HTTPS URL without embedded credentials.') from error
    hostname = parsed.hostname.rstrip('.').lower()
    if hostname == 'localhost' or hostname.endswith(('.localhost', '.local', '.internal')) or '%' in hostname:
        raise Rejected('Private-network destinations are not allowed.')
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not public_address(str(address)):
            raise Rejected('Private-network destinations are not allowed.')
    return parsed


def destination(parameters=None):
    if parameters is not None and 'url' in parameters:
        validate_url(parameters['url'])
        return parameters['url']
    value = settings.FORWARD_BASE_URL.rstrip('/')
    if not value:
        raise Rejected('Supply a full url, or configure a base origin for legacy path requests.')
    parsed = validate_url(value)
    if parsed.path or parsed.query:
        raise Rejected('Forwarding base destination must be a bare HTTPS origin')
    return value + parameters['path'] if parameters is not None else value


def resolved_address(parsed):
    # Validate all DNS answers, then pin the socket. TLS verifies the original host.
    try:
        records = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError as error:
        raise Rejected('Destination DNS lookup failed.') from error
    addresses = [record[4][0] for record in records]
    if not addresses or any(not public_address(address) for address in addresses):
        raise Rejected('Destination resolves to a non-public network address.')
    return addresses[0]


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address):
        super().__init__(host, port=port, timeout=20, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def execute_forward(parameters):
    url = destination(parameters)
    parsed = validate_url(url)
    address = resolved_address(parsed)
    headers = dict(parameters.get('headers', {}))
    # Origin-bound credentials are never injected into caller-selected URLs.
    if 'url' not in parameters and settings.FORWARD_BEARER_TOKEN:
        headers['Authorization'] = 'Bearer ' + settings.FORWARD_BEARER_TOKEN
    target = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
    connection = PinnedHTTPSConnection(parsed.hostname, parsed.port or 443, address)
    try:
        connection.request(parameters['method'], target,
                           body=parameters.get('body', '').encode('utf-8'), headers=headers)
        response = connection.getresponse()
        # No redirect following, proxies, cookies, retries, or unbounded decompression.
        if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''):
            raise Rejected('Compressed upstream responses are unsupported.')
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Rejected('Upstream response exceeded the size limit')
        return {'status_code': response.status, 'content_type': response.getheader('Content-Type', ''),
                'body': raw.decode('utf-8', errors='replace'), 'untrusted_upstream_content': True}
    finally:
        connection.close()
