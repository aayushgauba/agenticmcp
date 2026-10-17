import socket
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit
from django.test import TestCase, SimpleTestCase, override_settings
from .tests import KeyFixture
from . import service
from .models import Intent
from .policy import Rejected, validate, action_digest
from .forwarding import execute_forward, resolved_address, PinnedHTTPSConnection


@override_settings(API_MODE='forward', FORWARD_BASE_URL='', FORWARD_BEARER_TOKEN='')
class PublicForwardingTests(KeyFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.params = {'method': 'GET', 'url': 'https://www.google.com/search?q=test'}

    def test_any_public_domain_can_be_proposed_without_outbound_calls(self):
        with patch('muse.gateway.forwarding.socket.getaddrinfo') as dns:
            for url in ['https://www.google.com/', 'https://example.org/api?q=one', 'https://api.example.net:8443/jobs']:
                pending = service.propose(self.actor, 'forward_request', {**self.params, 'url': url})
                self.assertEqual(pending['destination'], url)
                self.assertTrue(pending['forwarding_configured'])
                self.assertEqual(pending['status'], 'pending')
                self.assertNotIn('intent_token', pending)
            dns.assert_not_called()

    def test_exact_destination_is_bound_to_approval(self):
        approved = self.approved('forward_request', self.params)
        with patch('muse.gateway.service.execute_forward', return_value={'status_code': 200}) as outbound:
            for url in ['https://example.org/', self.params['url'] + '&extra=true']:
                with self.assertRaises(Rejected):
                    service.execute(self.actor, approved['intent_id'], 'forward_request', {**self.params, 'url': url}, approved['intent_token'])
            outbound.assert_not_called()
            service.execute(self.actor, approved['intent_id'], 'forward_request', self.params, approved['intent_token'])
            with self.assertRaises(Rejected):
                service.execute(self.actor, approved['intent_id'], 'forward_request', self.params, approved['intent_token'])
            outbound.assert_called_once_with(self.params)

    def test_base_origin_changes_do_not_change_full_url_approval(self):
        digest = action_digest('forward_request', self.params)
        with override_settings(FORWARD_BASE_URL='https://legacy.example'):
            self.assertEqual(digest, action_digest('forward_request', self.params))

    def test_unsafe_urls_and_ambiguous_destinations_are_rejected(self):
        for url in ['http://example.org/', 'https://user:pass@example.org/', 'https://example.org/#fragment',
                    'https://localhost/', 'https://127.0.0.1/', 'https://10.0.0.1/', 'https://169.254.169.254/',
                    'https://[::1]/', 'https://[::ffff:127.0.0.1]/', 'https://[fe80::1%25eth0]/',
                    'https://example.org:0/', 'https://example.org:99999/', 'https://example.org/\r\nHost:evil',
                    'https://example.org/\\evil', 'https://example.org/ unsafe']:
            with self.subTest(url=url), self.assertRaises(Rejected):
                validate('forward_request', {**self.params, 'url': url})
        for params in [{**self.params, 'path': '/'}, {'method': 'GET'},
                       {**self.params, 'headers': {'Authorization': 'connector-secret'}}]:
            with self.assertRaises(Rejected):
                validate('forward_request', params)

    def test_review_shows_full_destination(self):
        pending = service.propose(self.actor, 'forward_request', self.params)
        self.client.force_login(self.user)
        response = self.client.get('/approvals/' + pending['intent_id'] + '/')
        self.assertContains(response, self.params['url'])


class NetworkBoundaryTests(SimpleTestCase):
    def test_private_mixed_empty_and_rebound_dns_are_blocked(self):
        for addresses in [[], ['127.0.0.1'], ['169.254.169.254'], ['8.8.8.8', '10.0.0.1'], ['::1'], ['224.0.0.1']]:
            records = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in addresses]
            with patch('muse.gateway.forwarding.socket.getaddrinfo', return_value=records), self.assertRaises(Rejected):
                resolved_address(urlsplit('https://example.org/'))

    def test_socket_uses_checked_ip_and_tls_uses_original_hostname(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
        with patch('muse.gateway.forwarding.socket.getaddrinfo', return_value=records) as dns:
            address = resolved_address(urlsplit('https://example.org/'))
            connection = PinnedHTTPSConnection('example.org', 443, address)
            context = MagicMock()
            connection._context = context
            with patch('muse.gateway.forwarding.socket.create_connection') as connect:
                connection.connect()
                connect.assert_called_once_with(('8.8.8.8', 443), timeout=20)
                context.wrap_socket.assert_called_once_with(connect.return_value, server_hostname='example.org')
            dns.assert_called_once()

    @override_settings(FORWARD_BASE_URL='https://legacy.example', FORWARD_BEARER_TOKEN='upstream-secret', CONNECTOR_TOKEN='connector-secret')
    def test_no_credentials_redirect_following_or_unbounded_response(self):
        response = MagicMock(status=302)
        response.read.return_value = b'go elsewhere'
        response.getheader.side_effect = lambda name, default='': {'Content-Type': 'text/plain'}.get(name, default)
        with patch('muse.gateway.forwarding.resolved_address', return_value='8.8.8.8'), \
                patch('muse.gateway.forwarding.PinnedHTTPSConnection') as factory:
            connection = factory.return_value
            connection.getresponse.return_value = response
            result = execute_forward({'method': 'GET', 'url': 'https://example.org/api?q=1'})
            connection.request.assert_called_once_with('GET', '/api?q=1', body=b'', headers={})
            self.assertEqual(result['status_code'], 302)
            self.assertNotIn('headers', result)
            response.read.assert_called_once_with(1024 * 1024 + 1)
            response.read.return_value = b'x' * (1024 * 1024 + 1)
            with self.assertRaises(Rejected):
                execute_forward({'method': 'GET', 'url': 'https://example.org/'})
            response.getheader.side_effect = lambda name, default='': 'gzip'
            with self.assertRaises(Rejected):
                execute_forward({'method': 'GET', 'url': 'https://example.org/'})
