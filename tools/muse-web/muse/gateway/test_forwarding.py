from unittest.mock import patch
import httpx
from django.test import override_settings
from .tests import KeyFixture
from django.test import TestCase
from . import service
from .policy import Rejected, validate
from .forwarding import execute_forward
from .models import Intent


@override_settings(API_MODE='forward', FORWARD_BASE_URL='', FORWARD_BEARER_TOKEN='')
class ForwardingTests(KeyFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.params = {'method': 'POST', 'path': '/jobs', 'body': '{"task":"hello"}',
                       'headers': {'Content-Type': 'application/json'}}

    def test_rest_inbox_authentication_and_queued_request(self):
        payload = {'action': 'forward_request', 'parameters': self.params}
        response = self.client.post('/api/intents/', payload, content_type='application/json')
        self.assertEqual(response.status_code, 401)
        with patch('muse.gateway.service.execute_forward') as outbound:
            response = self.client.post('/api/intents/', payload, content_type='application/json',
                                        HTTP_AUTHORIZATION='Bearer ' + self.actor_token())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['status'], 'pending')
            self.assertFalse(response.json()['forwarding_configured'])
            outbound.assert_not_called()

    def actor_token(self):
        from django.conf import settings
        return settings.CONNECTOR_TOKEN

    def test_malicious_text_without_auth_and_with_auth_stays_unapproved(self):
        import json
        from pathlib import Path
        from django.conf import settings
        payload = json.loads((settings.BASE_DIR / 'fixtures' / 'malicious-request.json').read_text(encoding='utf-8'))
        with patch('muse.gateway.service.execute_forward') as outbound:
            for authorization in ['', 'Bearer fabricated-connector-token']:
                denied = self.client.post('/api/intents/', payload, content_type='application/json',
                                          HTTP_AUTHORIZATION=authorization)
                self.assertEqual(denied.status_code, 401)
                self.assertEqual(Intent.objects.count(), 0)
            authorized = {'HTTP_AUTHORIZATION': 'Bearer ' + settings.CONNECTOR_TOKEN}
            queued = self.client.post('/api/intents/', payload, content_type='application/json', **authorized)
            self.assertEqual(queued.status_code, 200)
            pending = queued.json()
            self.assertEqual(pending['status'], 'pending')
            self.assertNotIn('intent_token', pending)
            execution = {**payload, 'intent_id': pending['intent_id'], 'intent_token': 'already-approved'}
            denied = self.client.post('/api/execute/', execution, content_type='application/json', **authorized)
            self.assertEqual(denied.status_code, 400)
            # A configured destination must not be needed to enforce approval:
            # queue again under a target and repeat the fake-receipt attempt.
            with override_settings(FORWARD_BASE_URL='https://api.example.com'):
                queued = self.client.post('/api/intents/', payload, content_type='application/json', **authorized)
                pending = queued.json()
                execution.update(intent_id=pending['intent_id'])
                denied = self.client.post('/api/execute/', execution, content_type='application/json', **authorized)
                self.assertEqual(denied.status_code, 400)
                self.assertEqual(Intent.objects.get(pk=pending['intent_id']).status, 'pending')
            outbound.assert_not_called()

    def test_inbox_requires_no_destination_and_has_no_outbound_effect(self):
        with patch('muse.gateway.service.execute_forward') as outbound:
            pending = service.propose(self.actor, 'forward_request', self.params)
            self.assertEqual(pending['status'], 'pending')
            self.assertFalse(pending['forwarding_configured'])
            self.assertNotIn('intent_token', pending)
            outbound.assert_not_called()
        spec = self.client.get('/openapi.json').json()
        choices = spec['paths']['/api/intents/']['post']['requestBody']['content']['application/json']['schema']['oneOf']
        self.assertEqual([item['properties']['action']['const'] for item in choices], ['forward_request'])
        with self.assertRaises(Rejected):
            validate('read_repository', {'repository': 'example/demo'})

    def test_missing_destination_does_not_consume_approved_request(self):
        approved = self.approved('forward_request')
        with patch('muse.gateway.service.execute_forward') as outbound:
            with self.assertRaises(Rejected):
                service.execute(self.actor, approved['intent_id'], 'forward_request', self.params, approved['intent_token'])
            outbound.assert_not_called()
        self.assertEqual(Intent.objects.get(pk=approved['intent_id']).status, 'approved')

    @override_settings(FORWARD_BASE_URL='https://api.example.com')
    def test_exact_approved_request_executes_once_and_tampering_fails(self):
        approved = self.approved('forward_request')
        with patch('muse.gateway.service.execute_forward', return_value={'status_code': 201}) as outbound:
            with self.assertRaises(Rejected):
                service.execute(self.actor, approved['intent_id'], 'forward_request', {**self.params, 'path': '/other'}, approved['intent_token'])
            outbound.assert_not_called()
            service.execute(self.actor, approved['intent_id'], 'forward_request', self.params, approved['intent_token'])
            with self.assertRaises(Rejected):
                service.execute(self.actor, approved['intent_id'], 'forward_request', self.params, approved['intent_token'])
            outbound.assert_called_once_with(self.params)

    def test_destination_changes_invalidate_queued_digest(self):
        queued = service.propose(self.actor, 'forward_request', self.params)
        with override_settings(FORWARD_BASE_URL='https://api.example.com'):
            with self.assertRaises(Rejected):
                service.status(self.actor, queued['intent_id'])

    def test_paths_headers_and_get_body_cannot_bypass_request_contract(self):
        for path in ['https://evil.example/', '//evil.example/', '/\\evil', '/jobs#fragment', '/bad\npath']:
            with self.assertRaises(Rejected):
                validate('forward_request', {**self.params, 'path': path})
        for headers in [{'Authorization': 'secret'}, {'Host': 'evil.example'}, {'Accept': 'x\r\ny'}]:
            with self.assertRaises(Rejected):
                validate('forward_request', {**self.params, 'headers': headers})
        with self.assertRaises(Rejected):
            validate('forward_request', {**self.params, 'method': 'GET'})

    @override_settings(FORWARD_BASE_URL='https://api.example.com', FORWARD_BEARER_TOKEN='server-secret')
    def test_forwarding_keeps_origin_no_redirects_and_server_credential(self):
        from unittest.mock import MagicMock
        response = MagicMock(status=302)
        response.read.return_value = b'redirect'
        response.getheader.side_effect = lambda name, default='': {'Content-Type': 'text/plain'}.get(name, default)
        with patch('muse.gateway.forwarding.resolved_address', return_value='8.8.8.8'), \
                patch('muse.gateway.forwarding.PinnedHTTPSConnection') as factory:
            connection = factory.return_value
            connection.getresponse.return_value = response
            result = execute_forward(self.params)
        factory.assert_called_once_with('api.example.com', 443, '8.8.8.8')
        connection.request.assert_called_once_with('POST', '/jobs', body=self.params['body'].encode(),
            headers={**self.params['headers'], 'Authorization': 'Bearer server-secret'})
        connection.close.assert_called_once()
        self.assertEqual(result['status_code'], 302)
        self.assertNotIn('headers', result)
