import json
from io import StringIO
from unittest.mock import patch
from django.conf import settings
from django.core.management import call_command
from django.test import Client, TestCase, TransactionTestCase, override_settings
from .tests import KeyFixture


@override_settings(API_MODE='forward', FORWARD_BASE_URL='https://api.example.com')
class HttpMcpTests(KeyFixture, TestCase):
    def rpc(self, method, params=None, **headers):
        return self.client.post('/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}},
                                content_type='application/json', **{
                                    'HTTP_HOST': '127.0.0.1:8000',
                                    'HTTP_AUTHORIZATION': 'Bearer ' + settings.CONNECTOR_TOKEN,
                                    'HTTP_ACCEPT': 'application/json, text/event-stream', **headers})

    def call(self, name, arguments=None):
        response = self.rpc('tools/call', {'name': name, 'arguments': arguments or {}})
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['result']

    def test_transport_guards_and_discovery(self):
        self.assertEqual(self.rpc('tools/list', HTTP_AUTHORIZATION='').status_code, 401)
        self.assertEqual(self.rpc('tools/list', HTTP_ORIGIN='https://evil.invalid').status_code, 403)
        self.assertEqual(self.rpc('tools/list', HTTP_HOST='testserver').status_code, 200)
        self.assertEqual(self.rpc('tools/list', HTTP_ACCEPT='text/html').status_code, 406)
        self.assertEqual(self.rpc('tools/list', HTTP_MCP_PROTOCOL_VERSION='2099-01-01').status_code, 400)
        with override_settings(CONNECTOR_TOKEN=''):
            self.assertEqual(self.rpc('tools/list').status_code, 503)
        initialized = self.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                             'clientInfo': {'name': 'test', 'version': '1'}}).json()
        self.assertEqual(initialized['result']['protocolVersion'], '2025-11-25')
        tools = self.rpc('tools/list').json()['result']['tools']
        self.assertEqual({tool['name'] for tool in tools}, {'action_schemas', 'propose_action', 'get_intent', 'execute_action'})
        self.assertNotIn(settings.CONNECTOR_TOKEN, json.dumps(tools))
        self.assertEqual(self.rpc('tools/call', {'name': 'propose_action', 'arguments': {'action': 'forward_request'}}).json()['error']['code'], -32602)
        # Cookie authentication is deliberately insufficient for the CSRF-exempt API.
        self.client.force_login(self.user)
        self.assertEqual(self.rpc('tools/list', HTTP_AUTHORIZATION='').status_code, 401)
        self.assertEqual(self.client.get('/mcp', HTTP_HOST='127.0.0.1:8000',
                                        HTTP_AUTHORIZATION='Bearer ' + settings.CONNECTOR_TOKEN).status_code, 405)

    def test_request_host_and_scheme_need_no_custom_muse_settings(self):
        # Any host in Django ALLOWED_HOSTS works without a second host setting.
        for host in ['127.0.0.1:8000', 'testserver']:
            response = self.rpc('tools/list', HTTP_HOST=host)
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.rpc('tools/list', HTTP_HOST='untrusted.invalid').status_code, 400)
        response = self.rpc('tools/list', HTTP_ORIGIN='https://other.example')
        self.assertEqual(response.json()['code'], 'origin_mismatch')
        self.assertNotIn(settings.CONNECTOR_TOKEN, response.content.decode())
        with override_settings(CSRF_TRUSTED_ORIGINS=['https://client.example']):
            self.assertEqual(self.rpc('tools/list', HTTP_ORIGIN='https://client.example').status_code, 200)
        # Header spoofing never changes the URL used for generated links.
        response = self.client.post('/api/intents/',
            {'action': 'forward_request', 'parameters': {'method': 'GET', 'url': 'https://example.org/'}},
            content_type='application/json', secure=True, HTTP_HOST='testserver',
            HTTP_X_FORWARDED_HOST='evil.invalid', HTTP_X_FORWARDED_PROTO='http',
            HTTP_AUTHORIZATION='Bearer ' + settings.CONNECTOR_TOKEN)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['review_url'].startswith('https://testserver/approvals/'))
        output = StringIO()
        call_command('check_muse', stdout=output)
        diagnostic = json.loads(output.getvalue())
        self.assertTrue(diagnostic['connector_token_configured'])
        self.assertNotIn(settings.CONNECTOR_TOKEN, output.getvalue())

    def test_exact_human_approval_then_one_execution(self):
        parameters = {'method': 'POST', 'path': '/jobs', 'body': 'hello'}
        with patch('muse.gateway.service.execute_forward', return_value={'status_code': 201}) as upstream:
            pending = self.call('propose_action', {'action': 'forward_request', 'parameters': parameters})['structuredContent']
            self.assertNotIn('intent_token', pending)
            args = {'intent_id': pending['intent_id'], 'action': 'forward_request', 'parameters': parameters,
                    'intent_token': 'forged'}
            self.assertTrue(self.call('execute_action', args)['isError'])
            upstream.assert_not_called()
            # Disposable test reviewer and key only; no real user approval is automated.
            human = Client(enforce_csrf_checks=True)
            human.force_login(self.user)
            review = '/approvals/' + pending['intent_id'] + '/'
            self.assertEqual(human.get(review).status_code, 200)
            decision = {'digest': pending['action_sha256'], 'decision': 'approve'}
            self.assertEqual(human.post(review, decision).status_code, 403)
            self.assertEqual(human.post(review, decision, HTTP_X_CSRFTOKEN=human.cookies['csrftoken'].value).status_code, 302)
            approved = self.call('get_intent', {'intent_id': pending['intent_id']})['structuredContent']
            args['intent_token'] = approved['intent_token']
            self.assertTrue(self.call('execute_action', {**args, 'parameters': {**parameters, 'path': '/other'}})['isError'])
            self.assertFalse(self.call('execute_action', args)['isError'])
            self.assertTrue(self.call('execute_action', args)['isError'])
            upstream.assert_called_once_with(parameters)

    def test_invalid_json_batches_notifications_and_size(self):
        headers = {'HTTP_HOST': '127.0.0.1:8000', 'HTTP_AUTHORIZATION': 'Bearer ' + settings.CONNECTOR_TOKEN,
                   'HTTP_ACCEPT': 'application/json, text/event-stream'}
        for body in ['{', '[]', '{"jsonrpc":"2.0","id":true,"method":"ping"}']:
            self.assertEqual(self.client.post('/mcp', body, content_type='application/json', **headers).status_code, 400)
        notification = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
        self.assertEqual(self.client.post('/mcp/', notification, content_type='application/json', **headers).status_code, 202)
        self.assertEqual(self.client.post('/mcp', ' ' * 65537, content_type='application/json', **headers).status_code, 413)


@override_settings(API_MODE='forward', FORWARD_BASE_URL='')
class SdkCompatibilityTests(KeyFixture, TransactionTestCase):
    async def test_sdk_initializes_lists_and_calls_django_endpoint(self):
        import httpx
        from django.core.asgi import get_asgi_application
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        app = get_asgi_application()

        def factory(**kwargs):
            return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), **kwargs)

        async with streamablehttp_client('http://127.0.0.1:8000' + '/mcp',
                headers={'Authorization': 'Bearer ' + settings.CONNECTOR_TOKEN}, httpx_client_factory=factory) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                self.assertEqual(len((await session.list_tools()).tools), 4)
                result = await session.call_tool('action_schemas')
                self.assertFalse(result.isError)
                self.assertIn('forward_request', json.loads(result.content[0].text)['actions'])
