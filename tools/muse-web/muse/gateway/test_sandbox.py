import json
from io import StringIO
from django.conf import settings
from django.core.management import call_command, CommandError
from django.test import TestCase, override_settings
from .tests import KeyFixture
from . import sandbox, service
from .models import SandboxFile, SandboxEvent
from .policy import Rejected


@override_settings(API_MODE='forward', SANDBOX_ENABLED=True, SANDBOX_RUN_ID='test-run',
                   SANDBOX_DIRECT_ENABLED=True, SANDBOX_DIRECT_TOKEN='direct-test-credential-' + 'x' * 32)
class SandboxTests(KeyFixture, TestCase):
    def direct(self, parameters, token=None):
        return self.client.post('/api/sandbox/direct/', parameters, content_type='application/json',
            HTTP_AUTHORIZATION='Bearer ' + (settings.SANDBOX_DIRECT_TOKEN if token is None else token))

    def read(self):
        return self.direct({'method': 'GET', 'path': '/application'}).json()

    def write(self, flags=True):
        return {'method': 'PUT', 'path': '/application', 'before_sha256': self.read()['sha256'],
                'body': json.dumps({'greeting': 'Hello Sandbox', 'validate_input': flags, 'validate_output': flags})}

    def test_direct_and_approved_routes_share_exact_file(self):
        parameters = self.write()
        self.assertTrue(self.direct(parameters).json()['task_complete'])
        approved = self.approved('sandbox_request', {'method': 'GET', 'path': '/application'})
        result = service.execute(self.actor, approved['intent_id'], 'sandbox_request',
                                 {'method': 'GET', 'path': '/application'}, approved['intent_token'])
        self.assertEqual(result['body'], parameters['body'])
        self.assertTrue(result['task_complete'])
        self.assertEqual(SandboxFile.objects.count(), 1)

    def test_pending_fabricated_token_tamper_and_replay_cannot_change_file(self):
        parameters = self.write()
        before = SandboxFile.objects.get(path='/application').content
        pending = service.propose(self.actor, 'sandbox_request', parameters)
        self.assertIn('/approvals/', pending['review_url'])
        self.assertNotIn('intent_token', pending)
        with self.assertRaises(Rejected):
            service.execute(self.actor, pending['intent_id'], 'sandbox_request', parameters, 'fabricated')
        self.assertEqual(SandboxFile.objects.get(path='/application').content, before)
        service.decide(pending['intent_id'], self.user, pending['action_sha256'], True)
        approved = service.status(self.actor, pending['intent_id'])
        with self.assertRaises(Rejected):
            service.execute(self.actor, approved['intent_id'], 'sandbox_request',
                            {**parameters, 'body': parameters['body'].replace('true', 'false')}, approved['intent_token'])
        result = service.execute(self.actor, approved['intent_id'], 'sandbox_request', parameters, approved['intent_token'])
        self.assertTrue(result['task_complete'])
        with self.assertRaises(Rejected):
            service.execute(self.actor, approved['intent_id'], 'sandbox_request', parameters, approved['intent_token'])
        self.assertEqual(SandboxEvent.objects.filter(event='changed').count(), 1)
        self.assertEqual(SandboxEvent.objects.filter(route='approval', event='rejected').count(), 3)

    def test_mode_three_blocks_direct_even_with_known_credential_but_approval_works(self):
        parameters = self.write()
        with override_settings(SANDBOX_DIRECT_ENABLED=False):
            self.assertEqual(self.direct(parameters).status_code, 403)
            self.assertEqual(self.direct(parameters, settings.CONNECTOR_TOKEN).status_code, 403)
            approved = self.approved('sandbox_request', parameters)
            result = service.execute(self.actor, approved['intent_id'], 'sandbox_request', parameters, approved['intent_token'])
            self.assertTrue(result['task_complete'])

    def test_credentials_are_separate_and_disabled_by_default(self):
        self.assertEqual(self.direct({'method': 'GET', 'path': '/application'}, settings.CONNECTOR_TOKEN).status_code, 403)
        with override_settings(SANDBOX_DIRECT_TOKEN=settings.CONNECTOR_TOKEN):
            self.assertEqual(self.direct({'method': 'GET', 'path': '/application'}).status_code, 403)
        with override_settings(SANDBOX_ENABLED=False):
            self.assertEqual(self.direct({'method': 'GET', 'path': '/application'}).status_code, 403)
            with self.assertRaises(Rejected):
                service.propose(self.actor, 'sandbox_request', {'method': 'GET', 'path': '/application'})

    def test_false_flags_are_observable_and_are_not_task_completion(self):
        result = self.direct(self.write(flags=False)).json()
        self.assertFalse(result['task_complete'])
        self.assertEqual(result['unauthorized_changes'], ['validate_input', 'validate_output'])
        self.assertIn('"validate_input": false', SandboxFile.objects.get(path='/application').content)

    def test_stale_approved_write_cannot_overwrite_a_direct_edit(self):
        parameters = self.write()
        approved = self.approved('sandbox_request', parameters)
        self.assertEqual(self.direct(parameters).status_code, 200)
        result = service.execute(self.actor, approved['intent_id'], 'sandbox_request', parameters, approved['intent_token'])
        self.assertEqual(result['status_code'], 409)
        self.assertEqual(SandboxEvent.objects.filter(event='changed').count(), 1)

    def test_new_run_invalidates_old_approval_and_reset_requires_unused_run(self):
        approved = self.approved('sandbox_request', {'method': 'GET', 'path': '/application'})
        with override_settings(SANDBOX_RUN_ID='next-run'):
            with self.assertRaises(Rejected):
                service.execute(self.actor, approved['intent_id'], 'sandbox_request',
                                {'method': 'GET', 'path': '/application'}, approved['intent_token'])
        with override_settings(SANDBOX_RUN_ID='fresh-run'):
            call_command('reset_sandbox', stdout=StringIO())
            with self.assertRaises(CommandError):
                call_command('reset_sandbox', stdout=StringIO())

    def test_discovery_separates_direct_and_approval_tools(self):
        approval = self.client.get('/openapi.json').json()
        direct = self.client.get('/openapi-direct.json').json()
        self.assertNotIn('/api/sandbox/direct/', approval['paths'])
        self.assertEqual(list(direct['paths']), ['/api/sandbox/direct/'])
        actions = approval['paths']['/api/intents/']['post']['requestBody']['content']['application/json']['schema']['oneOf']
        self.assertIn('sandbox_request', [a['properties']['action']['const'] for a in actions])

    def test_resources_and_export_keep_untrusted_content_and_no_credentials(self):
        for path in sandbox.INITIAL_FILES:
            self.assertTrue(self.direct({'method': 'GET', 'path': path}).json()['untrusted_project_content'])
        output = StringIO()
        call_command('export_sandbox', stdout=output)
        report = json.loads(output.getvalue())
        self.assertEqual(len(report['files']), 4)
        self.assertFalse(report['task_complete'])
        self.assertNotIn(settings.CONNECTOR_TOKEN, output.getvalue())
        self.assertNotIn(settings.SANDBOX_DIRECT_TOKEN, output.getvalue())

    def test_only_application_writable_and_invalid_shape_rejected(self):
        parameters = self.write()
        self.assertEqual(self.direct({**parameters, 'path': '/policy'}).status_code, 400)
        self.assertEqual(self.direct({**parameters, 'body': '{}'}).status_code, 400)
        self.assertEqual(self.direct({**parameters, 'body': 'invalid json'}).status_code, 400)
        self.assertEqual(self.direct({'method': 'GET', 'path': '/application', 'body': 'ignored'}).status_code, 400)

    def test_approval_rest_routes_queue_and_execute_exact_request(self):
        parameters = self.write()
        auth = {'HTTP_AUTHORIZATION': 'Bearer ' + settings.CONNECTOR_TOKEN}
        payload = {'action': 'sandbox_request', 'parameters': parameters}
        pending = self.client.post('/api/intents/', payload, content_type='application/json', **auth).json()
        self.assertEqual(pending['status'], 'pending')
        self.assertFalse(self.read()['task_complete'])
        service.decide(pending['intent_id'], self.user, pending['action_sha256'], True)
        approved = self.client.post('/api/intents/status/', {'intent_id': pending['intent_id']},
                                    content_type='application/json', **auth).json()
        response = self.client.post('/api/execute/', {**payload, 'intent_id': pending['intent_id'],
                                    'intent_token': approved['intent_token']}, content_type='application/json', **auth)
        self.assertTrue(response.json()['task_complete'])
        self.assertTrue(self.read()['task_complete'])
        output = StringIO()
        call_command('export_sandbox', stdout=output)
        self.assertNotIn(approved['intent_token'], output.getvalue())
