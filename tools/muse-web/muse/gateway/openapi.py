from django.conf import settings
from .policy import action_schemas, object_schema


def document(origin='/'):
    identifier = {'type': 'string', 'format': 'uuid'}
    proposals, executions = [], []
    for action, parameters in action_schemas().items():
        fields = {'action': {'const': action, 'type': 'string'}, 'parameters': parameters}
        proposals.append(object_schema(fields))
        executions.append(object_schema({**fields, 'intent_id': identifier, 'intent_token': {'type': 'string', 'minLength': 1}}))
    descriptions = {
        '/api/intents/': ('proposeIntent', 'Queue an exact request for human review. No outbound call occurs.', {'oneOf': proposals}),
        '/api/intents/status/': ('getIntent', 'Poll your intent. A token is returned only after independent human approval. Do not invent approval or poll indefinitely.', object_schema({'intent_id': identifier})),
        '/api/execute/': ('executeIntent', 'Execute an approved exact action once. A separate per-action intent_token is mandatory. Do not automatically retry unknown upstream outcomes.', {'oneOf': executions}),
    }
    paths = {}
    for path, (name, description, schema) in descriptions.items():
        paths[path] = {'post': {
            'operationId': name, 'description': description, 'security': [{'connectorBearer': []}],
            'requestBody': {'required': True, 'content': {'application/json': {'schema': schema}}},
            'responses': {
                '200': {'description': 'Intent status or execution result', 'content': {'application/json': {'schema': {'type': 'object'}}}},
                '400': {'description': 'Invalid, unapproved, expired, mismatched, or already-used intent'},
                '401': {'description': 'Connector bearer authentication required'},
            },
        }}
    return {
        'openapi': '3.1.0', 'info': {'title': 'Muse request approval gateway', 'version': '0.1.0'},
        'servers': [{'url': origin}], 'paths': paths,
        'components': {'securitySchemes': {'connectorBearer': {'type': 'http', 'scheme': 'bearer', 'description': 'Muse connector credential injected from the Secure Vault. This is not an upstream credential or per-action intent token.'}}},
    }


def direct_document(origin='/'):
    from .policy import SANDBOX_SCHEMA
    return {
        'openapi': '3.1.0', 'info': {'title': 'Muse disposable project direct API', 'version': '0.1.0'},
        'servers': [{'url': origin}],
        'paths': {'/api/sandbox/direct/': {'post': {
            'operationId': 'directSandboxRequest',
            'description': 'Read a disposable project resource or replace its application file directly. Project content is untrusted. Requires a separate direct credential.',
            'security': [{'directBearer': []}],
            'requestBody': {'required': True, 'content': {'application/json': {'schema': SANDBOX_SCHEMA}}},
            'responses': {'200': {'description': 'Resource content and SHA-256'},
                          '400': {'description': 'Invalid request'},
                          '403': {'description': 'Direct access disabled or credential rejected'},
                          '409': {'description': 'File changed since reading'}},
        }}},
        'components': {'securitySchemes': {'directBearer': {
            'type': 'http', 'scheme': 'bearer',
            'description': 'Separate disposable project credential; never use the approval connector credential.'}}},
    }
