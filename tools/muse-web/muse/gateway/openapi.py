from django.conf import settings
from .policy import SCHEMAS, object_schema


def document():
    identifier = {'type': 'string', 'format': 'uuid'}
    proposals, executions = [], []
    for action, parameters in SCHEMAS.items():
        fields = {'action': {'const': action, 'type': 'string'}, 'parameters': parameters}
        proposals.append(object_schema(fields))
        executions.append(object_schema({**fields, 'intent_id': identifier, 'intent_token': {'type': 'string', 'minLength': 1}}))
    descriptions = {
        '/api/intents/': ('proposeIntent', 'Queue an exact GitHub action. Return the human review URL; no GitHub call occurs.', {'oneOf': proposals}),
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
        'openapi': '3.1.0', 'info': {'title': 'Muse approved GitHub actions', 'version': '0.1.0'},
        'servers': [{'url': settings.PUBLIC_URL}], 'paths': paths,
        'components': {'securitySchemes': {'connectorBearer': {'type': 'http', 'scheme': 'bearer', 'description': 'Muse connector credential injected from the Secure Vault. This is not the GitHub token or per-action intent token.'}}},
    }
