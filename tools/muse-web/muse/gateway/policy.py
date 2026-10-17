import hashlib
import json
import re
from django.conf import settings
from jsonschema import Draft202012Validator


class Rejected(Exception):
    pass


def object_schema(properties, required=None):
    return {'type': 'object', 'properties': properties, 'required': required or list(properties), 'additionalProperties': False}


TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 1000}
REPO = {'type': 'string', 'pattern': r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'}
REF = {'type': 'string', 'pattern': r'^[A-Za-z0-9][A-Za-z0-9/_-]{0,99}$'}
SHA = {'type': 'string', 'pattern': r'^[0-9a-f]{40}$'}
SCHEMAS = {
    'read_repository': object_schema({'repository': REPO}),
    'read_file': object_schema({'repository': REPO, 'commit_sha': SHA, 'path': TEXT}),
    'create_pull_request': object_schema({
        'repository': REPO, 'base_branch': REF, 'base_sha': SHA, 'branch': REF,
        'title': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'body': {'type': 'string', 'maxLength': 10000},
        'files': {'type': 'array', 'minItems': 1, 'maxItems': 10, 'items': object_schema({
            'path': TEXT, 'content': {'type': 'string', 'maxLength': 100000}, 'mode': {'enum': ['100644', '100755']},
        })},
    }),
}


FORWARD_SCHEMAS = {
    'forward_request': object_schema({
        'method': {'enum': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']},
        'path': {'type': 'string', 'minLength': 1, 'maxLength': 2048},
        'url': {'type': 'string', 'minLength': 1, 'maxLength': 4096, 'description': 'Full public HTTPS destination including path and query. Never include the connector token.'},
        'headers': {'type': 'object', 'properties': {
            'Accept': {'type': 'string', 'maxLength': 200},
            'Content-Type': {'type': 'string', 'maxLength': 200},
        }, 'additionalProperties': False},
        'body': {'type': 'string', 'maxLength': 100000},
    }, required=['method']),
}
FORWARD_SCHEMAS['forward_request']['oneOf'] = [
    {'required': ['url'], 'not': {'required': ['path']}},
    {'required': ['path'], 'not': {'required': ['url']}},
]


def action_schemas():
    schemas = dict(SCHEMAS if settings.API_MODE == 'github' else FORWARD_SCHEMAS)
    if settings.SANDBOX_ENABLED:
        schemas['sandbox_request'] = SANDBOX_SCHEMA
    return schemas


SANDBOX_SCHEMA = object_schema({
    'method': {'enum': ['GET', 'PUT']},
    'path': {'enum': ['/documentation', '/application', '/policy', '/diagnostic']},
    'body': {'type': 'string', 'maxLength': 100000},
    'before_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
}, required=['method', 'path'])


def validate(action, parameters):
    schemas = action_schemas()
    if action not in schemas:
        raise Rejected('Action is not allowed')
    if not Draft202012Validator(schemas[action]).is_valid(parameters):
        raise Rejected('Parameters do not match the action schema')
    if action == 'sandbox_request':
        from .sandbox import enabled
        enabled()
        if parameters['method'] == 'GET' and set(parameters) != {'method', 'path'}:
            raise Rejected('Sandbox reads accept only method and path')
        if parameters['method'] == 'PUT' and (parameters['path'] != '/application'
                or set(parameters) != {'method', 'path', 'body', 'before_sha256'}):
            raise Rejected('Only the application is writable; body and before_sha256 are required')
        if parameters['method'] == 'PUT':
            from .sandbox import application_content
            application_content(parameters['body'])
        return parameters
    if action == 'forward_request':
        if 'url' in parameters:
            from .forwarding import validate_url
            validate_url(parameters['url'])
        else:
            path = parameters['path']
            if (not path.startswith('/') or path.startswith('//') or '\\' in path or '#' in path
                    or any(ord(c) < 33 or ord(c) == 127 for c in path)):
                raise Rejected('Use a relative API path beginning with a single slash')
        for value in parameters.get('headers', {}).values():
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise Rejected('Invalid request header')
        if parameters['method'] in ('GET', 'HEAD') and parameters.get('body'):
            raise Rejected('GET and HEAD requests cannot have a body')
        return parameters
    if parameters['repository'] not in settings.GITHUB_REPOSITORIES:
        raise Rejected('Repository is not allowed')
    paths = [parameters['path']] if action == 'read_file' else [f['path'] for f in parameters.get('files', [])]
    if len(paths) != len(set(paths)):
        raise Rejected('Duplicate paths are not allowed')
    for path in paths:
        if not re.fullmatch(r'[A-Za-z0-9_. /-]+', path) or any(p in ('', '.', '..') for p in path.split('/')):
            raise Rejected('Invalid repository path')
    for name in ('branch', 'base_branch'):
        if name in parameters and ('//' in parameters[name] or parameters[name].endswith('/')):
            raise Rejected('Invalid branch')
    if action == 'create_pull_request' and (not parameters['branch'].startswith('muse/') or parameters['branch'] == parameters['base_branch']):
        raise Rejected('New branches must use muse/ and differ from the base')
    return parameters


def action_digest(action, parameters):
    # Profile v1 has only bounded strings, objects and arrays; numbers/floats are
    # absent. These exact UTF-8 bytes are the documented binding, not RFC 8785.
    value = {'profile': 'muse-intent-v1', 'action': action, 'parameters': parameters}
    if action == 'forward_request' and 'url' not in parameters:
        value['destination'] = settings.FORWARD_BASE_URL
    if action == 'sandbox_request':
        value['sandbox_run_id'] = settings.SANDBOX_RUN_ID
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
