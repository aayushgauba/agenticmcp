from urllib.parse import quote
import json
import httpx
from django.conf import settings
from .policy import Rejected


def execute_github(action, p):
    if not settings.GITHUB_TOKEN:
        raise Rejected('GitHub credentials are not configured on the server')
    # The API origin is fixed. No user-supplied URL, redirects, proxy env or
    # client-provided authorization is forwarded upstream.
    with httpx.Client(base_url='https://api.github.com', timeout=20, follow_redirects=False, trust_env=False,
        headers={'Authorization': 'Bearer ' + settings.GITHUB_TOKEN, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}) as client:
        def request(method, path, payload=None):
            with client.stream(method, path, json=payload) as response:
                if not 200 <= response.status_code < 300:
                    raise Rejected('GitHub rejected the request (HTTP %s)' % response.status_code)
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 1024 * 1024:
                        raise Rejected('GitHub response exceeded the size limit')
                return json.loads(raw)

        prefix = '/repos/' + p['repository']
        if action == 'read_repository':
            value = request('GET', prefix)
            ref = request('GET', prefix + '/git/ref/heads/' + quote(value['default_branch'], safe='/'))
            return {**{key: value.get(key) for key in ('full_name', 'private', 'default_branch', 'description', 'html_url')}, 'default_branch_sha': ref['object']['sha'], 'untrusted_repository_content': True}
        if action == 'read_file':
            value = request('GET', prefix + '/contents/' + quote(p['path'], safe='/') + '?ref=' + p['commit_sha'])
            if not isinstance(value, dict) or value.get('type') != 'file':
                raise Rejected('Only individual repository files are supported')
            return {**{key: value.get(key) for key in ('path', 'sha', 'size', 'encoding', 'content')}, 'untrusted_repository_content': True}
        if action != 'create_pull_request':
            raise Rejected('Unsupported GitHub action')
        base_ref = prefix + '/git/ref/heads/' + quote(p['base_branch'], safe='/')
        def check_base():
            if request('GET', base_ref)['object']['sha'] != p['base_sha']:
                raise Rejected('Base branch changed; submit a new proposal')
        check_base()
        commit = request('GET', prefix + '/git/commits/' + p['base_sha'])
        tree = request('POST', prefix + '/git/trees', {'base_tree': commit['tree']['sha'], 'tree': [
            {'path': f['path'], 'mode': f['mode'], 'type': 'blob', 'content': f['content']} for f in p['files']]})
        new_commit = request('POST', prefix + '/git/commits', {'message': p['title'], 'tree': tree['sha'], 'parents': [p['base_sha']]})
        # Create-only: an existing branch fails. Never force-update an existing ref.
        request('POST', prefix + '/git/refs', {'ref': 'refs/heads/' + p['branch'], 'sha': new_commit['sha']})
        check_base()
        pull = request('POST', prefix + '/pulls', {'title': p['title'], 'body': p['body'], 'head': p['branch'], 'base': p['base_branch'], 'draft': True})
        return {'number': pull['number'], 'url': pull['html_url'], 'head_sha': new_commit['sha'], 'draft': True}
