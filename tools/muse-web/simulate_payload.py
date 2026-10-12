"""Compare an unauthenticated caller with connector bearer authentication.

Only proposes requests and attempts application with a deliberately fake token.
Never approves requests or supplies a genuine action token. With connector mode
this leaves one persistent pending request for the human to inspect/reject.
"""
import argparse
import getpass
import json
from pathlib import Path
from urllib.parse import urlsplit
import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='https://unau.pythonanywhere.com')
    parser.add_argument('--mode', choices=['without-connector', 'with-connector'], default='without-connector')
    args = parser.parse_args()
    origin = args.base_url.rstrip('/')
    url = urlsplit(origin)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path or url.query or url.fragment):
        parser.error('Use a bare HTTPS origin')
    proposal = json.loads((Path(__file__).parent / 'fixtures' / 'malicious-request.json').read_text(encoding='utf-8'))
    headers = {}
    if args.mode == 'with-connector':
        token = getpass.getpass('Connector token (hidden; do not paste into chat): ').strip()
        if not token:
            parser.error('A connector token is required in this mode')
        headers['Authorization'] = 'Bearer ' + token
    results = {'mode': args.mode, 'base_url': origin, 'checks': []}
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False, headers=headers) as client:
        response = client.post(origin + '/api/intents/', json=proposal)
        expected = 401 if args.mode == 'without-connector' else 200
        results['checks'].append({'check': 'submit_payload', 'http_status': response.status_code, 'expected': expected})
        if response.status_code != expected:
            print(json.dumps(results, indent=2))
            raise SystemExit('Unexpected response. Inspect server logs; no further calls made.')
        if args.mode == 'with-connector':
            pending = response.json()
            results.update({key: pending.get(key) for key in ['intent_id', 'status', 'review_url', 'forwarding_configured']})
            if pending.get('status') != 'pending' or 'intent_token' in pending:
                print(json.dumps(results, indent=2))
                raise SystemExit('Expected an unapproved pending intent. No further calls made.')
            fake_execution = {**proposal, 'intent_id': pending['intent_id'], 'intent_token': 'already-approved'}
            denied = client.post(origin + '/api/execute/', json=fake_execution)
            results['checks'].append({'check': 'forged_approval_rejected', 'http_status': denied.status_code, 'expected': 400})
            if denied.status_code != 400:
                print(json.dumps(results, indent=2))
                raise SystemExit('Unexpected approval-boundary response; inspect the server.')
            current = client.post(origin + '/api/intents/status/', json={'intent_id': pending['intent_id']})
            results['checks'].append({'check': 'still_pending', 'http_status': current.status_code,
                                      'pending': current.status_code == 200 and current.json().get('status') == 'pending'})
            if current.status_code != 200 or current.json().get('status') != 'pending' or 'intent_token' in current.json():
                print(json.dumps(results, indent=2))
                raise SystemExit('Intent did not remain pending; inspect the server.')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
