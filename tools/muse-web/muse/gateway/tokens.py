import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from .policy import Rejected


def private_key():
    key = serialization.load_pem_private_key(settings.SIGNING_KEY_PATH.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise Rejected('Ed25519 signing key required')
    return key


def mint(intent):
    return jwt.encode({
        'iss': settings.PUBLIC_URL, 'aud': settings.PUBLIC_URL + '/api/execute/',
        'sub': intent.actor, 'jti': str(intent.id),
        'iat': int(intent.approved_at.timestamp()), 'nbf': int(intent.approved_at.timestamp()),
        'exp': int(intent.expires_at.timestamp()), 'profile': 'muse-intent-v1',
        'action': intent.action, 'action_sha256': intent.digest,
    }, private_key(), algorithm='EdDSA', headers={'typ': 'muse-intent+jwt'})


def verify(token, actor):
    try:
        if jwt.get_unverified_header(token).get('typ') != 'muse-intent+jwt':
            raise Rejected('Wrong token type')
        claims = jwt.decode(token, private_key().public_key(), algorithms=['EdDSA'],
            audience=settings.PUBLIC_URL + '/api/execute/', issuer=settings.PUBLIC_URL,
            options={'require': ['iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'profile', 'action', 'action_sha256']})
        if claims['sub'] != actor or claims['profile'] != 'muse-intent-v1':
            raise Rejected('Wrong token subject or profile')
        return claims
    except jwt.PyJWTError as error:
        raise Rejected('Invalid or expired intent token') from error
