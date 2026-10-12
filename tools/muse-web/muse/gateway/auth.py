import secrets
from django.conf import settings
from .policy import Rejected


def authenticate(authorization):
    configured = settings.CONNECTOR_TOKEN
    if not configured or not isinstance(authorization, str) or not authorization.startswith('Bearer '):
        raise Rejected('Connector authentication required')
    value = authorization[7:]
    if not secrets.compare_digest(value.encode(), configured.encode()):
        raise Rejected('Connector authentication required')
    return settings.CONNECTOR_ID
