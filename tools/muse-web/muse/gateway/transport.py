"""Shared HTTP boundary for the Muse connector, independent of browser sessions."""
from urllib.parse import urlsplit
from django.conf import settings
from django.http import JsonResponse
from .auth import authenticate
from .policy import Rejected


def authorize(request):
    origin = urlsplit(settings.PUBLIC_URL)
    local = (settings.LOCAL_HTTP and origin.scheme == 'http'
             and origin.hostname in ('localhost', '127.0.0.1'))
    if (origin.scheme != 'https' and not local) or origin.path or origin.query or origin.fragment or origin.username:
        return None, JsonResponse({'error': 'Configure a bare HTTPS MUSE_PUBLIC_URL.'}, status=503)
    if (request.get_host() != origin.netloc
            or request.headers.get('Origin', settings.PUBLIC_URL) != settings.PUBLIC_URL
            or (not local and not request.is_secure())):
        return None, JsonResponse({'error': 'Invalid host, origin, or HTTPS scheme.'}, status=403)
    if len(settings.CONNECTOR_TOKEN) < 32:
        return None, JsonResponse({'error': 'Muse connector credentials are not configured.'}, status=503)
    try:
        return authenticate(request.headers.get('Authorization')), None
    except Rejected:
        response = JsonResponse({'error': 'Connector authentication required'}, status=401)
        response['WWW-Authenticate'] = 'Bearer'
        return None, response
