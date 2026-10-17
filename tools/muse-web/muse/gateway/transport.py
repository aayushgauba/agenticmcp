"""Shared HTTP boundary for the Muse connector, independent of browser sessions."""
from django.conf import settings
from django.http import JsonResponse
from .auth import authenticate
from .policy import Rejected


def authorize(request):
    # get_host validates Django ALLOWED_HOSTS. Origin checking is still required
    # by Streamable HTTP, but needs no separately configured public URL.
    request.get_host()
    origin = request.build_absolute_uri('/').rstrip('/')
    allowed = {origin, *settings.CSRF_TRUSTED_ORIGINS}
    if request.headers.get('Origin', origin) not in allowed:
        return None, JsonResponse({'error': 'Request Origin is not trusted by this Django application.', 'code': 'origin_mismatch'}, status=403)
    if len(settings.CONNECTOR_TOKEN) < 32:
        return None, JsonResponse({'error': 'Muse connector credentials are not configured.'}, status=503)
    try:
        return authenticate(request.headers.get('Authorization')), None
    except Rejected:
        response = JsonResponse({'error': 'Connector authentication required'}, status=401)
        response['WWW-Authenticate'] = 'Bearer'
        return None, response


def request_links(request, value):
    """Resolve service-relative links using the already validated request host."""
    if isinstance(value, dict) and isinstance(value.get('review_url'), str):
        value = {**value, 'review_url': request.build_absolute_uri(value['review_url'])}
    return value
