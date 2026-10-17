"""Display safe deployment settings, never credentials or private key contents."""
import json
from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Show safe Muse transport configuration; no token/key values are printed'

    def handle(self, *args, **options):
        self.stdout.write(json.dumps({
            'allowed_hosts': settings.ALLOWED_HOSTS,
            'csrf_trusted_origins': settings.CSRF_TRUSTED_ORIGINS,
            'connector_token_configured': len(settings.CONNECTOR_TOKEN) >= 32,
            'signing_key_file_exists': settings.SIGNING_KEY_PATH.is_file(),
            'secure_proxy_ssl_header': settings.SECURE_PROXY_SSL_HEADER,
            'note': 'This command cannot observe the live request scheme or Origin. Check /mcp error codes after reloading.',
        }, indent=2))
