import json
import os
import secrets
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.management.utils import get_random_secret_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Command(BaseCommand):
    help = 'Create local server secrets once; never print them or overwrite existing keys'

    def handle(self, *args, **options):
        settings.STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        config = settings.STATE_DIR / 'config.json'
        if config.exists() or settings.SIGNING_KEY_PATH.exists():
            raise CommandError('Secrets already exist. Refusing to overwrite them.')
        key = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        values = {'django_secret': get_random_secret_key(), 'connector_token': secrets.token_urlsafe(48)}
        for path, content in [(settings.SIGNING_KEY_PATH, key), (config, json.dumps(values).encode())]:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
                file.write(content)
        self.stdout.write('Server secrets created in the private state directory. No secret values were printed.')
