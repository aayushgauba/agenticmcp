from .settings import *

SECRET_KEY = 'test-only-django-secret-never-use-in-production-123456789'
CONNECTOR_TOKEN = 'test-only-connector-token-never-use-in-production-123456789'
LOCAL_HTTP = True
PUBLIC_URL = 'http://127.0.0.1:8000'
ALLOWED_HOSTS = ['testserver', '127.0.0.1']
CSRF_TRUSTED_ORIGINS = [PUBLIC_URL]
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
GITHUB_REPOSITORIES = frozenset({'example/demo'})
GITHUB_TOKEN = 'dummy-github-secret'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

# Preserve coverage of the former GitHub adapter independently of the default inbox.
API_MODE = 'github'
