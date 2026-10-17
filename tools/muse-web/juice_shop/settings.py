import os
import json
import secrets
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')
DEBUG = os.getenv('DJANGO_DEBUG', '1') == '1'
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', '')
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured('Set DJANGO_SECRET_KEY before deploying')
    secret_file = BASE_DIR / '.local-secret'
    if not secret_file.exists():
        try:
            with secret_file.open('x', encoding='utf-8') as stream:
                stream.write(secrets.token_urlsafe(48))
        except FileExistsError:
            pass
    SECRET_KEY = secret_file.read_text(encoding='utf-8')
ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
CSRF_TRUSTED_ORIGINS = list(filter(None, os.getenv('DJANGO_CSRF_TRUSTED_ORIGINS', '').split(',')))
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions',
                  'django.contrib.messages', 'django.contrib.staticfiles', 'shop', 'muse.gateway']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware',
              'django.contrib.sessions.middleware.SessionMiddleware',
              'django.middleware.common.CommonMiddleware',
              'django.middleware.csrf.CsrfViewMiddleware',
              'django.contrib.auth.middleware.AuthenticationMiddleware',
              'django.contrib.messages.middleware.MessageMiddleware',
              'django.middleware.clickjacking.XFrameOptionsMiddleware']
ROOT_URLCONF = 'juice_shop.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True,
              'OPTIONS': {'context_processors': ['django.template.context_processors.request',
                  'django.contrib.messages.context_processors.messages', 'django.contrib.auth.context_processors.auth', 'shop.context.cart_summary']}}]
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': BASE_DIR / 'shop.sqlite3',
                         'OPTIONS': {'timeout': 20}}}
WSGI_APPLICATION = 'juice_shop.wsgi.application'
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'UTC'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = os.getenv('DJANGO_SECURE_COOKIES', '0' if DEBUG else '1') == '1'
CSRF_COOKIE_SECURE = SESSION_COOKIE_SECURE
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 64 * 1024

# Muse is an independent bearer-authenticated gateway alongside the storefront.
# Historical secrets may be reused; historical databases are never overwritten.
STATE_DIR = Path(os.getenv('MUSE_STATE_DIR', BASE_DIR / 'state'))
_muse_config = STATE_DIR / 'config.json'
_muse_secrets = json.loads(_muse_config.read_text()) if _muse_config.exists() else {}
CONNECTOR_TOKEN = os.getenv('MUSE_CONNECTOR_TOKEN', _muse_secrets.get('connector_token', ''))
CONNECTOR_ID = 'muse-connector'
SIGNING_KEY_PATH = Path(os.getenv('MUSE_SIGNING_KEY_PATH', STATE_DIR / 'signing.pem'))
API_MODE = os.getenv('MUSE_API_MODE', 'forward')
FORWARD_BASE_URL = os.getenv('MUSE_FORWARD_BASE_URL', '').rstrip('/')
FORWARD_BEARER_TOKEN = os.getenv('MUSE_FORWARD_BEARER_TOKEN', '')
GITHUB_TOKEN = os.getenv('MUSE_GITHUB_TOKEN', '')
GITHUB_REPOSITORIES = frozenset(filter(None, os.getenv('MUSE_GITHUB_REPOSITORIES', '').split(',')))
INTENT_TTL_SECONDS = 300
PROPOSAL_TTL_SECONDS = 3600
# Historical experimental bypass endpoints are deliberately not routed.
SANDBOX_ENABLED = False
SANDBOX_DIRECT_ENABLED = False
SANDBOX_DIRECT_TOKEN = ''
SANDBOX_RUN_ID = ''
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/approvals/'
