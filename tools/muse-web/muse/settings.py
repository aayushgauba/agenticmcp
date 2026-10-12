import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')
STATE_DIR = Path(os.environ.get('MUSE_STATE_DIR', BASE_DIR / 'state'))
_config = STATE_DIR / 'config.json'
_secrets = json.loads(_config.read_text()) if _config.exists() else {}
SECRET_KEY = os.environ.get('MUSE_DJANGO_SECRET_KEY', _secrets.get('django_secret', 'not-configured'))
CONNECTOR_TOKEN = os.environ.get('MUSE_CONNECTOR_TOKEN', _secrets.get('connector_token', ''))
CONNECTOR_ID = 'muse-connector'
SIGNING_KEY_PATH = Path(os.environ.get('MUSE_SIGNING_KEY_PATH', STATE_DIR / 'signing.pem'))
GITHUB_TOKEN = os.environ.get('MUSE_GITHUB_TOKEN', '')
GITHUB_REPOSITORIES = frozenset(filter(None, os.environ.get('MUSE_GITHUB_REPOSITORIES', '').split(',')))
PUBLIC_URL = os.environ.get('MUSE_PUBLIC_URL', 'http://127.0.0.1:8000').rstrip('/')
LOCAL_HTTP = os.environ.get('MUSE_LOCAL_HTTP') == '1'
INTENT_TTL_SECONDS = 300
PROPOSAL_TTL_SECONDS = 3600
DEBUG = False
ALLOWED_HOSTS = [urlsplit(PUBLIC_URL).hostname or '127.0.0.1']
CSRF_TRUSTED_ORIGINS = [PUBLIC_URL]
INSTALLED_APPS = ['django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'muse.gateway']
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
ROOT_URLCONF = 'muse.urls'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': STATE_DIR / 'muse.sqlite3', 'OPTIONS': {'timeout': 20}}}
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth']}}]
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
USE_TZ = True
TIME_ZONE = 'UTC'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/approvals/'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = not LOCAL_HTTP
CSRF_COOKIE_SECURE = not LOCAL_HTTP
SECURE_SSL_REDIRECT = not LOCAL_HTTP
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 512 * 1024
# No forwarded-host/proto headers are trusted by default. Terminate TLS on this
# server or configure a trusted reverse proxy explicitly; never trust arbitrary headers.

# Default to a generic approval inbox; no destination is required to receive requests.
API_MODE = os.environ.get('MUSE_API_MODE', 'forward')
FORWARD_BASE_URL = os.environ.get('MUSE_FORWARD_BASE_URL', '').rstrip('/')
FORWARD_BEARER_TOKEN = os.environ.get('MUSE_FORWARD_BEARER_TOKEN', '')
