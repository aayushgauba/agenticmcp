"""Compatibility entry point; MCP and REST share Django routing and validation."""
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'juice_shop.settings')
application = get_asgi_application()
