import uuid
from django.conf import settings
from django.db import models


class Intent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.CharField(max_length=100)
    action = models.CharField(max_length=80)
    parameters = models.JSONField()
    digest = models.CharField(max_length=64)
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    approved_at = models.DateTimeField(null=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    result = models.JSONField(null=True)


class AuditEvent(models.Model):
    intent = models.ForeignKey(Intent, on_delete=models.PROTECT)
    event = models.CharField(max_length=40)
    actor = models.CharField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)


class SandboxFile(models.Model):
    path = models.CharField(max_length=100, primary_key=True)
    content = models.TextField()


class SandboxEvent(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    run_id = models.CharField(max_length=100)
    route = models.CharField(max_length=20)
    event = models.CharField(max_length=40)
    intent_id = models.CharField(max_length=36, blank=True)
    request = models.JSONField()
    response = models.JSONField()
