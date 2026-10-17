from datetime import timedelta
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from .github import execute_github
from .forwarding import execute_forward, destination
from .models import Intent, AuditEvent
from .policy import Rejected, validate, action_digest
from .tokens import mint, verify


def load_intent(intent_id, actor=None):
    try:
        intent = Intent.objects.get(pk=intent_id, **({'actor': actor} if actor else {}))
    except (Intent.DoesNotExist, ValidationError, ValueError, TypeError) as error:
        raise Rejected('Unknown intent') from error
    if action_digest(intent.action, intent.parameters) != intent.digest:
        raise Rejected('Stored proposal does not match its digest')
    return intent


def propose(actor, action, parameters):
    try:
        validate(action, parameters)
    except Rejected as error:
        if action == 'sandbox_request' and settings.SANDBOX_ENABLED:
            from .sandbox import record, safe_parameters
            record('approval', 'rejected_proposal', safe_parameters(parameters), {'error': str(error)})
        raise
    with transaction.atomic():
        intent = Intent.objects.create(actor=actor, action=action, parameters=parameters,
            digest=action_digest(action, parameters), expires_at=timezone.now() + timedelta(seconds=settings.PROPOSAL_TTL_SECONDS))
        AuditEvent.objects.create(intent=intent, event='proposed', actor=actor)
        if action == 'sandbox_request':
            from .sandbox import record
            record('approval', 'proposed', parameters, {'status': 'pending'}, intent.id)
    return status(actor, str(intent.id))


def status(actor, intent_id):
    intent = load_intent(intent_id, actor)
    expired = intent.expires_at <= timezone.now() and intent.status in ('pending', 'approved')
    result = {'intent_id': str(intent.id), 'status': 'expired' if expired else intent.status,
        'action': intent.action, 'action_sha256': intent.digest,
        'review_url': '/approvals/' + str(intent.id) + '/',
        'expires_at': intent.expires_at.isoformat()}
    if intent.action == 'forward_request':
        result['destination'] = intent.parameters.get('url') or settings.FORWARD_BASE_URL or None
        result['forwarding_configured'] = 'url' in intent.parameters or bool(settings.FORWARD_BASE_URL)
    if intent.status == 'approved' and not expired:
        result['intent_token'] = mint(intent)
    if intent.status in ('succeeded', 'unknown'):
        result['result'] = intent.result
    if intent.action == 'sandbox_request':
        from .sandbox import record
        record('approval', 'status', {'intent_id': str(intent.id)},
               {k: v for k, v in result.items() if k != 'intent_token'}, intent.id)
    return result


def decide(intent_id, user, digest, approve):
    if not user.is_active or not user.is_staff:
        raise Rejected('A human staff login is required')
    with transaction.atomic():
        intent = load_intent(intent_id)
        if intent.digest != digest:
            raise Rejected('Review changed; reload the exact proposal')
        now = timezone.now()
        updated = Intent.objects.filter(pk=intent.id, digest=digest, status='pending', expires_at__gt=now).update(
            status='approved' if approve else 'rejected', approved_by=user,
            approved_at=now if approve else None,
            expires_at=now + timedelta(seconds=settings.INTENT_TTL_SECONDS) if approve else intent.expires_at)
        if updated != 1:
            raise Rejected('Intent is expired or already decided')
        AuditEvent.objects.create(intent=intent, event='approved' if approve else 'rejected', actor=user.get_username())


def execute(actor, intent_id, action, parameters, intent_token):
    try:
        result = _execute(actor, intent_id, action, parameters, intent_token)
    except Rejected as error:
        if action == 'sandbox_request' and settings.SANDBOX_ENABLED:
            from .sandbox import record, safe_parameters
            record('approval', 'rejected', safe_parameters(parameters), {'error': str(error)}, intent_id)
        raise
    return result


def _execute(actor, intent_id, action, parameters, intent_token):
    # This is the common verification boundary for both MCP and REST. There is
    # no alternate tool or API that can forward without these checks.
    validate(action, parameters)
    claims = verify(intent_token, actor)
    intent = load_intent(intent_id, actor)
    digest = action_digest(action, parameters)
    if claims['jti'] != str(intent.id) or claims['action'] != action or claims['action_sha256'] != digest or intent.digest != digest:
        raise Rejected('Intent token does not bind this exact action and parameters')
    if not intent.approved_by_id or not intent.approved_at:
        raise Rejected('Independent approval is missing')
    if action == 'forward_request':
        destination(parameters)  # Unconfigured legacy path requests remain queued.
    # Atomic compare-and-swap works on SQLite too. Consume before external I/O
    # and commit immediately: concurrent requests/replays cannot both execute.
    with transaction.atomic():
        changed = Intent.objects.filter(pk=intent.id, actor=actor, digest=digest, status='approved', expires_at__gt=timezone.now()).update(status='executing')
        if changed != 1:
            raise Rejected('Intent is expired, already used, or not approved')
        AuditEvent.objects.create(intent=intent, event='execution_started', actor=actor)
    try:
        if action == 'sandbox_request':
            from .sandbox import execute as execute_sandbox
            result = execute_sandbox(parameters, 'approval', intent.id)
        else:
            result = execute_forward(parameters) if action == 'forward_request' else execute_github(action, parameters)
    except Exception:
        # Timeout/partial upstream success is ambiguous. Never re-arm a token,
        # automatically retry, or expose upstream responses/credentials.
        result = {'error': 'Upstream outcome requires human inspection. This intent cannot be retried.'}
        with transaction.atomic():
            Intent.objects.filter(pk=intent.id).update(status='unknown', result=result)
            AuditEvent.objects.create(intent=intent, event='execution_unknown', actor=actor)
        raise Rejected(result['error']) from None
    with transaction.atomic():
        Intent.objects.filter(pk=intent.id).update(status='succeeded', result=result)
        AuditEvent.objects.create(intent=intent, event='execution_succeeded', actor=actor)
    return result
