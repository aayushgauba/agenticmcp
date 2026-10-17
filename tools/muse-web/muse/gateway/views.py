import json
from functools import wraps
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden
from django.conf import settings
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.views.decorators.http import require_GET
from django.views.decorators.cache import never_cache
from .auth import authenticate
from .models import Intent
from .policy import Rejected
from . import service
from .transport import authorize


@require_GET
@never_cache
def direct_openapi(request):
    from .openapi import direct_document
    return JsonResponse(direct_document())


@csrf_exempt
@require_POST
@never_cache
def sandbox_direct(request):
    from . import sandbox
    from .policy import validate
    # Sessions and the approval connector credential never authorize this endpoint.
    try:
        sandbox.authenticate_direct(request.headers.get('Authorization'))
    except Rejected as error:
        response = {'error': str(error)}
        try:
            attempted = json.loads(request.body)
            safe = sandbox.safe_parameters(attempted)
        except (ValueError, UnicodeError):
            safe = {}
        sandbox.record('direct', 'rejected', safe, response)
        return JsonResponse(response, status=403)
    parameters = {}
    try:
        if request.content_type != 'application/json':
            raise Rejected('JSON required')
        parameters = json.loads(request.body)
        validate('sandbox_request', parameters)
        result = sandbox.execute(parameters, 'direct')
        return JsonResponse(result, status=result['status_code'])
    except (Rejected, ValueError, KeyError, TypeError) as error:
        response = {'error': str(error) if isinstance(error, Rejected) else 'Invalid request'}
        safe = sandbox.safe_parameters(parameters)
        sandbox.record('direct', 'rejected', safe, response)
        return JsonResponse(response, status=400)


@require_GET
@never_cache
def openapi(request):
    from .openapi import document
    return JsonResponse(document())


def api_view(func):
    @csrf_exempt  # Service bearer only; session cookies never authenticate APIs.
    @require_POST
    @never_cache
    @wraps(func)
    def wrapper(request):
        actor, denied = authorize(request)
        if denied is not None:
            return denied
        try:
            if request.content_type != 'application/json':
                raise Rejected('JSON required')
            data = json.loads(request.body)
            if not isinstance(data, dict):
                raise Rejected('Object required')
            return JsonResponse(func(actor, data))
        except (Rejected, ValueError, KeyError, TypeError) as error:
            return JsonResponse({'error': str(error) if isinstance(error, Rejected) else 'Invalid request'}, status=400)
    return wrapper


@api_view
def propose(request_actor, data):
    if set(data) != {'action', 'parameters'}:
        raise Rejected('Only action and parameters are accepted')
    return service.propose(request_actor, data['action'], data['parameters'])


@api_view
def status(request_actor, data):
    if set(data) != {'intent_id'}:
        raise Rejected('Only intent_id is accepted')
    return service.status(request_actor, data['intent_id'])


@api_view
def execute(request_actor, data):
    if set(data) != {'intent_id', 'action', 'parameters', 'intent_token'}:
        raise Rejected('Unexpected execution fields')
    return service.execute(request_actor, **data)


@never_cache
@login_required
def approvals(request, intent_id=None):
    if not request.user.is_staff or not request.user.is_active:
        return HttpResponseForbidden('Staff login required')
    if intent_id is None:
        return render(request, 'muse/queue.html', {'intents': Intent.objects.order_by('-created_at')[:100]})
    try:
        intent = service.load_intent(intent_id)
        if request.method == 'POST':
            decision = request.POST.get('decision')
            if decision not in ('approve', 'reject'):
                raise Rejected('Unknown decision')
            service.decide(str(intent.id), request.user, request.POST.get('digest'), decision == 'approve')
            return redirect('review', intent_id=intent.id)
        if request.method != 'GET':
            raise Rejected('Unsupported method')
        return render(request, 'muse/review.html', {'intent': intent, 'parameters': json.dumps(intent.parameters, indent=2, ensure_ascii=True), 'destination': (intent.parameters.get('url') or settings.FORWARD_BASE_URL) if intent.action == 'forward_request' else None})
    except Rejected as error:
        return JsonResponse({'error': str(error)}, status=400)
