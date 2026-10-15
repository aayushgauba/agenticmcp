from .models import Cart


def cart_summary(request):
    key = request.session.session_key
    cart = Cart.objects.filter(session_key=key, status='open').first() if key else None
    return {'cart_count': sum(cart.items.values_list('quantity', flat=True)) if cart else 0}
