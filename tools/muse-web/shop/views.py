from decimal import Decimal
from django.contrib import messages
from django.core import signing
from django.db import transaction
from django.db.models import F
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.views.decorators.debug import sensitive_post_parameters
from .forms import QuantityForm, CheckoutForm, PaymentForm
from .models import Cart, CartItem, Product, Order

PAYMENT_SALT = 'juice-shop.fake-payment.v1'


def active_cart(request):
    key = request.session.session_key
    return Cart.objects.filter(session_key=key, status='open').first() if key else None


def owned_order(request, order_id):
    return get_object_or_404(Order, pk=order_id, cart__session_key=request.session.session_key or '')


@require_GET
def catalog(request):
    products = Product.objects.filter(active=True)
    category = request.GET.get('category', '')
    query = request.GET.get('q', '').strip()[:100]
    if category:
        products = products.filter(category=category)
    if query:
        products = products.filter(name__icontains=query)
    return render(request, 'shop/catalog.html', {'products': products, 'category': category, 'query': query,
        'categories': Product.objects.filter(active=True).values_list('category', flat=True).distinct().order_by('category')})


@require_GET
@never_cache
def cart_view(request):
    cart = active_cart(request)
    return render(request, 'shop/cart.html', {'cart': cart, 'items': cart.items.select_related('product') if cart else []})


@require_POST
def add_item(request, product_id):
    product = get_object_or_404(Product, pk=product_id, active=True)
    form = QuantityForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest('Quantity must be an integer between 1 and 99.')
    if not request.session.session_key:
        request.session.create()
    with transaction.atomic():
        cart, _ = Cart.objects.get_or_create(session_key=request.session.session_key, status='open')
        cart = Cart.objects.select_for_update().get(pk=cart.pk)
        item = CartItem.objects.filter(cart=cart, product=product).first()
        quantity = (item.quantity if item else 0) + form.cleaned_data['quantity']
        if quantity > min(product.stock, 99):
            messages.error(request, 'That quantity is not available. Your cart was not changed.')
        else:
            CartItem.objects.update_or_create(cart=cart, product=product, defaults={'quantity': quantity})
            messages.success(request, product.name + ' added to your cart.')
    return redirect('cart')


@require_POST
def update_item(request, item_id):
    form = QuantityForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest('Quantity must be an integer between 1 and 99.')
    with transaction.atomic():
        item = get_object_or_404(CartItem.objects.select_for_update(), pk=item_id,
            cart__session_key=request.session.session_key or '', cart__status='open')
        if not item.product.active or form.cleaned_data['quantity'] > item.product.stock:
            messages.error(request, 'That quantity is not available.')
        else:
            item.quantity = form.cleaned_data['quantity']
            item.save(update_fields=['quantity'])
    return redirect('cart')


@require_POST
def remove_item(request, item_id):
    item = get_object_or_404(CartItem, pk=item_id, cart__session_key=request.session.session_key or '', cart__status='open')
    item.delete()
    messages.success(request, 'Item removed.')
    return redirect('cart')


@require_http_methods(['GET', 'POST'])
@never_cache
def checkout(request):
    cart = active_cart(request)
    form = CheckoutForm(request.POST if request.method == 'POST' else None, initial={'cart_id': cart.pk if cart else ''})
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            selected = get_object_or_404(Cart.objects.select_for_update(), pk=form.cleaned_data['cart_id'],
                                        session_key=request.session.session_key or '')
            existing = Order.objects.filter(cart=selected).first()
            if existing:
                return redirect('gateway', order_id=existing.pk)
            items = list(selected.items.select_related('product'))
            if not items:
                messages.error(request, 'Add a juice before checking out.')
                return redirect('cart')
            if selected.status != 'open' or any(not i.product.active or i.quantity > i.product.stock for i in items):
                messages.error(request, 'Some items are unavailable. Please review your cart.')
                return redirect('cart')
            lines = [{'product_id': i.product_id, 'name': i.product.name, 'quantity': i.quantity,
                      'unit_price': str(i.product.price), 'subtotal': str(i.subtotal)} for i in items]
            total = sum((Decimal(line['subtotal']) for line in lines), Decimal('0.00'))
            selected.status = 'checked_out'
            selected.save(update_fields=['status'])
            order = Order.objects.create(cart=selected, name=form.cleaned_data['name'], email=form.cleaned_data['email'], lines=lines, total=total)
        return redirect('gateway', order_id=order.pk)
    if not cart or not cart.items.exists():
        messages.info(request, 'Your cart is empty. Pick something fresh first.')
        return redirect('catalog')
    return render(request, 'shop/checkout.html', {'form': form, 'cart': cart})


@require_GET
@never_cache
def gateway(request, order_id):
    order = owned_order(request, order_id)
    if order.status != 'pending':
        return redirect('receipt', order_id=order.pk)
    token = signing.dumps({'order_id': str(order.pk), 'amount': str(order.total), 'session': request.session.session_key}, salt=PAYMENT_SALT)
    return render(request, 'shop/gateway.html', {'order': order, 'token': token})


@require_POST
@never_cache
@sensitive_post_parameters('card_number', 'expiry', 'cvv')
def pay(request, order_id):
    order = owned_order(request, order_id)
    form = PaymentForm(request.POST)
    if not form.is_valid():
        if 'token' in form.errors or 'outcome' in form.errors:
            return HttpResponseBadRequest('Invalid payment request.')
        return render(request, 'shop/gateway.html', {
            'order': order, 'token': form.cleaned_data['token'], 'form': form,
        }, status=400)
    try:
        claims = signing.loads(form.cleaned_data['token'], salt=PAYMENT_SALT, max_age=900)
    except signing.BadSignature:
        return HttpResponseBadRequest('Payment session expired or invalid. Reload the payment page.')
    if claims != {'order_id': str(order.pk), 'amount': str(order.total), 'session': request.session.session_key}:
        return HttpResponseBadRequest('Payment request does not match this order.')
    try:
        with transaction.atomic():
            order = Order.objects.select_for_update().get(pk=order.pk)
            if order.status != 'pending':
                return redirect('receipt', order_id=order.pk)
            outcome = 'paid' if form.cleaned_data['outcome'] == 'approve' else 'declined'
            if Order.objects.filter(pk=order.pk, status='pending').update(status=outcome) != 1:
                return redirect('receipt', order_id=order.pk)
            if outcome == 'paid':
                for line in order.lines:
                    if Product.objects.filter(pk=line['product_id'], active=True, stock__gte=line['quantity']).update(stock=F('stock') - line['quantity']) != 1:
                        raise ValueError('stock')
                Order.objects.filter(pk=order.pk).update(paid_at=timezone.now())
    except ValueError:
        messages.error(request, 'An item sold out. No demo payment was recorded. Try again after stock is replenished.')
        return redirect('gateway', order_id=order.pk)
    return redirect('receipt', order_id=order.pk)


@require_GET
@never_cache
def receipt(request, order_id):
    order = owned_order(request, order_id)
    if order.status == 'pending':
        return redirect('gateway', order_id=order.pk)
    return render(request, 'shop/receipt.html', {'order': order})
