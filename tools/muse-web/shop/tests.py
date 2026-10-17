from decimal import Decimal
from unittest.mock import patch
from django.core import signing
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from .models import Product, Cart, CartItem, Order
from .views import PAYMENT_SALT


@override_settings(ALLOWED_HOSTS=['testserver'], SESSION_COOKIE_SECURE=False, CSRF_COOKIE_SECURE=False)
class ShoppingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.product = Product.objects.create(name='Orange Sunrise', description='Fresh orange juice.',
            category='Citrus', emoji='🍊', price=Decimal('6.50'), stock=5)

    def add(self, quantity=1, client=None):
        return (client or self.client).post(reverse('add_item', args=[self.product.pk]), {'quantity': quantity})

    def order(self):
        self.add(2)
        cart = Cart.objects.get(session_key=self.client.session.session_key, status='open')
        response = self.client.post(reverse('checkout'), {'cart_id': cart.pk, 'name': 'Demo Shopper', 'email': 'demo@example.com'})
        self.assertEqual(response.status_code, 302)
        return Order.objects.get(cart=cart)

    def token(self, order):
        return self.client.get(reverse('gateway', args=[order.pk])).context['token']

    def pay(self, order, token, outcome='approve', **extra):
        return self.client.post(reverse('pay', args=[order.pk]), {
            'token': token, 'outcome': outcome, 'card_number': '4242 4242 4242 4242',
            'expiry': '12/30', 'cvv': '123', **extra})

    def test_browse_does_not_create_cart_first_add_does_and_duplicate_add_merges(self):
        self.assertContains(self.client.get('/'), 'Orange Sunrise')
        self.client.get('/cart/')
        self.assertEqual(Cart.objects.count(), 0)
        self.add()
        self.add(2)
        self.assertEqual(Cart.objects.count(), 1)
        self.assertEqual(CartItem.objects.get().quantity, 3)
        self.assertEqual(Cart.objects.get().total, Decimal('19.50'))

    def test_invalid_quantities_and_out_of_stock_do_not_add_items(self):
        for quantity in ['-1', '0', '100', '1.5', 'bad']:
            self.assertEqual(self.add(quantity).status_code, 400)
        self.add(6)
        self.assertEqual(CartItem.objects.count(), 0)

    def test_cart_updates_removal_and_cross_session_access(self):
        self.add()
        item = CartItem.objects.get()
        other = Client()
        self.assertEqual(other.post(reverse('update_item', args=[item.pk]), {'quantity': 3}).status_code, 404)
        self.assertEqual(other.post(reverse('remove_item', args=[item.pk])).status_code, 404)
        self.client.post(reverse('update_item', args=[item.pk]), {'quantity': 3})
        item.refresh_from_db()
        self.assertEqual(item.quantity, 3)
        self.client.post(reverse('remove_item', args=[item.pk]))
        self.assertEqual(CartItem.objects.count(), 0)

    def test_cart_and_payment_mutations_reject_get(self):
        self.add()
        item = CartItem.objects.get()
        for name, identifier in [('add_item', self.product.pk), ('update_item', item.pk), ('remove_item', item.pk)]:
            self.assertEqual(self.client.get(reverse(name, args=[identifier])).status_code, 405)
        order = self.order()
        self.assertEqual(self.client.get(reverse('pay', args=[order.pk])).status_code, 405)
        order.refresh_from_db()
        self.assertEqual(order.status, 'pending')

    def test_csrf_is_required_for_cart_checkout_and_payment(self):
        browser = Client(enforce_csrf_checks=True)
        self.assertEqual(self.add(client=browser).status_code, 403)
        browser.get('/')
        csrf = browser.cookies['csrftoken'].value
        self.assertEqual(browser.post(reverse('add_item', args=[self.product.pk]), {'quantity': 1, 'csrfmiddlewaretoken': csrf}).status_code, 302)
        self.assertEqual(browser.post('/checkout/', {}).status_code, 403)
        order = self.order()
        self.assertEqual(browser.post(reverse('pay', args=[order.pk]), {}).status_code, 403)

    def test_checkout_snapshot_ignores_client_amount_and_duplicate_checkout(self):
        order = self.order()
        self.assertEqual(order.total, Decimal('13.00'))
        self.assertEqual(order.lines[0]['unit_price'], '6.50')
        response = self.client.post('/checkout/', {'cart_id': order.cart_id, 'name': 'Changed',
                                   'email': 'demo@example.com', 'total': '0.01'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Order.objects.count(), 1)
        Product.objects.filter(pk=self.product.pk).update(price='99.00')
        order.refresh_from_db()
        self.assertEqual(order.total, Decimal('13.00'))

    def test_successful_fake_payment_receipt_and_replay_do_not_charge_or_decrement_twice(self):
        order = self.order()
        token = self.token(order)
        response = self.pay(order, token, amount='0.01')
        self.assertRedirects(response, reverse('receipt', args=[order.pk]))
        order.refresh_from_db()
        self.product.refresh_from_db()
        self.assertEqual(order.status, 'paid')
        self.assertIsNotNone(order.paid_at)
        self.assertEqual(order.total, Decimal('13.00'))
        self.assertEqual(self.product.stock, 3)
        self.pay(order, token)
        self.pay(order, token, 'decline')
        self.product.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(self.product.stock, 3)
        self.assertEqual(order.status, 'paid')
        self.assertContains(self.client.get(reverse('receipt', args=[order.pk])), 'No real payment was taken')
        self.add()
        self.assertEqual(Cart.objects.filter(status='open').count(), 1)

    def test_decline_does_not_change_stock(self):
        order = self.order()
        self.pay(order, self.token(order), 'decline')
        order.refresh_from_db()
        self.product.refresh_from_db()
        self.assertEqual(order.status, 'declined')
        self.assertIsNone(order.paid_at)
        self.assertEqual(self.product.stock, 5)
        self.assertContains(self.client.get(reverse('receipt', args=[order.pk])), 'Payment declined')

    def test_tampered_expired_and_wrong_order_tokens_fail_without_mutation(self):
        order = self.order()
        token = self.token(order)
        self.assertEqual(self.pay(order, token + 'tampered').status_code, 400)
        wrong = signing.dumps({'order_id': str(order.pk), 'amount': '0.01', 'session': self.client.session.session_key}, salt=PAYMENT_SALT)
        self.assertEqual(self.pay(order, wrong).status_code, 400)
        with patch('django.core.signing.time.time', return_value=1):
            expired = signing.dumps({'order_id': str(order.pk), 'amount': str(order.total), 'session': self.client.session.session_key}, salt=PAYMENT_SALT)
        self.assertEqual(self.pay(order, expired).status_code, 400)
        self.assertEqual(self.pay(order, token, 'unknown').status_code, 400)
        order.refresh_from_db()
        self.assertEqual(order.status, 'pending')

    def test_other_session_cannot_view_or_pay_order(self):
        order = self.order()
        other = Client()
        for name in ['gateway', 'receipt']:
            self.assertEqual(other.get(reverse(name, args=[order.pk])).status_code, 404)
        self.assertEqual(other.post(reverse('pay', args=[order.pk]), {'token': self.token(order), 'outcome': 'approve'}).status_code, 404)
        self.assertEqual(other.post('/checkout/', {'cart_id': order.cart_id, 'name': 'Other', 'email': 'other@example.com'}).status_code, 404)

    def test_inventory_failure_rolls_back_payment(self):
        order = self.order()
        token = self.token(order)
        Product.objects.filter(pk=self.product.pk).update(stock=0)
        self.pay(order, token)
        order.refresh_from_db()
        self.assertEqual(order.status, 'pending')
        self.assertIsNone(order.paid_at)

    def test_experimental_direct_endpoints_remain_removed(self):
        for path in ['/api/sandbox/direct/', '/openapi-direct.json']:
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_fake_card_fields_are_required_and_only_demo_details_accepted(self):
        order = self.order()
        token = self.token(order)
        page = self.client.get(reverse('gateway', args=[order.pk]))
        self.assertContains(page, 'Fake card number')
        self.assertContains(page, 'Never enter real card details')
        for field, value in [('card_number', ''), ('card_number', '5555555555554444'),
                             ('expiry', '01/40'), ('cvv', '999')]:
            response = self.pay(order, token, **{field: value})
            self.assertEqual(response.status_code, 400)
            if field == 'card_number' and value:
                self.assertNotContains(response, value, status_code=400)
        order.refresh_from_db()
        self.assertEqual(order.status, 'pending')
        self.pay(order, token)
        order.refresh_from_db()
        self.assertEqual(order.status, 'paid')
        self.assertNotIn('4242', str(Order.objects.values().get(pk=order.pk)))
        self.assertNotContains(self.client.get(reverse('receipt', args=[order.pk])), '4242')
