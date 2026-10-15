import uuid
from decimal import Decimal
from django.db import models
from django.db.models import Q


class Product(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    category = models.CharField(max_length=30)
    emoji = models.CharField(max_length=10)
    color = models.CharField(max_length=7, default='#f0f4c3')
    price = models.DecimalField(max_digits=8, decimal_places=2)
    stock = models.PositiveIntegerField(default=50)
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']
        constraints = [models.CheckConstraint(condition=Q(price__gte=0), name='product_price_nonnegative')]


class Cart(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_key = models.CharField(max_length=40)
    status = models.CharField(max_length=20, default='open', choices=[('open', 'Open'), ('checked_out', 'Checked out')])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['session_key'], condition=Q(status='open'), name='one_open_cart_per_session')]

    @property
    def total(self):
        return sum((item.subtotal for item in self.items.select_related('product')), Decimal('0.00'))


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, related_name='items', on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['cart', 'product'], name='unique_cart_product'),
                       models.CheckConstraint(condition=Q(quantity__gte=1) & Q(quantity__lte=99), name='cart_quantity_bounds')]

    @property
    def subtotal(self):
        return self.product.price * self.quantity


class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cart = models.OneToOneField(Cart, on_delete=models.PROTECT)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    lines = models.JSONField()
    total = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, default='pending', choices=[('pending', 'Pending'), ('paid', 'Paid'), ('declined', 'Declined')])
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    payment_reference = models.UUIDField(default=uuid.uuid4, editable=False)
