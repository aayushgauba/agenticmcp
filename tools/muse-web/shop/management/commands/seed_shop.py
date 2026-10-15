from decimal import Decimal
from django.core.management.base import BaseCommand
from shop.models import Product

PRODUCTS = [
    ('Orange Sunrise', 'Sweet oranges, a squeeze of lemon, and a sunny start.', 'Citrus', '🍊', '#f8deb5', '6.50'),
    ('Green Day', 'Crisp apple, leafy greens, cucumber, and a ginger kick.', 'Greens', '🥬', '#e0ebc1', '7.50'),
    ('Berry Good', 'Strawberry, blueberry, and apple. Your happy place, bottled.', 'Berries', '🍓', '#f2d4d8', '7.00'),
    ('Tropical State', 'Mango meets pineapple for an instant island moment.', 'Tropical', '🥭', '#f5e6ad', '8.00'),
    ('Lemon Glow', 'Bright lemon, fresh ginger, and a little golden goodness.', 'Citrus', '🍋', '#edf0bb', '6.00'),
    ('Watermelon Wave', 'Juicy watermelon and fresh mint. Summer in every sip.', 'Refreshers', '🍉', '#dfebda', '7.00'),
]


class Command(BaseCommand):
    help = 'Add six demo juices without resetting existing prices or inventory.'

    def handle(self, *args, **options):
        created = 0
        for name, description, category, emoji, color, price in PRODUCTS:
            _, new = Product.objects.get_or_create(name=name, defaults={
                'description': description, 'category': category, 'emoji': emoji,
                'color': color, 'price': Decimal(price), 'stock': 50})
            created += new
        self.stdout.write(self.style.SUCCESS(f'Added {created} juices. Catalog contains {Product.objects.count()} products.'))
