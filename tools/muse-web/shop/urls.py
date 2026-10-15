from django.urls import path
from . import views

urlpatterns = [
    path('', views.catalog, name='catalog'),
    path('cart/', views.cart_view, name='cart'),
    path('cart/add/<int:product_id>/', views.add_item, name='add_item'),
    path('cart/items/<int:item_id>/update/', views.update_item, name='update_item'),
    path('cart/items/<int:item_id>/remove/', views.remove_item, name='remove_item'),
    path('checkout/', views.checkout, name='checkout'),
    path('payments/<uuid:order_id>/', views.gateway, name='gateway'),
    path('payments/<uuid:order_id>/submit/', views.pay, name='pay'),
    path('orders/<uuid:order_id>/', views.receipt, name='receipt'),
]
