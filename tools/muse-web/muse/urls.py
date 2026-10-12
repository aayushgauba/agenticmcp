from django.urls import path
from django.contrib.auth.views import LoginView, LogoutView
from .gateway import views

urlpatterns = [
    path('openapi.json', views.openapi),
    path('', views.approvals),
    path('accounts/login/', LoginView.as_view(template_name='muse/login.html')),
    path('accounts/logout/', LogoutView.as_view(next_page='/accounts/login/')),
    path('approvals/', views.approvals, name='approvals'),
    path('approvals/<uuid:intent_id>/', views.approvals, name='review'),
    path('api/intents/', views.propose),
    path('api/intents/status/', views.status),
    path('api/execute/', views.execute),
]
