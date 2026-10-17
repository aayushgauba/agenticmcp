from django.urls import include, path
from django.contrib.auth.views import LoginView, LogoutView
from muse.gateway import views as gateway
from muse.gateway.mcp_http import endpoint

urlpatterns = [
    path('mcp', endpoint),
    path('mcp/', endpoint),
    path('openapi.json', gateway.openapi),
    path('accounts/login/', LoginView.as_view(template_name='muse/login.html')),
    path('accounts/logout/', LogoutView.as_view(next_page='/accounts/login/')),
    path('approvals/', gateway.approvals, name='approvals'),
    path('approvals/<uuid:intent_id>/', gateway.approvals, name='review'),
    path('api/intents/', gateway.propose),
    path('api/intents/status/', gateway.status),
    path('api/execute/', gateway.execute),
    path('', include('shop.urls')),
]
