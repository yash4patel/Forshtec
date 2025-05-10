from django.urls import path
from .views import IPAddressView, IPAddressDBView

urlpatterns = [
    path('<str:ip_address>/', IPAddressView.as_view(), name='ip-analysis'),
    path('db/<str:ip_address>/', IPAddressDBView.as_view(), name='ip-db-analysis'),
]