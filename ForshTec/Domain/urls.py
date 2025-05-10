from django.urls import path
from .views import DomainReportView, DatabaseDomainView, DomainFilterView

urlpatterns = [
    # Base domain report from VirusTotal
    path('virustotal/<str:domain_name>/', DomainReportView.as_view(), name='virustotal-domain-report'),
    
    # Database views for domain details
    path('database/<str:domain_name>/', DatabaseDomainView.as_view(), name='database-domain'),
    
    # Filter domains with query parameters
    path('filter/', DomainFilterView.as_view(), name='domain-filter'),
]