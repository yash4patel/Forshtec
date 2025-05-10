from django.urls import path
from django.views.generic import TemplateView
from .views import FileUploadAnalysisView,DatabaseFileView

urlpatterns = [
    path('upload/', TemplateView.as_view(template_name='upload.html'), name='upload'),
    path('file-analysis/', FileUploadAnalysisView.as_view(), name='file-analyze'),
    path('file-db/<str:file_hash>/', DatabaseFileView.as_view(), name='file-db'),

]