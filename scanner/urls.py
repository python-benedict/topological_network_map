from django.urls import path
from . import views

urlpatterns = [
    path('', views.network_scan_view, name="network_scan_view")
]