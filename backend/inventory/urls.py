from django.urls import path

from .views import DeviceListView


urlpatterns = [
    path("devices/", DeviceListView.as_view(), name="device-list"),
]
