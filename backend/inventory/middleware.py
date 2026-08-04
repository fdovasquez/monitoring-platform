from django.shortcuts import redirect
from django.conf import settings
from django.urls import reverse

from .models import UserProfile


class ForcePasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            static_url = settings.STATIC_URL if settings.STATIC_URL.startswith("/") else f"/{settings.STATIC_URL}"
            media_url = settings.MEDIA_URL if settings.MEDIA_URL.startswith("/") else f"/{settings.MEDIA_URL}"
            if request.path.startswith(static_url) or request.path.startswith(media_url):
                return self.get_response(request)
            profile, _ = UserProfile.objects.get_or_create(user=user)
            allowed_paths = {
                reverse("password-change"),
                reverse("password-change-done"),
                reverse("logout"),
            }
            if profile.must_change_password and request.path not in allowed_paths:
                return redirect("password-change")
        return self.get_response(request)
