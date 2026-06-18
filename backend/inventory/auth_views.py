import hashlib
import secrets
from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import TemplateView

from alerts.models import SmtpSettings
from alerts.services import sender, smtp_backend


class CorporateLoginForm(forms.Form):
    identifier = forms.CharField(label="Usuario o correo", max_length=254)
    password = forms.CharField(label="Contrasena", widget=forms.PasswordInput)

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)
        self.fields["identifier"].widget.attrs.update({
            "placeholder": "usuario@empresa.cl",
            "autocomplete": "username",
            "autofocus": "autofocus",
        })
        self.fields["password"].widget.attrs.update({
            "placeholder": "Ingresa tu contrasena",
            "autocomplete": "current-password",
        })

    def clean(self):
        cleaned_data = super().clean()
        identifier = cleaned_data.get("identifier", "").strip()
        password = cleaned_data.get("password", "")
        if not identifier or not password:
            return cleaned_data

        username = identifier
        if "@" in identifier:
            user = User.objects.filter(email__iexact=identifier).first()
            if user:
                username = user.username

        self.user_cache = authenticate(self.request, username=username, password=password)
        if self.user_cache is None:
            raise forms.ValidationError("Usuario o contrasena incorrectos.")
        if not self.user_cache.is_active:
            raise forms.ValidationError("La cuenta esta desactivada.")
        return cleaned_data

    def get_user(self):
        return self.user_cache


class LoginCodeForm(forms.Form):
    code = forms.CharField(label="Codigo de verificacion", min_length=6, max_length=6)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["code"].widget.attrs.update({
            "placeholder": "000000",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
            "autofocus": "autofocus",
        })

    def clean_code(self):
        code = self.cleaned_data["code"].strip()
        if not code.isdigit():
            raise forms.ValidationError("Ingresa el codigo numerico de 6 digitos.")
        return code


def safe_next_url(request):
    next_url = request.POST.get("next") or request.GET.get("next") or reverse("device-list")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return reverse("device-list")
    return next_url


def code_hash(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def send_login_code_email(user, code):
    if not user.email:
        raise ValueError("El usuario no tiene correo electronico registrado.")
    settings = SmtpSettings.load()
    if not settings.is_configured:
        raise ValueError("La configuracion SMTP esta incompleta.")
    body = (
        "Se solicito el ingreso a la plataforma de monitoreo.\n\n"
        f"Codigo de verificacion: {code}\n\n"
        "Este codigo expira en 10 minutos. Si no solicitaste este acceso, ignora este mensaje."
    )
    message = EmailMessage(
        subject="Codigo de acceso - Plataforma de monitoreo",
        body=body,
        from_email=sender(settings),
        to=[user.email],
        connection=smtp_backend(settings),
    )
    message.send()


class CorporateLoginView(TemplateView):
    template_name = "inventory/login.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(safe_next_url(request))
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form"] = kwargs.get("form") or CorporateLoginForm(request=self.request)
        context["next"] = safe_next_url(self.request)
        context["step"] = "credentials"
        return context

    def post(self, request):
        form = CorporateLoginForm(request, request.POST)
        if not form.is_valid():
            return self.render_to_response(self.get_context_data(form=form))

        user = form.get_user()
        next_url = safe_next_url(request)
        if user.is_superuser:
            login(request, user)
            return redirect(next_url)

        code = f"{secrets.randbelow(1000000):06d}"
        try:
            send_login_code_email(user, code)
        except Exception as exc:
            form.add_error(None, f"No se pudo enviar el codigo de verificacion: {exc}")
            return self.render_to_response(self.get_context_data(form=form))

        request.session["pending_login_2fa"] = {
            "user_id": user.id,
            "code_hash": code_hash(code),
            "expires_at": (timezone.now() + timedelta(minutes=10)).timestamp(),
            "attempts": 0,
            "next_url": next_url,
        }
        messages.success(request, "Enviamos un codigo de verificacion a tu correo.")
        return redirect("login-verify")


class LoginCodeVerifyView(TemplateView):
    template_name = "inventory/login.html"

    def pending(self):
        return self.request.session.get("pending_login_2fa") or {}

    def pending_user(self):
        user_id = self.pending().get("user_id")
        if not user_id:
            return None
        return User.objects.filter(id=user_id, is_active=True).first()

    def dispatch(self, request, *args, **kwargs):
        pending = self.pending()
        if not pending or not self.pending_user():
            messages.error(request, "Inicia sesion nuevamente para recibir un codigo.")
            return redirect("login")
        if timezone.now().timestamp() >= pending.get("expires_at", 0):
            request.session.pop("pending_login_2fa", None)
            messages.error(request, "El codigo expiro. Inicia sesion nuevamente.")
            return redirect("login")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form"] = kwargs.get("form") or LoginCodeForm()
        context["pending_user"] = self.pending_user()
        context["step"] = "code"
        return context

    def post(self, request):
        pending = self.pending()
        user = self.pending_user()
        form = LoginCodeForm(request.POST)
        if form.is_valid() and code_hash(form.cleaned_data["code"]) == pending.get("code_hash"):
            request.session.pop("pending_login_2fa", None)
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            return redirect(pending.get("next_url") or reverse("device-list"))

        pending["attempts"] = int(pending.get("attempts", 0)) + 1
        request.session["pending_login_2fa"] = pending
        if pending["attempts"] >= 5:
            request.session.pop("pending_login_2fa", None)
            messages.error(request, "Demasiados intentos. Inicia sesion nuevamente.")
            return redirect("login")
        form.add_error("code", "El codigo ingresado no es valido.")
        return self.render_to_response(self.get_context_data(form=form))


class CorporateLogoutView(LoginRequiredMixin, TemplateView):
    def post(self, request):
        logout(request)
        return redirect("login")
