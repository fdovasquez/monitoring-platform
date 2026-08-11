import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from django import forms
from django.conf import settings as django_settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import (
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import TemplateView

from alerts.models import SmtpSettings
from alerts.services import sender, smtp_backend
from .models import SiteSettings, UserProfile


def default_login_redirect():
    if django_settings.CENTRAL_PORTAL_ENABLED:
        return reverse("hub-dashboard")
    return reverse("device-list")


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


class CorporatePasswordResetForm(PasswordResetForm):
    email = forms.CharField(label="Usuario o correo", max_length=254)

    def __init__(self, *args, **kwargs):
        self.user_cache = None
        super().__init__(*args, **kwargs)
        self.fields["email"].widget.attrs.update({
            "placeholder": "usuario@empresa.cl o usuario",
            "autocomplete": "email",
            "autofocus": "autofocus",
        })

    def clean_email(self):
        identifier = self.cleaned_data["email"].strip()
        user = User.objects.filter(email__iexact=identifier, is_active=True).first()
        if not user:
            user = User.objects.filter(username__iexact=identifier, is_active=True).first()
        if not user or not user.has_usable_password():
            raise forms.ValidationError("El usuario o correo no existe.")
        if not user.email:
            raise forms.ValidationError("El usuario existe, pero no tiene correo electronico registrado.")
        self.user_cache = user
        return user.email

    def get_users(self, email):
        if self.user_cache:
            yield self.user_cache

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        smtp_settings = SmtpSettings.load()
        if not smtp_settings.is_configured:
            raise ValueError("La configuracion SMTP esta incompleta.")

        site_settings = SiteSettings.load()
        context.update({
            "display_name": context["user"].get_full_name() or context["user"].username,
            "site_name": site_settings.site_name,
            "site_subtitle": site_settings.subtitle,
        })
        subject = render_to_string(subject_template_name, context)
        subject = "".join(subject.splitlines())
        body = render_to_string(email_template_name, context)
        html_body = render_to_string(html_email_template_name, context) if html_email_template_name else None

        message = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=sender(smtp_settings),
            to=[to_email],
            connection=smtp_backend(smtp_settings),
        )
        if html_body:
            message.attach_alternative(html_body, "text/html")
        message.send()


class CorporateSetPasswordForm(SetPasswordForm):
    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        self.fields["new_password1"].widget.attrs.update({
            "placeholder": "Nueva contrasena",
            "autocomplete": "new-password",
            "autofocus": "autofocus",
        })
        self.fields["new_password2"].widget.attrs.update({
            "placeholder": "Confirma la nueva contrasena",
            "autocomplete": "new-password",
        })

    def clean_new_password1(self):
        password = self.cleaned_data.get("new_password1", "")
        if password:
            if not any(character.isupper() for character in password):
                raise forms.ValidationError("La nueva contrasena debe incluir al menos una mayuscula.")
            if not any(character.islower() for character in password):
                raise forms.ValidationError("La nueva contrasena debe incluir al menos una minuscula.")
            if not any(character.isdigit() for character in password):
                raise forms.ValidationError("La nueva contrasena debe incluir al menos un numero.")
            if not any(not character.isalnum() for character in password):
                raise forms.ValidationError("La nueva contrasena debe incluir al menos un caracter especial.")
        return password


def safe_next_url(request):
    next_url = request.POST.get("next") or request.GET.get("next") or default_login_redirect()
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return default_login_redirect()
    return next_url


def is_viewer_only(user):
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists():
        return False
    return user.groups.filter(name="Visualizador").exists()


def is_client_only(user):
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists():
        return False
    return user.groups.filter(name="Cliente").exists()


def client_safe_next_url(next_url):
    path = urlparse(next_url).path or next_url
    device_list_path = reverse("device-list")
    device_base_path = device_list_path.rstrip("/")
    account_paths = (reverse("profile"), reverse("password-change"), reverse("password-change-done"))
    blocked_fragments = (
        "/operational-history/",
        "/runtime/",
        "/console/",
        "/edit/",
        "/delete/",
        "/credentials/",
    )
    if path == device_list_path:
        return next_url
    if path.startswith(f"{device_base_path}/") and not any(fragment in path for fragment in blocked_fragments):
        return next_url
    for account_path in account_paths:
        if path == account_path or path.startswith(f"{account_path.rstrip('/')}/"):
            return next_url
    return default_login_redirect()


def role_safe_next_url(user, next_url):
    if not next_url:
        return default_login_redirect()
    if is_client_only(user) and not django_settings.CENTRAL_PORTAL_ENABLED:
        return client_safe_next_url(next_url)
    if not is_viewer_only(user):
        return next_url

    path = urlparse(next_url).path or next_url
    if django_settings.CENTRAL_PORTAL_ENABLED:
        allowed_paths = (
            reverse("hub-dashboard"),
            reverse("profile"),
            reverse("password-change"),
        )
    else:
        allowed_paths = (
            reverse("device-list"),
            reverse("profile"),
            reverse("password-change"),
        )
    for allowed_path in allowed_paths:
        if path == allowed_path or path.startswith(f"{allowed_path.rstrip('/')}/"):
            return next_url
    return default_login_redirect()


def code_hash(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def login_url_for_request(request):
    configured_url = getattr(django_settings, "MONITORING_PUBLIC_URL", "").rstrip("/")
    if configured_url:
        return f"{configured_url}{reverse('login-verify')}"
    if request is not None:
        return request.build_absolute_uri(reverse("login-verify"))
    return reverse("login-verify")


def send_login_code_email(user, code, request=None):
    if not user.email:
        raise ValueError("El usuario no tiene correo electronico registrado.")
    smtp_settings = SmtpSettings.load()
    if not smtp_settings.is_configured:
        raise ValueError("La configuracion SMTP esta incompleta.")

    site_settings = SiteSettings.load()
    context = {
        "code": code,
        "login_url": login_url_for_request(request),
        "site_name": site_settings.site_name,
        "site_subtitle": site_settings.subtitle,
        "username": user.get_full_name() or user.username,
        "expires_minutes": 10,
    }
    text_body = render_to_string("inventory/emails/login_code.txt", context)
    html_body = render_to_string("inventory/emails/login_code.html", context)

    message = EmailMultiAlternatives(
        subject="Codigo de acceso - Plataforma de monitoreo",
        body=text_body,
        from_email=sender(smtp_settings),
        to=[user.email],
        connection=smtp_backend(smtp_settings),
    )
    message.attach_alternative(html_body, "text/html")
    message.send()


class CorporateLoginView(TemplateView):
    template_name = "inventory/login.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(role_safe_next_url(request.user, safe_next_url(request)))
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
        if user.is_superuser or user.groups.filter(name="Administrador").exists():
            login(request, user)
            return redirect(role_safe_next_url(user, next_url))

        code = f"{secrets.randbelow(1000000):06d}"
        try:
            send_login_code_email(user, code, request)
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
            return redirect(role_safe_next_url(user, pending.get("next_url") or default_login_redirect()))

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


class CorporatePasswordResetView(PasswordResetView):
    form_class = CorporatePasswordResetForm
    template_name = "inventory/password_reset.html"
    email_template_name = "inventory/emails/password_reset_email.txt"
    html_email_template_name = "inventory/emails/password_reset_email.html"
    subject_template_name = "inventory/emails/password_reset_subject.txt"
    success_url = reverse_lazy("password-reset-done")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site_settings = SiteSettings.load()
        context["site_name"] = site_settings.site_name
        context["site_subtitle"] = site_settings.subtitle
        return context


class CorporatePasswordResetDoneView(PasswordResetDoneView):
    template_name = "inventory/password_reset_done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site_settings = SiteSettings.load()
        context["site_name"] = site_settings.site_name
        context["site_subtitle"] = site_settings.subtitle
        return context


class CorporatePasswordResetConfirmView(PasswordResetConfirmView):
    form_class = CorporateSetPasswordForm
    template_name = "inventory/password_reset_confirm.html"
    success_url = reverse_lazy("password-reset-complete")

    def form_valid(self, form):
        response = super().form_valid(form)
        profile, _ = UserProfile.objects.get_or_create(user=form.user)
        if profile.must_change_password:
            profile.must_change_password = False
            profile.save(update_fields=["must_change_password", "updated_at"])
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site_settings = SiteSettings.load()
        context["site_name"] = site_settings.site_name
        context["site_subtitle"] = site_settings.subtitle
        return context


class CorporatePasswordResetCompleteView(PasswordResetCompleteView):
    template_name = "inventory/password_reset_complete.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site_settings = SiteSettings.load()
        context["site_name"] = site_settings.site_name
        context["site_subtitle"] = site_settings.subtitle
        return context
