from django import forms
from django.contrib.auth.models import Group, User

from .models import MachineCredential


ROLE_NAMES = ["Administrador", "Editor", "Visualizador"]


def ensure_base_roles():
    for role_name in ROLE_NAMES:
        Group.objects.get_or_create(name=role_name)


def role_queryset():
    ensure_base_roles()
    return Group.objects.filter(name__in=ROLE_NAMES).order_by("name")


class UserCreateForm(forms.ModelForm):
    password = forms.CharField(label="Clave", widget=forms.PasswordInput)
    role = forms.ModelChoiceField(label="Rol", queryset=Group.objects.none())

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]
        labels = {
            "username": "Usuario",
            "first_name": "Nombre",
            "last_name": "Apellido",
            "email": "Email",
            "is_active": "Activo",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = role_queryset()

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.is_staff = self.cleaned_data["role"].name in {"Administrador", "Editor"}
        user.is_superuser = False
        if commit:
            user.save()
            user.groups.set([self.cleaned_data["role"]])
        return user


class UserEditForm(forms.ModelForm):
    password = forms.CharField(label="Nueva clave", widget=forms.PasswordInput, required=False)
    role = forms.ModelChoiceField(label="Rol", queryset=Group.objects.none())

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]
        labels = {
            "username": "Usuario",
            "first_name": "Nombre",
            "last_name": "Apellido",
            "email": "Email",
            "is_active": "Activo",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = role_queryset()
        current_role = self.instance.groups.filter(name__in=ROLE_NAMES).first()
        if current_role:
            self.fields["role"].initial = current_role

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get("password"):
            user.set_password(self.cleaned_data["password"])
        user.is_staff = self.cleaned_data["role"].name in {"Administrador", "Editor"}
        user.is_superuser = user.is_superuser and self.cleaned_data["role"].name == "Administrador"
        if commit:
            user.save()
            user.groups.set([self.cleaned_data["role"]])
        return user


class MachineCredentialForm(forms.ModelForm):
    secret = forms.CharField(label="Clave", widget=forms.PasswordInput)

    class Meta:
        model = MachineCredential
        fields = ["label", "username", "port", "secret", "is_active"]
        labels = {
            "label": "Nombre de la credencial",
            "username": "Usuario",
            "port": "Puerto SSH",
            "is_active": "Activa",
        }

    def save(self, commit=True):
        credential = super().save(commit=False)
        credential.auth_method = MachineCredential.AUTH_PASSWORD
        credential.set_secret(self.cleaned_data["secret"])
        if commit:
            credential.save()
        return credential
