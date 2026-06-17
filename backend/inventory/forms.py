from django import forms
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError

from .models import MachineCredential, UserProfile


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


class ProfileForm(forms.Form):
    first_name = forms.CharField(label="Nombre", max_length=150)
    last_name = forms.CharField(label="Apellido", max_length=150)
    email = forms.EmailField(label="Correo electrónico")
    phone = forms.CharField(label="Teléfono", max_length=40, required=False)
    position = forms.CharField(label="Cargo", max_length=120, required=False)
    photo = forms.ImageField(label="Foto de perfil", required=False)
    delete_photo = forms.BooleanField(label="Eliminar foto actual", required=False)

    allowed_content_types = {"image/jpeg", "image/png", "image/webp"}
    max_photo_size = 2 * 1024 * 1024

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        initial = kwargs.pop("initial", {})
        initial.update(
            {
                "first_name": self.user.first_name,
                "last_name": self.user.last_name,
                "email": self.user.email,
                "phone": self.profile.phone,
                "position": self.profile.position,
            }
        )
        super().__init__(*args, initial=initial, **kwargs)

    def clean_photo(self):
        photo = self.cleaned_data.get("photo")
        if not photo:
            return photo
        if photo.size > self.max_photo_size:
            raise forms.ValidationError("La foto no puede superar 2 MB.")
        if getattr(photo, "content_type", "") not in self.allowed_content_types:
            raise forms.ValidationError("Solo se permiten imágenes JPG, PNG o WEBP.")
        return photo

    def save(self):
        self.user.first_name = self.cleaned_data["first_name"].strip()
        self.user.last_name = self.cleaned_data["last_name"].strip()
        self.user.email = self.cleaned_data["email"].strip()
        self.user.save(update_fields=["first_name", "last_name", "email"])

        self.profile.phone = self.cleaned_data.get("phone", "").strip()
        self.profile.position = self.cleaned_data.get("position", "").strip()
        if self.cleaned_data.get("delete_photo") and self.profile.photo:
            self.profile.photo.delete(save=False)
            self.profile.photo = None
        if self.cleaned_data.get("photo"):
            if self.profile.photo:
                self.profile.photo.delete(save=False)
            self.profile.photo = self.cleaned_data["photo"]
        self.profile.save()
        return self.user


class AccountPasswordChangeForm(forms.Form):
    current_password = forms.CharField(label="Contraseña actual", widget=forms.PasswordInput)
    new_password = forms.CharField(label="Nueva contraseña", widget=forms.PasswordInput)
    confirm_password = forms.CharField(label="Confirmar nueva contraseña", widget=forms.PasswordInput)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get("current_password", "")
        if not self.user.check_password(current_password):
            raise forms.ValidationError("La contraseña actual no es correcta.")
        return current_password

    def clean(self):
        cleaned_data = super().clean()
        current_password = cleaned_data.get("current_password", "")
        new_password = cleaned_data.get("new_password", "")
        confirm_password = cleaned_data.get("confirm_password", "")

        if not new_password or not confirm_password:
            return cleaned_data
        if new_password != confirm_password:
            self.add_error("confirm_password", "La confirmación no coincide con la nueva contraseña.")
        if current_password and current_password == new_password:
            self.add_error("new_password", "La nueva contraseña debe ser distinta a la actual.")
        if not any(character.isupper() for character in new_password):
            self.add_error("new_password", "La nueva contraseña debe incluir al menos una mayúscula.")
        if not any(character.islower() for character in new_password):
            self.add_error("new_password", "La nueva contraseña debe incluir al menos una minúscula.")
        if not any(character.isdigit() for character in new_password):
            self.add_error("new_password", "La nueva contraseña debe incluir al menos un número.")
        if not any(not character.isalnum() for character in new_password):
            self.add_error("new_password", "La nueva contraseña debe incluir al menos un carácter especial.")
        if len(new_password) < 8:
            self.add_error("new_password", "La nueva contraseña debe tener al menos 8 caracteres.")
        try:
            validate_password(new_password, self.user)
        except ValidationError as error:
            self.add_error("new_password", error)
        return cleaned_data

    def save(self):
        self.user.set_password(self.cleaned_data["new_password"])
        self.user.save(update_fields=["password"])
        return self.user


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
