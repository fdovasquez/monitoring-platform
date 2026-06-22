from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from inventory.models import TlsCertificate


class Command(BaseCommand):
    help = "Exports the stored TLS certificate and private key for Nginx."

    def add_arguments(self, parser):
        parser.add_argument("--directory", default="/etc/monitoring-platform/tls")

    def handle(self, *args, **options):
        certificate = TlsCertificate.load()
        if not certificate.is_configured:
            raise CommandError("No hay un certificado HTTPS cargado en Configuracion.")

        directory = Path(options["directory"])
        try:
            directory.mkdir(parents=True, exist_ok=True)
            certificate_path = directory / "certificate.pem"
            key_path = directory / "private.key"
            certificate_path.write_text(certificate.certificate_pem, encoding="utf-8")
            key_path.write_text(certificate.get_private_key(), encoding="utf-8")
            certificate_path.chmod(0o644)
            key_path.chmod(0o600)
        except OSError as exc:
            raise CommandError(f"No se pudieron exportar los archivos: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Certificado exportado en {directory}"))
