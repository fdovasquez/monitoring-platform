import logging
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from metrics.central_reporter import CentralReporterConfigurationError, run_report_cycle


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Envia reportes del satelite local hacia el servidor central publico."

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop",
            action="store_true",
            help="Ejecuta el reporte permanentemente usando REPORT_INTERVAL_SECONDS.",
        )

    def handle(self, *args, **options):
        if options["loop"]:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Reporte central en modo continuo cada {settings.REPORT_INTERVAL_SECONDS} segundos."
                )
            )
            while True:
                self.run_once()
                time.sleep(settings.REPORT_INTERVAL_SECONDS)
        else:
            self.run_once()

    def run_once(self):
        try:
            result = run_report_cycle()
        except CentralReporterConfigurationError as exc:
            raise CommandError(str(exc)) from exc
        except Exception as exc:
            logger.exception("Error inesperado al ejecutar reporte central.")
            raise CommandError(f"Error inesperado al ejecutar reporte central: {exc}") from exc

        if not result["enabled"]:
            self.stdout.write(self.style.WARNING("Reporte central desactivado."))
            return

        if result.get("queued"):
            self.stdout.write(
                self.style.WARNING(
                    "Reporte central encolado para reintento. "
                    f"Pendientes reenviados: {result['pending_sent']}. Error: {result.get('error', '-')}"
                )
            )
            return

        self.stdout.write(
            self.style.SUCCESS(
                "Reporte central enviado correctamente. "
                f"Pendientes reenviados: {result['pending_sent']}."
            )
        )
