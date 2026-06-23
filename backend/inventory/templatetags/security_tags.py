import re

from django import template


register = template.Library()


def metric_payload(sample):
    if not sample or not isinstance(getattr(sample, "payload", None), dict):
        return {}, {}
    metrics = sample.payload.get("metrics", {})
    inventory = sample.payload.get("inventory", {})
    return (
        metrics if isinstance(metrics, dict) else {},
        inventory if isinstance(inventory, dict) else {},
    )


def security_check(label, description, passed, detail, weight, pending=False):
    return {
        "label": label,
        "description": description,
        "passed": bool(passed),
        "detail": detail or "No evaluado",
        "weight": weight,
        "pending": pending,
    }


def display_os_version(value):
    """Returns a compact OS name instead of the complete os-release contents."""
    if not value:
        return "Version no informada"

    text = str(value).replace("\n", " ").strip()
    pretty_name = re.search(r'(?:^|\s)PRETTY_NAME=["\']?([^"\']+)', text)
    if pretty_name:
        return pretty_name.group(1).strip()

    return text[:120] + ("..." if len(text) > 120 else "")


def security_summary(checks):
    score = sum(check["weight"] for check in checks if check["passed"])
    score = max(0, min(score, 100))
    if score >= 90:
        level = "Bajo riesgo"
        tone = "success"
    elif score >= 70:
        level = "Riesgo medio"
        tone = "warning"
    else:
        level = "Riesgo alto"
        tone = "danger"
    return {
        "score": score,
        "level": level,
        "tone": tone,
        "checks": checks,
        "passed_count": sum(1 for check in checks if check["passed"]),
        "pending_count": sum(1 for check in checks if check["pending"]),
        "failed_count": sum(1 for check in checks if not check["passed"] and not check["pending"]),
        "gauge_rotation": round(-75 + (score * 1.5), 2),
    }


@register.filter
def security_assessment(sample):
    metrics, inventory = metric_payload(sample)
    security = metrics.get("security", {}) if isinstance(metrics.get("security"), dict) else {}

    disk_encryption = security.get("disk_encryption", {}) if isinstance(security.get("disk_encryption"), dict) else {}
    firewall = security.get("firewall", {}) if isinstance(security.get("firewall"), dict) else {}
    os_security = security.get("os_security", {}) if isinstance(security.get("os_security"), dict) else {}
    patch_compliance = security.get("patch_compliance", {}) if isinstance(security.get("patch_compliance"), dict) else {}
    os_version = security.get("os_version", {}) if isinstance(security.get("os_version"), dict) else {}

    if not security:
        checks = [
            security_check(
                "Cifrado de disco",
                "Verifica si la unidad principal utiliza cifrado.",
                False,
                "Pendiente de reporte del agente",
                5,
                pending=True,
            ),
            security_check(
                "Firewall",
                "Valida que el firewall del sistema este habilitado.",
                False,
                "Pendiente de reporte del agente",
                25,
                pending=True,
            ),
            security_check(
                "Seguridad del sistema",
                "Revisa los controles de seguridad nativos del sistema operativo.",
                False,
                "Pendiente de reporte del agente",
                25,
                pending=True,
            ),
            security_check(
                "Actualizaciones de seguridad",
                "Comprueba el estado de actualizaciones y parches de seguridad.",
                False,
                "Pendiente de reporte del agente",
                25,
                pending=True,
            ),
            security_check(
                "Version del sistema",
                "Comprueba que la version informada por el sistema sea compatible.",
                bool(inventory.get("os_version")),
                display_os_version(inventory.get("os_version")),
                20,
            ),
        ]
        return security_summary(checks)

    checks = [
        security_check(
            "Cifrado de disco",
            "Verifica si la unidad principal utiliza cifrado.",
            disk_encryption.get("enabled"),
            disk_encryption.get("detail") or "El disco principal no esta cifrado",
            5,
            pending=disk_encryption.get("pending", False),
        ),
        security_check(
            "Firewall",
            "Valida que el firewall del sistema este habilitado.",
            firewall.get("enabled"),
            firewall.get("detail") or "Firewall no activo",
            25,
            pending=firewall.get("pending", False),
        ),
        security_check(
            "Seguridad del sistema",
            "Revisa los controles de seguridad nativos del sistema operativo.",
            os_security.get("enabled"),
            os_security.get("detail") or "Control de seguridad no activo",
            25,
            pending=os_security.get("pending", False),
        ),
        security_check(
            "Actualizaciones de seguridad",
            "Comprueba el estado de actualizaciones y parches de seguridad.",
            patch_compliance.get("up_to_date"),
            patch_compliance.get("detail") or "No evaluado",
            25,
            pending=patch_compliance.get("pending", False),
        ),
        security_check(
            "Version del sistema",
            "Comprueba que la version informada por el sistema sea compatible.",
            os_version.get("supported", True),
            display_os_version(os_version.get("detail") or inventory.get("os_version")),
            20,
            pending=os_version.get("pending", False),
        ),
    ]
    return security_summary(checks)


@register.filter
def security_score(sample):
    return security_assessment(sample)["score"]


@register.filter
def security_tone(sample):
    return security_assessment(sample)["tone"]

