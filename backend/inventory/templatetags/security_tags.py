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


def security_check(label, passed, detail, weight, pending=False):
    return {
        "label": label,
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
                "Controles de seguridad",
                False,
                "El agente aun no reporta controles de seguridad.",
                0,
                pending=True,
            ),
            security_check(
                "Version del sistema",
                bool(inventory.get("os_version")),
                display_os_version(inventory.get("os_version")),
                20,
            ),
        ]
        return security_summary(checks)

    checks = [
        security_check(
            "Cifrado de disco",
            disk_encryption.get("enabled"),
            disk_encryption.get("detail") or "El disco principal no esta cifrado",
            5,
        ),
        security_check(
            "Firewall",
            firewall.get("enabled"),
            firewall.get("detail") or "Firewall no activo",
            25,
        ),
        security_check(
            "Seguridad del sistema",
            os_security.get("enabled"),
            os_security.get("detail") or "Control de seguridad no activo",
            25,
        ),
        security_check(
            "Actualizaciones de seguridad",
            patch_compliance.get("up_to_date"),
            patch_compliance.get("detail") or "No evaluado",
            25,
        ),
        security_check(
            "Version del sistema",
            os_version.get("supported", True),
            display_os_version(os_version.get("detail") or inventory.get("os_version")),
            20,
        ),
    ]
    return security_summary(checks)


@register.filter
def security_score(sample):
    return security_assessment(sample)["score"]


@register.filter
def security_tone(sample):
    return security_assessment(sample)["tone"]

