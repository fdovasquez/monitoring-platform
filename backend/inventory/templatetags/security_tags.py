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


def security_check(label, passed, detail, weight):
    return {
        "label": label,
        "passed": bool(passed),
        "detail": detail or "No evaluado",
        "weight": weight,
    }


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
            security_check("Disk encryption", False, "Agente pendiente de actualizar", 5),
            security_check("Firewall", False, "Agente pendiente de actualizar", 25),
            security_check("OS security", False, "Agente pendiente de actualizar", 25),
            security_check("Patch compliance", False, "Agente pendiente de actualizar", 25),
            security_check("OS version", bool(inventory.get("os_version")), inventory.get("os_version") or "No informado", 20),
        ]
        return security_summary(checks)

    checks = [
        security_check(
            "Disk encryption",
            disk_encryption.get("enabled"),
            disk_encryption.get("detail") or "Primary disk not encrypted",
            5,
        ),
        security_check(
            "Firewall",
            firewall.get("enabled"),
            firewall.get("detail") or "Firewall no activo",
            25,
        ),
        security_check(
            "OS security",
            os_security.get("enabled"),
            os_security.get("detail") or "Control de seguridad no activo",
            25,
        ),
        security_check(
            "Patch compliance",
            patch_compliance.get("up_to_date"),
            patch_compliance.get("detail") or "No evaluado",
            25,
        ),
        security_check(
            "OS version",
            os_version.get("supported", True),
            os_version.get("detail") or inventory.get("os_version") or "Version no informada",
            20,
        ),
    ]
    return security_summary(checks)


@register.filter
def security_score(sample):
    return security_assessment(sample)["score"]
