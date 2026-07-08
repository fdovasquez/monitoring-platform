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


def security_check(label, description, passed, detail, weight, pending=False, latest_update=""):
    return {
        "label": label,
        "description": description,
        "passed": bool(passed),
        "detail": detail or "No evaluado",
        "weight": weight,
        "pending": pending,
        "latest_update": latest_update,
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


def split_patch_detail(value):
    marker = ". Ultimo paquete instalado: "
    detail = str(value or "No evaluado")
    if marker not in detail:
        return detail, ""
    status, package = detail.split(marker, 1)
    return status.strip(), package.strip()


def service_is_active(service):
    state = str(service.get("state") or service.get("status") or "").lower()
    sub_state = str(service.get("sub_state") or "").lower()
    return state in {"active", "running"} or sub_state == "running"


def identity_audit_from_payload(sample, security):
    identity_audit = security.get("identity_audit", {})
    if isinstance(identity_audit, dict) and identity_audit:
        return {
            "passed": bool(identity_audit.get("enabled")),
            "detail": identity_audit.get("detail") or "Auditoria no evaluada",
            "pending": bool(identity_audit.get("pending", False)),
        }

    payload = getattr(sample, "payload", {}) if sample else {}
    services = payload.get("services", []) if isinstance(payload, dict) else []
    if not isinstance(services, list):
        services = []

    audit_candidates = {"auditd.service", "systemd-journald.service", "eventlog", "windows event log"}
    for service in services:
        if not isinstance(service, dict):
            continue
        name = str(service.get("name") or service.get("display_name") or "").lower()
        description = str(service.get("description") or service.get("display_name") or "").lower()
        if any(candidate in name or candidate in description for candidate in audit_candidates):
            if service_is_active(service):
                return {"passed": True, "detail": f"Auditoria activa ({service.get('name') or service.get('display_name')})", "pending": False}
            return {"passed": False, "detail": f"Servicio de auditoria no activo ({service.get('name') or service.get('display_name')})", "pending": False}

    return {
        "passed": False,
        "detail": "No se recibio evidencia de auditoria o trazabilidad desde el agente",
        "pending": True,
    }


def inventory_visibility_from_payload(sample, inventory):
    required_fields = [
        ("hostname", "Hostname"),
        ("fqdn", "FQDN"),
        ("primary_ip", "IP principal"),
        ("os_name", "Sistema operativo"),
        ("os_version", "Version del sistema"),
        ("architecture", "Arquitectura"),
        ("manufacturer", "Fabricante"),
        ("model", "Modelo"),
        ("serial_number", "Numero de serie"),
    ]
    present = []
    missing = []
    for key, label in required_fields:
        value = inventory.get(key)
        if value not in [None, "", [], {}]:
            present.append(label)
        else:
            missing.append(label)

    payload = getattr(sample, "payload", {}) if sample else {}
    metrics = payload.get("metrics", {}) if isinstance(payload, dict) else {}
    interfaces = inventory.get("interfaces")
    if interfaces:
        present.append("Interfaces de red")
    else:
        missing.append("Interfaces de red")
    if getattr(sample, "agent_version", ""):
        present.append("Version del agente")
    else:
        missing.append("Version del agente")
    if metrics.get("uptime_seconds") is not None:
        present.append("Uptime")
    else:
        missing.append("Uptime")

    total = len(present) + len(missing)
    coverage = round(len(present) / total * 100) if total else 0
    if coverage >= 80:
        return {
            "passed": True,
            "detail": f"Inventario suficiente ({len(present)}/{total} datos clave, {coverage}%)",
            "pending": False,
        }
    if coverage >= 50:
        return {
            "passed": False,
            "detail": f"Inventario incompleto ({len(present)}/{total} datos clave). Faltan: {', '.join(missing[:3])}",
            "pending": True,
        }
    return {
        "passed": False,
        "detail": f"Inventario insuficiente ({len(present)}/{total} datos clave)",
        "pending": False,
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
        "passed_count": sum(1 for check in checks if check["passed"]),
        "pending_count": sum(1 for check in checks if check["pending"]),
        "failed_count": sum(1 for check in checks if not check["passed"] and not check["pending"]),
        "gauge_rotation": round(-75 + (score * 1.5), 2),
    }


@register.filter
def security_assessment(sample):
    metrics, inventory = metric_payload(sample)
    security = metrics.get("security", {}) if isinstance(metrics.get("security"), dict) else {}

    firewall = security.get("firewall", {}) if isinstance(security.get("firewall"), dict) else {}
    os_security = security.get("os_security", {}) if isinstance(security.get("os_security"), dict) else {}
    patch_compliance = security.get("patch_compliance", {}) if isinstance(security.get("patch_compliance"), dict) else {}
    os_version = security.get("os_version", {}) if isinstance(security.get("os_version"), dict) else {}

    if not security:
        inventory_visibility = inventory_visibility_from_payload(sample, inventory)
        checks = [
            security_check(
                "Actualizaciones y vulnerabilidades",
                "Verifica parches pendientes, actualizaciones criticas y exposicion por software vulnerable.",
                False,
                "Pendiente de reporte del agente",
                25,
                pending=True,
            ),
            security_check(
                "Firewall y exposicion de red",
                "Valida firewall activo y reduce la exposicion innecesaria de servicios de red.",
                False,
                "Pendiente de reporte del agente",
                20,
                pending=True,
            ),
            security_check(
                "Endurecimiento del sistema operativo",
                "Revisa controles nativos de seguridad y compatibilidad de la version del sistema.",
                bool(inventory.get("os_version")),
                display_os_version(inventory.get("os_version")),
                20,
            ),
            security_check(
                "Inventario y visibilidad del activo",
                "Verifica que el servidor reporte informacion tecnica suficiente para identificacion y gestion.",
                inventory_visibility["passed"],
                inventory_visibility["detail"],
                15,
                pending=inventory_visibility["pending"],
            ),
            security_check(
                "Identidad, auditoria y trazabilidad",
                "Comprueba evidencia de auditoria, trazabilidad de eventos y controles de acceso.",
                False,
                "Pendiente de reporte del agente",
                20,
                pending=True,
            ),
        ]
        return security_summary(checks)

    patch_detail, latest_update = split_patch_detail(
        patch_compliance.get("detail") or "No evaluado"
    )
    identity_audit = identity_audit_from_payload(sample, security)
    os_security_passed = bool(os_security.get("enabled")) and bool(os_version.get("supported", True))
    os_security_detail = os_security.get("detail") or "Control de seguridad no activo"
    os_version_detail = display_os_version(os_version.get("detail") or inventory.get("os_version"))
    if os_version_detail:
        os_security_detail = f"{os_security_detail}. Version: {os_version_detail}"
    inventory_visibility = inventory_visibility_from_payload(sample, inventory)

    checks = [
        security_check(
            "Actualizaciones y vulnerabilidades",
            "Verifica parches pendientes, actualizaciones criticas y exposicion por software vulnerable.",
            patch_compliance.get("up_to_date"),
            patch_detail,
            25,
            pending=patch_compliance.get("pending", False),
            latest_update=latest_update,
        ),
        security_check(
            "Firewall y exposicion de red",
            "Valida firewall activo y reduce la exposicion innecesaria de servicios de red.",
            firewall.get("enabled"),
            firewall.get("detail") or "Firewall no activo",
            20,
            pending=firewall.get("pending", False),
        ),
        security_check(
            "Endurecimiento del sistema operativo",
            "Revisa controles nativos de seguridad y compatibilidad de la version del sistema.",
            os_security_passed,
            os_security_detail,
            20,
            pending=os_security.get("pending", False),
        ),
        security_check(
            "Inventario y visibilidad del activo",
            "Verifica que el servidor reporte informacion tecnica suficiente para identificacion y gestion.",
            inventory_visibility["passed"],
            inventory_visibility["detail"],
            15,
            pending=inventory_visibility["pending"],
        ),
        security_check(
            "Identidad, auditoria y trazabilidad",
            "Comprueba evidencia de auditoria, trazabilidad de eventos y controles de acceso.",
            identity_audit["passed"],
            identity_audit["detail"],
            20,
            pending=identity_audit["pending"],
        ),
    ]
    return security_summary(checks)


@register.filter
def security_score(sample):
    return security_assessment(sample)["score"]


@register.filter
def security_tone(sample):
    return security_assessment(sample)["tone"]

