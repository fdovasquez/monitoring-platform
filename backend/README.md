# Backend

Aqui debe vivir la aplicacion web propia.

Stack recomendado:

- Django
- Django REST Framework
- PostgreSQL
- Redis
- Celery
- Gunicorn

Modulos sugeridos:

- `accounts`: usuarios, grupos, roles y auditoria.
- `inventory`: servidores, ambientes, responsables y tokens de agente.
- `metrics`: ingesta e historial de metricas.
- `alerts`: reglas, eventos y notificaciones.

Endpoints minimos:

- `POST /api/v1/metrics/ingest/`
- `GET /api/v1/servers/`
- `GET /api/v1/servers/{id}/metrics/`
- `GET /admin/`
