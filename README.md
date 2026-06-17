# Guia manual para instalar una plataforma propia de monitoreo en Ubuntu

Este repositorio contiene una guia paso a paso para instalar en Ubuntu una plataforma propia de monitoreo, pensada para ser desarrollada y versionada en Git.

La instalacion propuesta permite:

- Alojar una aplicacion web propia.
- Administrar usuarios, grupos, roles y permisos.
- Exponer una API para recibir metricas.
- Monitorear servidores Linux con un agente propio.
- Monitorear servidores Windows con un agente propio en PowerShell.
- Mantener codigo y documentacion en Git para instalarlo en un servidor local.

## Guia principal

Abrir:

- [docs/guia-instalacion-plataforma-propia-ubuntu.md](docs/guia-instalacion-plataforma-propia-ubuntu.md)

## Stack recomendado

- Ubuntu Server 24.04 LTS
- Python 3
- Django
- Django REST Framework
- PostgreSQL
- Redis
- Celery
- Gunicorn
- Nginx

## Componentes esperados

- `backend/`: aplicacion web y API.
- `agents/linux/`: agente propio para servidores Linux.
- `agents/windows/`: agente propio para servidores Windows.
- `docs/`: documentacion de instalacion y operacion.
- `deploy/`: archivos de ejemplo para systemd, Nginx y variables de entorno.
