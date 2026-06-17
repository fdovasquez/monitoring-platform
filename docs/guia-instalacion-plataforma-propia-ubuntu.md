# Guia manual de instalacion de una plataforma propia de monitoreo en Ubuntu

Esta guia instala una plataforma propia de monitoreo en Ubuntu usando Django, PostgreSQL, Redis, Celery, Gunicorn y Nginx. La aplicacion queda preparada para administrar usuarios, registrar servidores y recibir metricas desde agentes propios para Linux y Windows.

## 1. Arquitectura

```text
Servidores Linux/Windows -> Agentes propios -> API HTTPS -> PostgreSQL
                                             -> Aplicacion web -> Usuarios/Dashboards
```

Componentes del repositorio:

- `backend/`: aplicacion web y API.
- `agents/linux/`: agente Linux en Python.
- `agents/windows/`: agente Windows en PowerShell.
- `deploy/`: plantillas de systemd, Nginx y variables.
- `docs/`: documentacion.

## 2. Requisitos

Servidor recomendado:

- Ubuntu Server 24.04 LTS
- 2 vCPU minimo, 4 vCPU recomendado
- 4 GB RAM minimo, 8 GB recomendado
- 40 GB disco minimo
- IP fija
- Usuario con sudo

Variables a definir:

```text
APP_DIR=/opt/monitoring-platform
APP_USER=monitoring
APP_DOMAIN=monitor.local
DB_NAME=monitoring
DB_USER=monitoring
DB_PASSWORD=CAMBIAR_ESTA_CLAVE
DJANGO_SECRET_KEY=CAMBIAR_ESTE_SECRETO
```

## 3. Preparar Ubuntu

```bash
sudo apt update
sudo apt -y upgrade
sudo apt -y install git curl wget vim unzip ca-certificates gnupg lsb-release ufw
sudo hostnamectl set-hostname monitor
sudo timedatectl set-timezone America/Santiago
```

Firewall basico:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from RED_ADMIN to any port 22 proto tcp
sudo ufw allow from RED_ADMIN to any port 80 proto tcp
sudo ufw allow from RED_ADMIN to any port 443 proto tcp
sudo ufw allow from RED_MONITOREO to any port 443 proto tcp
sudo ufw enable
sudo ufw status verbose
```

## 4. Instalar dependencias

```bash
sudo apt -y install python3 python3-venv python3-pip python3-dev build-essential
sudo apt -y install postgresql postgresql-contrib libpq-dev
sudo apt -y install redis-server nginx
sudo systemctl enable --now postgresql redis-server nginx
```

## 5. Crear usuario y base de datos

```bash
sudo adduser --system --group --home /opt/monitoring-platform monitoring
sudo mkdir -p /opt/monitoring-platform
sudo chown -R monitoring:monitoring /opt/monitoring-platform
sudo -u postgres psql
```

En PostgreSQL:

```sql
CREATE USER monitoring WITH PASSWORD 'CAMBIAR_ESTA_CLAVE';
CREATE DATABASE monitoring OWNER monitoring;
ALTER ROLE monitoring SET client_encoding TO 'utf8';
ALTER ROLE monitoring SET default_transaction_isolation TO 'read committed';
ALTER ROLE monitoring SET timezone TO 'UTC';
\q
```

## 6. Clonar desde GitHub

Repositorio remoto:

```text
https://github.com/fdovasquez/monitoring-platform
```

Si ya existe `/opt/monitoring-platform` pero esta vacio por un clone previo, elimina y clona de nuevo:

```bash
sudo rm -rf /opt/monitoring-platform
sudo -u monitoring git clone https://github.com/fdovasquez/monitoring-platform.git /opt/monitoring-platform
```

Valida:

```bash
cd /opt/monitoring-platform
ls
```

## 7. Crear entorno Python

```bash
cd /opt/monitoring-platform/backend
sudo -u monitoring python3 -m venv .venv
sudo -u monitoring .venv/bin/pip install --upgrade pip wheel setuptools
sudo -u monitoring .venv/bin/pip install -r requirements.txt
```

## 8. Variables de entorno

Crea `/etc/monitoring-platform.env`:

```ini
DJANGO_SETTINGS_MODULE=config.settings
DJANGO_SECRET_KEY=CAMBIAR_ESTE_SECRETO
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=monitor.local,IP_DEL_SERVIDOR
DATABASE_URL=postgresql://monitoring:CAMBIAR_ESTA_CLAVE@localhost:5432/monitoring
REDIS_URL=redis://localhost:6379/0
TIME_ZONE=America/Santiago
AGENT_SHARED_SECRET=CAMBIAR_SECRETO_DE_AGENTES
```

Protege el archivo:

```bash
sudo chown root:monitoring /etc/monitoring-platform.env
sudo chmod 640 /etc/monitoring-platform.env
```

## 9. Preparar Django

Cuando exista el proyecto Django dentro de `backend/`, ejecuta:

```bash
cd /opt/monitoring-platform/backend
sudo -u monitoring bash -c 'set -a; source /etc/monitoring-platform.env; set +a; .venv/bin/python manage.py migrate'
sudo -u monitoring bash -c 'set -a; source /etc/monitoring-platform.env; set +a; .venv/bin/python manage.py collectstatic --noinput'
sudo -u monitoring bash -c 'set -a; source /etc/monitoring-platform.env; set +a; .venv/bin/python manage.py createsuperuser'
```

## 10. Servicios systemd

Copia plantillas:

```bash
sudo cp /opt/monitoring-platform/deploy/gunicorn.service /etc/systemd/system/monitoring-gunicorn.service
sudo cp /opt/monitoring-platform/deploy/celery-worker.service /etc/systemd/system/monitoring-celery-worker.service
sudo cp /opt/monitoring-platform/deploy/celery-beat.service /etc/systemd/system/monitoring-celery-beat.service
sudo systemctl daemon-reload
sudo systemctl enable --now monitoring-gunicorn monitoring-celery-worker monitoring-celery-beat
```

Valida:

```bash
sudo systemctl status monitoring-gunicorn --no-pager
sudo systemctl status monitoring-celery-worker --no-pager
sudo systemctl status monitoring-celery-beat --no-pager
```

## 11. Nginx

```bash
sudo cp /opt/monitoring-platform/deploy/nginx.conf /etc/nginx/sites-available/monitoring-platform
sudo ln -s /etc/nginx/sites-available/monitoring-platform /etc/nginx/sites-enabled/monitoring-platform
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

Acceso inicial:

```text
http://IP_DEL_SERVIDOR/admin/
```

## 12. Administracion de usuarios

Desde Django Admin crea:

- Grupo `Administradores` con acceso total.
- Grupo `Operadores` para operar servidores, metricas y alertas.
- Grupo `Lectores` solo lectura.

Buenas practicas:

- No operar con el superusuario diariamente.
- Usar usuarios nominales.
- Registrar auditoria para cambios de usuarios, servidores, tokens y reglas.
- Usar token unico por servidor monitoreado.

## 13. Agente Linux

Instalacion en servidor Linux monitoreado:

```bash
sudo mkdir -p /opt/monitoring-agent
sudo cp agents/linux/agent.py /opt/monitoring-agent/agent.py
sudo python3 -m venv /opt/monitoring-agent/.venv
sudo /opt/monitoring-agent/.venv/bin/pip install psutil requests
sudo cp agents/linux/agent.env.example /etc/monitoring-agent.env
sudo vim /etc/monitoring-agent.env
sudo chmod 600 /etc/monitoring-agent.env
sudo cp agents/linux/monitoring-agent.service /etc/systemd/system/monitoring-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now monitoring-agent
```

Edita `/etc/monitoring-agent.env`:

```ini
MONITORING_API_URL=https://IP_DEL_SERVIDOR/api/v1/metrics/ingest/
MONITORING_AGENT_TOKEN=TOKEN_DEL_SERVIDOR
MONITORING_HOSTNAME=srv-linux-01
MONITORING_INTERVAL=60
MONITORING_VERIFY_TLS=true
```

## 14. Agente Windows

Ejecuta PowerShell como administrador:

```powershell
New-Item -ItemType Directory -Force "C:\ProgramData\MonitoringAgent"
Copy-Item ".\agents\windows\agent.ps1" "C:\ProgramData\MonitoringAgent\agent.ps1"
Copy-Item ".\agents\windows\agent.env.example.ps1" "C:\ProgramData\MonitoringAgent\agent.env.ps1"
notepad "C:\ProgramData\MonitoringAgent\agent.env.ps1"
.\agents\windows\install-task.ps1
```

Configura token y URL en `C:\ProgramData\MonitoringAgent\agent.env.ps1`.

## 15. Backups

```bash
sudo mkdir -p /opt/backups/monitoring-platform
sudo chmod 700 /opt/backups/monitoring-platform
sudo -u postgres pg_dump monitoring | gzip | sudo tee /opt/backups/monitoring-platform/monitoring-$(date +%F).sql.gz >/dev/null
sudo tar -czf /opt/backups/monitoring-platform/config-$(date +%F).tar.gz /etc/monitoring-platform.env /etc/nginx/sites-available/monitoring-platform /etc/systemd/system/monitoring-*.service
```

## 16. Actualizar desde Git

```bash
cd /opt/monitoring-platform
sudo -u monitoring git pull
cd backend
sudo -u monitoring .venv/bin/pip install -r requirements.txt
sudo -u monitoring bash -c 'set -a; source /etc/monitoring-platform.env; set +a; .venv/bin/python manage.py migrate'
sudo -u monitoring bash -c 'set -a; source /etc/monitoring-platform.env; set +a; .venv/bin/python manage.py collectstatic --noinput'
sudo systemctl restart monitoring-gunicorn monitoring-celery-worker monitoring-celery-beat
```

## 17. Puertos

| Puerto | Origen | Destino | Uso |
| --- | --- | --- | --- |
| 22/tcp | Red admin | Ubuntu | SSH |
| 80/tcp | Red admin | Ubuntu | HTTP inicial |
| 443/tcp | Red admin y agentes | Ubuntu | Web/API HTTPS |
| 5432/tcp | Localhost | PostgreSQL | Base de datos |
| 6379/tcp | Localhost | Redis | Cola de tareas |
| 8000/tcp | Localhost | Gunicorn | App interna |

No expongas PostgreSQL, Redis ni Gunicorn directamente a la red.
