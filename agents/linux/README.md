# Agente Linux

Agente propio de ejemplo para enviar metricas basicas a la API de la plataforma.

## Instalacion rapida

```bash
sudo mkdir -p /opt/monitoring-agent
sudo cp agent.py /opt/monitoring-agent/agent.py
sudo python3 -m venv /opt/monitoring-agent/.venv
sudo /opt/monitoring-agent/.venv/bin/pip install psutil requests
sudo cp agent.env.example /etc/monitoring-agent.env
sudo vim /etc/monitoring-agent.env
sudo chmod 600 /etc/monitoring-agent.env
sudo cp monitoring-agent.service /etc/systemd/system/monitoring-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now monitoring-agent
```
