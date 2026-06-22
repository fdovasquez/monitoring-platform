Exit code: 0
Wall time: 0.7 seconds
Output:
# Agente Linux independiente

El instalador de la plataforma descarga un binario estatico para Linux x86_64
desde el propio servidor de monitoreo. Los equipos Oracle Linux, RHEL, Rocky,
CentOS, Ubuntu o Debian no requieren Python, pip, Git, dnf ni acceso a Internet.

## Construccion unica en el monitor

Ejecuta una vez en el servidor de monitoreo:

```bash
sudo apt install -y golang-go
cd /opt/monitoring-platform
./agents/linux/build_standalone.sh
file agents/dist/linux/monitoring-agent-linux-x86_64
```

El archivo generado queda disponible para los instaladores internos en:

```text
/app/agents/download/linux/monitoring-agent-linux-x86_64
```

## Requisito minimo del cliente

El cliente solo necesita `curl` o `wget` para bajar el binario desde el
monitor interno y `systemd` para ejecutarlo como servicio.

