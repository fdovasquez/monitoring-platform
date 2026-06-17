# Agente Windows

Agente propio de ejemplo en PowerShell. Esta pensado para ejecutarse con el Programador de tareas cada 1 minuto.

## Instalacion rapida

Ejecutar PowerShell como administrador:

```powershell
New-Item -ItemType Directory -Force "C:\ProgramData\MonitoringAgent"
Copy-Item ".\agent.ps1" "C:\ProgramData\MonitoringAgent\agent.ps1"
Copy-Item ".\agent.env.example.ps1" "C:\ProgramData\MonitoringAgent\agent.env.ps1"
notepad "C:\ProgramData\MonitoringAgent\agent.env.ps1"
.\install-task.ps1
```
