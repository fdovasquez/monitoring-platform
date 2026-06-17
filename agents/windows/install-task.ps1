$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\MonitoringAgent\agent.ps1"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "MonitoringAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Force
Start-ScheduledTask -TaskName "MonitoringAgent"
