$ConfigPath = "C:\ProgramData\MonitoringAgent\agent.env.ps1"
if (Test-Path $ConfigPath) {
    . $ConfigPath
}

if (-not $env:MONITORING_API_URL -or -not $env:MONITORING_AGENT_TOKEN) {
    throw "MONITORING_API_URL and MONITORING_AGENT_TOKEN are required."
}

if ($env:MONITORING_SKIP_TLS_VERIFY -eq "true") {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

$Hostname = if ($env:MONITORING_HOSTNAME) { $env:MONITORING_HOSTNAME } else { $env:COMPUTERNAME }
$Cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$Os = Get-CimInstance Win32_OperatingSystem
$Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$Uptime = [int]((Get-Date) - $Os.LastBootUpTime).TotalSeconds
$MemoryPercent = [math]::Round((($Os.TotalVisibleMemorySize - $Os.FreePhysicalMemory) / $Os.TotalVisibleMemorySize) * 100, 2)
$DiskPercent = [math]::Round((($Disk.Size - $Disk.FreeSpace) / $Disk.Size) * 100, 2)

$Payload = @{
    hostname = $Hostname
    agent_version = "1.0.0"
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    metrics = @{
        cpu_percent = [double]$Cpu
        memory_percent = [double]$MemoryPercent
        disk_c_percent = [double]$DiskPercent
        uptime_seconds = $Uptime
    }
    services = @()
} | ConvertTo-Json -Depth 5

$Headers = @{
    Authorization = "Bearer $($env:MONITORING_AGENT_TOKEN)"
}

Invoke-RestMethod -Method Post -Uri $env:MONITORING_API_URL -Headers $Headers -Body $Payload -ContentType "application/json"
