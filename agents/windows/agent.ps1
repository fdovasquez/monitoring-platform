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
$Computer = Get-CimInstance Win32_ComputerSystem
$Bios = Get-CimInstance Win32_BIOS
$Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$Disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $Percent = if ($_.Size -gt 0) { [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2) } else { 0 }
    @{
        device = $_.DeviceID
        mountpoint = $_.DeviceID
        fstype = $_.FileSystem
        total_gb = [math]::Round($_.Size / 1GB, 2)
        percent = [double]$Percent
    }
}
$NetworkConfigs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
$Adapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
$Interfaces = @($NetworkConfigs | ForEach-Object {
    $config = $_
    $adapter = $Adapters | Where-Object { $_.MACAddress -eq $config.MACAddress } | Select-Object -First 1
    @{
        name = $config.Description
        is_up = $true
        speed_mbps = if ($adapter -and $adapter.Speed) { [math]::Round($adapter.Speed / 1000000, 0) } else { $null }
        ips = @($config.IPAddress | Where-Object { $_ -and $_ -notlike "fe80*" })
        mac = $config.MACAddress
    }
})
$PrimaryIp = ($NetworkConfigs | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -match "^\d+\.\d+\.\d+\.\d+$" -and $_ -ne "127.0.0.1" } | Select-Object -First 1)
$Gateway = ($NetworkConfigs | ForEach-Object { $_.DefaultIPGateway } | Where-Object { $_ } | Select-Object -First 1)
$DnsServers = @($NetworkConfigs | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ } | Select-Object -Unique)
$MacAddresses = @($NetworkConfigs | ForEach-Object { $_.MACAddress } | Where-Object { $_ } | Select-Object -Unique)
$Uptime = [int]((Get-Date) - $Os.LastBootUpTime).TotalSeconds
$MemoryPercent = [math]::Round((($Os.TotalVisibleMemorySize - $Os.FreePhysicalMemory) / $Os.TotalVisibleMemorySize) * 100, 2)
$DiskPercent = [math]::Round((($Disk.Size - $Disk.FreeSpace) / $Disk.Size) * 100, 2)
$Services = @(Get-CimInstance Win32_Service | Select-Object -First 120 | ForEach-Object {
    @{
        name = $_.Name
        display_name = $_.DisplayName
        state = $_.State
        sub_state = $_.Status
        start_type = $_.StartMode
    }
})
$Processes = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 40 | ForEach-Object {
    $ProcessPath = ""
    try {
        $ProcessPath = $_.Path
    } catch {
        $ProcessPath = ""
    }
    @{
        pid = $_.Id
        name = $_.ProcessName
        user = ""
        cpu_percent = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
        memory_percent = if ($Computer.TotalPhysicalMemory -gt 0) { [math]::Round(($_.WorkingSet64 / $Computer.TotalPhysicalMemory) * 100, 2) } else { 0 }
        path = $ProcessPath
    }
})
$TcpPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First 160 | ForEach-Object {
    $ProcessName = ""
    if ($_.OwningProcess) {
        try {
            $ProcessName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
        } catch {
            $ProcessName = ""
        }
    }
    @{
        protocol = "TCP"
        local_address = $_.LocalAddress
        local_port = $_.LocalPort
        status = $_.State
        pid = $_.OwningProcess
        process = $ProcessName
    }
})
$UdpPorts = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 80 | ForEach-Object {
    $ProcessName = ""
    if ($_.OwningProcess) {
        try {
            $ProcessName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
        } catch {
            $ProcessName = ""
        }
    }
    @{
        protocol = "UDP"
        local_address = $_.LocalAddress
        local_port = $_.LocalPort
        status = "LISTEN"
        pid = $_.OwningProcess
        process = $ProcessName
    }
})

$Payload = @{
    hostname = $Hostname
    agent_version = "1.0.0"
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    metrics = @{
        cpu_percent = [double]$Cpu
        memory_percent = [double]$MemoryPercent
        disk_c_percent = [double]$DiskPercent
        disk_count = @($Disks).Count
        disks = @($Disks)
        uptime_seconds = $Uptime
    }
    inventory = @{
        hostname = $Hostname
        fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)
        os_name = $Os.Caption
        os_version = $Os.Version
        kernel = $Os.BuildNumber
        architecture = $Os.OSArchitecture
        serial_number = $Bios.SerialNumber
        model = $Computer.Model
        manufacturer = $Computer.Manufacturer
        domain = $Computer.Domain
        logged_user = $Computer.UserName
        primary_ip = $PrimaryIp
        gateway = $Gateway
        dns_servers = @($DnsServers)
        mac_addresses = @($MacAddresses)
        interfaces = @($Interfaces)
        timezone = (Get-TimeZone).Id
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    services = @($Services)
    processes = @($Processes)
    ports = @($TcpPorts + $UdpPorts)
} | ConvertTo-Json -Depth 8

$Headers = @{
    Authorization = "Bearer $($env:MONITORING_AGENT_TOKEN)"
}

Invoke-RestMethod -Method Post -Uri $env:MONITORING_API_URL -Headers $Headers -Body $Payload -ContentType "application/json"
