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
$ProcessCpuSample = @{}
Get-Process | ForEach-Object {
    $ProcessCpuSample[$_.Id] = if ($_.CPU) { $_.CPU } else { 0 }
}
$ProcessCreationMap = @{}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.ProcessId -and $_.CreationDate) {
        $ProcessCreationMap[[int]$_.ProcessId] = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)
    }
}
Start-Sleep -Milliseconds 500
$ProcessorCount = [Environment]::ProcessorCount
$Processes = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 120 | ForEach-Object {
    $ProcessPath = ""
    try {
        $ProcessPath = $_.Path
    } catch {
        $ProcessPath = ""
    }
    $WindowTitle = ""
    try {
        $WindowTitle = $_.MainWindowTitle
    } catch {
        $WindowTitle = ""
    }
    $StartTimeText = ""
    $RunningSeconds = $null
    try {
        $StartTime = $_.StartTime
        if ($StartTime) {
            $StartTimeText = $StartTime.ToString("o")
            $RunningSeconds = [int]((Get-Date) - $StartTime).TotalSeconds
        }
    } catch {
        $StartTimeText = ""
        $RunningSeconds = $null
    }
    if (-not $RunningSeconds -and $ProcessCreationMap.ContainsKey($_.Id)) {
        $StartTime = $ProcessCreationMap[$_.Id]
        $StartTimeText = $StartTime.ToString("o")
        $RunningSeconds = [int]((Get-Date) - $StartTime).TotalSeconds
    }
    $PreviousCpu = if ($ProcessCpuSample.ContainsKey($_.Id)) { $ProcessCpuSample[$_.Id] } else { $_.CPU }
    $CpuDelta = if ($_.CPU -and $PreviousCpu -ne $null) { $_.CPU - $PreviousCpu } else { 0 }
    $CpuPercent = if ($ProcessorCount -gt 0) { [math]::Round(($CpuDelta / 0.5 / $ProcessorCount) * 100, 2) } else { 0 }
    @{
        pid = $_.Id
        name = $_.ProcessName
        user = ""
        cpu_percent = $CpuPercent
        cpu_seconds = if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }
        memory_mb = if ($_.WorkingSet64) { [math]::Round($_.WorkingSet64 / 1MB, 1) } else { 0 }
        memory_percent = if ($Computer.TotalPhysicalMemory -gt 0) { [math]::Round(($_.WorkingSet64 / $Computer.TotalPhysicalMemory) * 100, 2) } else { 0 }
        window_title = $WindowTitle
        category = if ($WindowTitle) { "app" } else { "background" }
        start_time = $StartTimeText
        running_seconds = $RunningSeconds
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
$BitLockerEnabled = $false
$BitLockerDetail = "BitLocker no disponible"
try {
    $BitLockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    $BitLockerEnabled = $BitLockerVolume.ProtectionStatus -eq "On"
    $BitLockerDetail = if ($BitLockerEnabled) { "Disco C: cifrado" } else { "Disco C: no cifrado" }
} catch {
    $BitLockerDetail = "BitLocker no evaluado"
}

$FirewallEnabled = $false
$FirewallDetail = "Firewall no evaluado"
try {
    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $FirewallEnabled = -not (@($FirewallProfiles | Where-Object { $_.Enabled -ne $true }).Count -gt 0)
    $FirewallDetail = if ($FirewallEnabled) { "Activo (Windows Firewall)" } else { "Uno o mas perfiles desactivados" }
} catch {
    $FirewallDetail = "Firewall no evaluado"
}

$OsSecurityEnabled = $false
$OsSecurityDetail = "Microsoft Defender no evaluado"
try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop
    $OsSecurityEnabled = [bool]$Defender.RealTimeProtectionEnabled
    $OsSecurityDetail = if ($OsSecurityEnabled) { "Activo (Defender)" } else { "Defender sin proteccion en tiempo real" }
} catch {
    $OsSecurityDetail = "Microsoft Defender no evaluado"
}

$PatchUpToDate = $false
$PatchDetail = "Parches no evaluados"
try {
    $LastHotFix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($LastHotFix -and $LastHotFix.InstalledOn) {
        $DaysSincePatch = ((Get-Date) - $LastHotFix.InstalledOn).TotalDays
        $PatchUpToDate = $DaysSincePatch -le 45
        $PatchDetail = if ($PatchUpToDate) { "Al dia" } else { "Ultimo parche hace mas de 45 dias" }
    }
} catch {
    $PatchDetail = "Parches no evaluados"
}

$IdentityAuditEnabled = $false
$IdentityAuditDetail = "Auditoria no evaluada"
try {
    $EventLogService = Get-CimInstance Win32_Service -Filter "Name='EventLog'" -ErrorAction Stop
    $IdentityAuditEnabled = $EventLogService.State -eq "Running"
    $IdentityAuditDetail = if ($IdentityAuditEnabled) { "Trazabilidad activa (Windows Event Log)" } else { "Windows Event Log no activo" }
} catch {
    $IdentityAuditDetail = "Auditoria no evaluada"
}

$Payload = @{
    hostname = $Hostname
    agent_version = "1.1.0"
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    metrics = @{
        cpu_percent = [double]$Cpu
        memory_percent = [double]$MemoryPercent
        disk_c_percent = [double]$DiskPercent
        disk_count = @($Disks).Count
        disks = @($Disks)
        uptime_seconds = $Uptime
        security = @{
            disk_encryption = @{
                enabled = $BitLockerEnabled
                detail = $BitLockerDetail
            }
            firewall = @{
                enabled = $FirewallEnabled
                name = "Windows Firewall"
                detail = $FirewallDetail
            }
            os_security = @{
                enabled = $OsSecurityEnabled
                name = "Microsoft Defender"
                detail = $OsSecurityDetail
            }
            patch_compliance = @{
                up_to_date = $PatchUpToDate
                detail = $PatchDetail
            }
            os_version = @{
                supported = $true
                detail = $Os.Caption
            }
            identity_audit = @{
                enabled = $IdentityAuditEnabled
                name = "Windows Event Log"
                detail = $IdentityAuditDetail
            }
        }
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
