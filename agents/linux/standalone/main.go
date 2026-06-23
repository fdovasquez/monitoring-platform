package main

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "strconv"
    "strings"
    "time"
)

const agentVersion = "1.4.0-standalone"

var lastPatchCheck time.Time
var cachedPatchSecurity map[string]interface{}

func env(name, fallback string) string {
    if value := os.Getenv(name); value != "" { return value }
    return fallback
}

func command(args ...string) string {
    output, err := exec.Command(args[0], args[1:]...).Output()
    if err != nil { return "" }
    return strings.TrimSpace(string(output))
}

func read(path string) string {
    data, err := os.ReadFile(path)
    if err != nil { return "" }
    return strings.TrimSpace(string(data))
}

func number(value string) float64 {
    result, _ := strconv.ParseFloat(strings.TrimSpace(value), 64)
    return result
}

func cpuTimes() (float64, float64) {
    fields := strings.Fields(read("/proc/stat"))
    if len(fields) < 6 { return 0, 0 }
    total, idle := 0.0, 0.0
    for index := 1; index < len(fields) && index < 9; index++ { total += number(fields[index]) }
    idle = number(fields[4]) + number(fields[5])
    return idle, total
}

func cpuPercent() float64 {
    idleA, totalA := cpuTimes()
    time.Sleep(time.Second)
    idleB, totalB := cpuTimes()
    if totalB <= totalA { return 0 }
    return round((1-(idleB-idleA)/(totalB-totalA))*100, 2)
}

func memoryPercent() float64 {
    values := map[string]float64{}
    for _, line := range strings.Split(read("/proc/meminfo"), "\n") {
        fields := strings.Fields(line)
        if len(fields) >= 2 { values[strings.TrimSuffix(fields[0], ":")] = number(fields[1]) }
    }
    if values["MemTotal"] == 0 { return 0 }
    available := values["MemAvailable"]
    if available == 0 { available = values["MemFree"] }
    return round((values["MemTotal"]-available)/values["MemTotal"]*100, 2)
}

func disks() ([]map[string]interface{}, float64) {
    lines := strings.Split(command("df", "-P", "-B1"), "\n")
    result := []map[string]interface{}{}
    rootPercent := 0.0
    for _, line := range lines[1:] {
        fields := strings.Fields(line)
        if len(fields) < 6 { continue }
        total, used := number(fields[1]), number(fields[2])
        if total <= 0 { continue }
        percent := round(used/total*100, 2)
        disk := map[string]interface{}{"device": fields[0], "mountpoint": fields[5], "total_gb": round(total/(1024*1024*1024), 2), "percent": percent}
        result = append(result, disk)
        if fields[5] == "/" { rootPercent = percent }
    }
    if rootPercent == 0 && len(result) > 0 { rootPercent = result[0]["percent"].(float64) }
    return result, rootPercent
}

func primaryIP() string {
    output := command("sh", "-c", "ip route get 1 2>/dev/null | awk '{print $7; exit}'")
    return output
}

func osVersion() string {
    for _, line := range strings.Split(read("/etc/os-release"), "\n") {
        parts := strings.SplitN(line, "=", 2)
        if len(parts) == 2 && parts[0] == "PRETTY_NAME" {
            return strings.Trim(parts[1], "\"")
        }
    }
    return runtime.GOOS
}

func serviceActive(name string) bool {
    return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

func firewallSecurity() map[string]interface{} {
    if serviceActive("firewalld") {
        return map[string]interface{}{"enabled": true, "detail": "Activo (firewalld)"}
    }
    if serviceActive("ufw") {
        return map[string]interface{}{"enabled": true, "detail": "Activo (UFW)"}
    }
    return map[string]interface{}{"enabled": false, "detail": "No se detecto un firewall activo"}
}

func diskEncryptionSecurity() map[string]interface{} {
    rootSource := command("findmnt", "-n", "-o", "SOURCE", "/")
    if rootSource == "" {
        return pendingSecurity("No fue posible identificar el volumen raiz")
    }

    volumeType := strings.ToLower(command("lsblk", "-no", "TYPE", rootSource))
    if volumeType == "crypt" {
        return map[string]interface{}{"enabled": true, "detail": "Volumen raiz protegido con LUKS/dm-crypt"}
    }

    return map[string]interface{}{"enabled": false, "detail": "El volumen raiz no usa cifrado LUKS/dm-crypt"}
}

func osSecurity() map[string]interface{} {
    selinux := strings.ToLower(command("getenforce"))
    if selinux == "enforcing" {
        return map[string]interface{}{"enabled": true, "detail": "SELinux en modo Enforcing"}
    }
    if serviceActive("apparmor") {
        return map[string]interface{}{"enabled": true, "detail": "AppArmor activo"}
    }
    return map[string]interface{}{"enabled": false, "detail": "No se detecto SELinux Enforcing ni AppArmor activo"}
}

func pendingSecurity(detail string) map[string]interface{} {
    return map[string]interface{}{"enabled": false, "detail": detail, "pending": true}
}

func patchSecurity() map[string]interface{} {
    if cachedPatchSecurity != nil && time.Since(lastPatchCheck) < 30*time.Minute {
        return cachedPatchSecurity
    }

    packageManager := ""
    if _, err := exec.LookPath("dnf"); err == nil {
        packageManager = "dnf"
    } else if _, err := exec.LookPath("yum"); err == nil {
        packageManager = "yum"
    }
    if packageManager == "" {
        cachedPatchSecurity = map[string]interface{}{
            "up_to_date": false,
            "detail": "No se encontro dnf ni yum para revisar actualizaciones",
            "pending": true,
        }
        lastPatchCheck = time.Now()
        return cachedPatchSecurity
    }

    run := exec.Command(packageManager, "-q", "check-update", "--cacheonly")
    if err := run.Run(); err == nil {
        cachedPatchSecurity = map[string]interface{}{"up_to_date": true, "detail": "Sin actualizaciones pendientes en el cache local"}
    } else if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 100 {
        cachedPatchSecurity = map[string]interface{}{"up_to_date": false, "detail": "Hay actualizaciones disponibles en el cache local"}
    } else {
        cachedPatchSecurity = map[string]interface{}{
            "up_to_date": false,
            "detail": "No fue posible consultar actualizaciones desde el cache local",
            "pending": true,
        }
    }
    lastPatchCheck = time.Now()
    return cachedPatchSecurity
}

func security() map[string]interface{} {
    return map[string]interface{}{
        "disk_encryption": diskEncryptionSecurity(),
        "firewall": firewallSecurity(),
        "os_security": osSecurity(),
        "patch_compliance": patchSecurity(),
        "os_version": map[string]interface{}{
            "supported": true,
            "detail": osVersion(),
        },
    }
}

func inventory(hostname string) map[string]interface{} {
    dns := []string{}
    for _, line := range strings.Split(read("/etc/resolv.conf"), "\n") {
        fields := strings.Fields(line)
        if len(fields) > 1 && fields[0] == "nameserver" { dns = append(dns, fields[1]) }
    }
    return map[string]interface{}{
        "hostname": hostname, "fqdn": command("hostname", "-f"), "os_name": runtime.GOOS,
        "os_version": osVersion(), "kernel": command("uname", "-r"), "architecture": runtime.GOARCH,
        "serial_number": read("/sys/class/dmi/id/product_serial"), "model": read("/sys/class/dmi/id/product_name"),
        "manufacturer": read("/sys/class/dmi/id/sys_vendor"), "domain": command("hostname", "-d"),
        "logged_user": env("SUDO_USER", env("USER", "")), "primary_ip": primaryIP(),
        "gateway": command("sh", "-c", "ip route | awk '/default/ {print $3; exit}'"), "dns_servers": dns,
        "mac_addresses": []string{}, "interfaces": []interface{}{}, "timezone": time.Now().Location().String(),
        "collected_at": time.Now().UTC().Format(time.RFC3339),
    }
}

func uptime() int64 { return int64(number(strings.Fields(read("/proc/uptime"))[0])) }
func round(value float64, decimals int) float64 { factor := 1.0; for i:=0; i<decimals; i++ { factor *= 10 }; return float64(int(value*factor+0.5))/factor }

func payload() map[string]interface{} {
    hostname, err := os.Hostname(); if err != nil { hostname = "unknown" }
    diskList, diskRoot := disks()
    return map[string]interface{}{
        "hostname": hostname, "agent_version": agentVersion, "timestamp": time.Now().UTC().Format(time.RFC3339),
        "metrics": map[string]interface{}{"cpu_percent": cpuPercent(), "memory_percent": memoryPercent(), "disk_root_percent": diskRoot, "disk_count": len(diskList), "disks": diskList, "uptime_seconds": uptime(), "security": security()},
        "inventory": inventory(hostname), "services": []interface{}{}, "processes": []interface{}{}, "ports": []interface{}{},
    }
}

func send(client *http.Client, apiURL, token string) error {
    data, err := json.Marshal(payload()); if err != nil { return err }
    request, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(data)); if err != nil { return err }
    request.Header.Set("Authorization", "Bearer "+token); request.Header.Set("Content-Type", "application/json")
    response, err := client.Do(request); if err != nil { return err }; defer response.Body.Close(); io.Copy(io.Discard, response.Body)
    if response.StatusCode >= 400 { return fmt.Errorf("HTTP %d", response.StatusCode) }; return nil
}

func main() {
    apiURL, token := os.Getenv("MONITORING_API_URL"), os.Getenv("MONITORING_AGENT_TOKEN")
    if apiURL == "" || token == "" { fmt.Fprintln(os.Stderr, "MONITORING_API_URL and MONITORING_AGENT_TOKEN are required"); os.Exit(1) }
    interval, err := time.ParseDuration(env("MONITORING_INTERVAL", "60")+"s"); if err != nil { interval = time.Minute }
    transport := &http.Transport{}
    tlsConfig := &tls.Config{}
    hasTLSConfig := false
    if caFile := os.Getenv("MONITORING_CA_FILE"); caFile != "" {
        pemData, err := os.ReadFile(caFile)
        if err != nil { fmt.Fprintf(os.Stderr, "No se pudo leer MONITORING_CA_FILE: %v\n", err); os.Exit(1) }
        roots := x509.NewCertPool()
        if !roots.AppendCertsFromPEM(pemData) { fmt.Fprintln(os.Stderr, "MONITORING_CA_FILE no contiene certificados PEM validos"); os.Exit(1) }
        tlsConfig.RootCAs = roots
        hasTLSConfig = true
    }
    if strings.EqualFold(env("MONITORING_VERIFY_TLS", "true"), "false") {
        tlsConfig.InsecureSkipVerify = true
        hasTLSConfig = true
    }
    if hasTLSConfig { transport.TLSClientConfig = tlsConfig }
    client := &http.Client{Timeout: 20*time.Second, Transport: transport}
    for { if err := send(client, apiURL, token); err != nil { fmt.Fprintf(os.Stderr, "%s error=%v\n", time.Now().UTC().Format(time.RFC3339), err) }; time.Sleep(interval) }
}
