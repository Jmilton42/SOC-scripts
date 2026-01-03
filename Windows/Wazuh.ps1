param(
    [String]$ScriptArgs = ""
)

$ArgumentsArray = $ScriptArgs -split ";"
if ($ArgumentsArray.Length -lt 1) {
    Write-Host "Not enough arguments provided." -ForegroundColor Red
    break
}
$Manager = $ArgumentsArray[0]
if ($ArgumentsArray[1]) {
    $RegistrationPassword = $ArgumentsArray[1]
} else {
    $RegistrationPassword = ""
}

$ErrorActionPreference = "Continue"

$DownloadPath = "C:\Windows\System32\wazuh-agent-4.11.1-1.msi"

if (Test-Path $DownloadPath) {
    $InstallCommand = "msiexec /i $DownloadPath /qn WAZUH_MANAGER=$Manager"
    if ($RegistrationPassword -ne "") {
        $InstallCommand += " WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword"
    }
	
    cmd.exe /c "$InstallCommand"
    sc.exe config WazuhSvc start= auto
    sc.exe start WazuhSvc
}

if (sc.exe query WazuhSvc | Select-String "RUNNING") {
    Write-Host "Wazuh agent is running." -ForegroundColor Green
    Write-Output "Wazuh agent is running."
} else {
    Write-Host "Wazuh agent is NOT running." -ForegroundColor RED
    Write-Output "Wazuh agent is NOT running."
}

# Suricata Installation and Configuration
Write-Host "`nStarting Suricata installation..." -ForegroundColor Cyan

# 1. Setup Directories
$workDir = "C:\temp\suricata_install"
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
Set-Location $workDir

# 2. Download Npcap (Required for Suricata to see the network)
Write-Host "Downloading Npcap..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://nmap.org/npcap/dist/npcap-1.85.exe" -OutFile "npcap.exe" -UseBasicParsing
    # Silent Install for Npcap (WinPcap compatibility mode is required)
    Start-Process -FilePath ".\npcap.exe" -ArgumentList "/S /winpcap_mode=yes" -Wait -NoNewWindow
    Write-Host "Npcap installed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error downloading/installing Npcap: $_" -ForegroundColor Red
}

# 3. Download and Install Suricata
Write-Host "Downloading Suricata..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.2-1-64bit.msi" -OutFile "suricata.msi" -UseBasicParsing
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i suricata.msi /qn /norestart" -Wait -NoNewWindow
    Write-Host "Suricata installed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error downloading/installing Suricata: $_" -ForegroundColor Red
}

# 4. Configure Suricata (Update HOME_NET and Interface)
$confPath = "C:\Program Files\Suricata\suricata.yaml"
if (Test-Path $confPath) {
    Write-Host "Configuring Suricata..." -ForegroundColor Yellow
    try {
        $content = Get-Content $confPath -Raw
        # Update HOME_NET - user should replace [YOUR_CCDC_SUBNET] with actual subnet
        $content = $content -replace 'HOME_NET: "\[192\.168\.0\.0/16,10\.0\.0\.0/8,172\.16\.0\.0/12\]"', 'HOME_NET: "[YOUR_CCDC_SUBNET]"'
        Set-Content -Path $confPath -Value $content -NoNewline
        Write-Host "Suricata configuration updated. NOTE: Update HOME_NET with your actual CCDC subnet!" -ForegroundColor Yellow
    } catch {
        Write-Host "Error configuring Suricata: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Suricata configuration file not found at $confPath" -ForegroundColor Red
}

# 5. Connect to Wazuh Agent
$wazuhConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $wazuhConf) {
    Write-Host "Configuring Wazuh to collect Suricata logs..." -ForegroundColor Yellow
    try {
        $suricataBlock = @"
  <localfile>
    <log_format>json</log_format>
    <location>C:\Program Files\Suricata\log\eve.json</location>
  </localfile>
"@
        # Check if Suricata block already exists
        $currentContent = Get-Content $wazuhConf -Raw
        if ($currentContent -notmatch "Suricata.*eve\.json") {
            Add-Content -Path $wazuhConf -Value $suricataBlock
            Write-Host "Suricata log collection added to Wazuh configuration." -ForegroundColor Green
        } else {
            Write-Host "Suricata log collection already configured in Wazuh." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error configuring Wazuh for Suricata: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Wazuh configuration file not found at $wazuhConf" -ForegroundColor Red
}

# 6. Start Services
Write-Host "Starting services..." -ForegroundColor Yellow
try {
    Restart-Service -Name "Suricata" -ErrorAction SilentlyContinue
    Write-Host "Suricata service restarted." -ForegroundColor Green
} catch {
    Write-Host "Could not restart Suricata service (may not be installed yet)." -ForegroundColor Yellow
}

try {
    Restart-Service -Name "wazuh" -ErrorAction SilentlyContinue
    Write-Host "Wazuh service restarted." -ForegroundColor Green
} catch {
    Write-Host "Could not restart Wazuh service." -ForegroundColor Red
}

Write-Host "`nSuricata installation and configuration completed!" -ForegroundColor Cyan
Write-Host "IMPORTANT: Update HOME_NET in C:\Program Files\Suricata\suricata.yaml with your actual CCDC subnet!" -ForegroundColor Yellow