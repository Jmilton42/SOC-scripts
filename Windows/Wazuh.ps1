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

# Download and Install Wazuh Agent
Write-Host "Downloading Wazuh Agent..." -ForegroundColor Yellow
$DownloadPath = "$env:tmp\wazuh-agent.msi"
try {
    Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi" -OutFile $DownloadPath -UseBasicParsing
    Write-Host "Wazuh Agent downloaded successfully." -ForegroundColor Green
    
    Write-Host "Installing Wazuh Agent..." -ForegroundColor Yellow
    $InstallCommand = "msiexec.exe /i `"$DownloadPath`" /q WAZUH_MANAGER=$Manager"
    if ($RegistrationPassword -ne "") {
        $InstallCommand += " WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword"
    }
    
    cmd.exe /c $InstallCommand
    Start-Sleep -Seconds 5
    
    sc.exe config WazuhSvc start= auto
    sc.exe start WazuhSvc
    Start-Sleep -Seconds 3
    
    if (sc.exe query WazuhSvc | Select-String "RUNNING") {
        Write-Host "Wazuh agent is running." -ForegroundColor Green
        Write-Output "Wazuh agent is running."
    } else {
        Write-Host "Wazuh agent is NOT running." -ForegroundColor RED
        Write-Output "Wazuh agent is NOT running."
    }
} catch {
    Write-Host "Error downloading/installing Wazuh Agent: $_" -ForegroundColor Red
}

## Suricata Installation and Configuration
#Write-Host "`nStarting Suricata installation..." -ForegroundColor Cyan
#
## 1. Setup Directories
#$workDir = "C:\temp\suricata_install"
#New-Item -ItemType Directory -Force -Path $workDir | Out-Null
#Set-Location $workDir
#
## 2. Download and Install Npcap (Required for Suricata to see the network)
#Write-Host "Downloading Npcap..." -ForegroundColor Yellow
#try {
#    Invoke-WebRequest -Uri "https://nmap.org/npcap/dist/npcap-1.85.exe" -OutFile "npcap.exe" -UseBasicParsing
#    Write-Host "Installing Npcap (this may show a UI window)..." -ForegroundColor Yellow
#    # Npcap standard version shows a warning about silent install, but we'll proceed
#    # The installer will still run and can be completed
#    $npcapArgs = "/S /winpcap_mode=yes /npf_startup=yes /loopback_support=yes"
#    $process = Start-Process -FilePath ".\npcap.exe" -ArgumentList $npcapArgs -Wait -PassThru
#    Start-Sleep -Seconds 2
#    
#    # Check if Npcap was installed by checking for the service or driver
#    $npcapInstalled = $false
#    if (Test-Path "C:\Program Files\Npcap") {
#        $npcapInstalled = $true
#    } elseif (Get-Service -Name "npcap" -ErrorAction SilentlyContinue) {
#        $npcapInstalled = $true
#    }
#    
#    if ($npcapInstalled -or $process.ExitCode -eq 0) {
#        Write-Host "Npcap installed successfully." -ForegroundColor Green
#    } else {
#        Write-Host "Npcap installation may require manual completion. Please check if Npcap is installed." -ForegroundColor Yellow
#    }
#} catch {
#    Write-Host "Error downloading/installing Npcap: $_" -ForegroundColor Red
#    Write-Host "Please install Npcap manually from: https://nmap.org/npcap/" -ForegroundColor Yellow
#}
#
## 3. Download and Install Suricata
#Write-Host "Downloading Suricata..." -ForegroundColor Yellow
#try {
#    Invoke-WebRequest -Uri "https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.2-1-64bit.msi" -OutFile "suricata.msi" -UseBasicParsing
#    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i suricata.msi /qn /norestart" -Wait -NoNewWindow
#    Write-Host "Suricata installed successfully." -ForegroundColor Green
#} catch {
#    Write-Host "Error downloading/installing Suricata: $_" -ForegroundColor Red
#}
#
## 3.5. Download Emerging Threats Rules
#Write-Host "Downloading Emerging Threats rules..." -ForegroundColor Yellow
#try {
#    $rulesDir = "C:\Program Files\Suricata\rules"
#    New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
#    Invoke-WebRequest -Uri "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules" -OutFile "$rulesDir\emerging-all.rules" -UseBasicParsing
#    Write-Host "Emerging Threats rules downloaded successfully." -ForegroundColor Green
#} catch {
#    Write-Host "Error downloading rules: $_" -ForegroundColor Red
#}
#
# 4. Configure Suricata (Update HOME_NET and Interface)
#$confPath = "C:\Program Files\Suricata\suricata.yaml"
#if (Test-Path $confPath) {
#    Write-Host "Configuring Suricata..." -ForegroundColor Yellow
#    try {
#        # Auto-detect IPv4 address from Ethernet adapter
#        $ethernetAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -like "*Ethernet*" } | Select-Object -First 1
#        if (-not $ethernetAdapter) {
#            # Fallback to any up adapter
#            $ethernetAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
#        }
#        
#        if ($ethernetAdapter) {
#            $adapterName = $ethernetAdapter.Name
#            $ipAddress = (Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254.*" }).IPAddress
#            
#            if ($ipAddress) {
#                Write-Host "Detected Ethernet adapter: $adapterName" -ForegroundColor Green
#                Write-Host "Detected IPv4 address: $ipAddress" -ForegroundColor Green
#                
#                $content = Get-Content $confPath -Raw
#                
#                # Update HOME_NET with detected IP
#                $content = $content -replace '(HOME_NET:\s*")([^"]*)(")', "`$1$ipAddress`$3"
#                
#                # Update EXTERNAL_NET to "any"
#                $content = $content -replace '(EXTERNAL_NET:\s*")([^"]*)(")', "`$1any`$3"
#                
#                # Update default-rule-path (Windows uses forward slashes in YAML)
#                $content = $content -replace '(default-rule-path:\s*)([^\r\n]*)', "`$1/etc/suricata/rules"
#                
#                # Update rule-files to use emerging-all.rules
#                if ($content -match '(rule-files:\s*\r?\n)') {
#                    # Remove existing rule entries and add emerging-all.rules
#                    $content = $content -replace '(rule-files:\s*\r?\n)(\s*-\s*[^\r\n]*\r?\n)*', "rule-files:`r`n  - emerging-all.rules`r`n"
#                } else {
#                    $content = $content -replace '(default-rule-path:\s*/etc/suricata/rules)', "`$1`r`nrule-files:`r`n  - emerging-all.rules"
#                }
#                
#                # Update af-packet interface (Windows uses interface name like "Ethernet0")
#                # Find af-packet section and update interface
#                if ($content -match '(af-packet:\s*\r?\n\s*-\s*interface:\s*)([^\r\n]*)') {
#                    $content = $content -replace '(af-packet:\s*\r?\n\s*-\s*interface:\s*)([^\r\n]*)', "`$1$adapterName"
#                } else {
#                    # If af-packet section doesn't exist, add it
#                    $afPacketBlock = @"
#
## Linux high speed capture support
#af-packet:
#  - interface: $adapterName
#"@
#                    $content = $content -replace '(# Linux high speed capture support)', $afPacketBlock
#                }
#                
#                # Enable stats
#                if ($content -match '(stats:\s*\r?\n\s*enabled:\s*)([^\r\n]*)') {
#                    $content = $content -replace '(stats:\s*\r?\n\s*enabled:\s*)([^\r\n]*)', "`$1yes"
#                } else {
#                    # Add stats section if it doesn't exist
#                    $statsBlock = @"
#
## Global stats configuration
#stats:
#  enabled: yes
#"@
#                    $content = $content -replace '(# Global stats configuration)', $statsBlock
#                }
#                
#                Set-Content -Path $confPath -Value $content -NoNewline
#                Write-Host "Suricata configuration updated successfully!" -ForegroundColor Green
#                Write-Host "  HOME_NET: $ipAddress" -ForegroundColor Cyan
#                Write-Host "  EXTERNAL_NET: any" -ForegroundColor Cyan
#                Write-Host "  Interface: $adapterName" -ForegroundColor Cyan
#            } else {
#                Write-Host "Could not detect IPv4 address for adapter $adapterName" -ForegroundColor Red
#            }
#        } else {
#            Write-Host "Could not detect Ethernet adapter" -ForegroundColor Red
#        }
#    } catch {
#        Write-Host "Error configuring Suricata: $_" -ForegroundColor Red
#    }
#} else {
#    Write-Host "Suricata configuration file not found at $confPath" -ForegroundColor Red
#}

# 5. Download and Install Sysmon
Write-Host "`nDownloading Sysmon..." -ForegroundColor Cyan
try {
    $sysmonZip = "$workDir\Sysmon.zip"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip -UseBasicParsing
    Write-Host "Extracting Sysmon..." -ForegroundColor Yellow
    
    # Extract Sysmon
    Expand-Archive -Path $sysmonZip -DestinationPath "$workDir\Sysmon" -Force
    
    # Determine which Sysmon executable to use (64-bit or 32-bit)
    $sysmonExe = "$workDir\Sysmon\Sysmon64.exe"
    if (-not (Test-Path $sysmonExe)) {
        $sysmonExe = "$workDir\Sysmon\Sysmon.exe"
    }
    
    if (Test-Path $sysmonExe) {
        Write-Host "Installing Sysmon..." -ForegroundColor Yellow
        
        # Find sysmon.xml - check script directory first (where it's located with Wazuh.ps1)
        $sysmonXml = $null
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        if (-not $scriptDir) {
            $scriptDir = $PSScriptRoot
        }
        $possiblePaths = @(
            "$scriptDir\sysmon.xml",           # Same directory as script (primary location)
            "$PSScriptRoot\sysmon.xml",        # Using $PSScriptRoot
            ".\sysmon.xml",                    # Current directory
            "$scriptDir\..\sysmon.xml",        # Parent directory (fallback)
            "$PSScriptRoot\..\sysmon.xml",     # Parent of script root (fallback)
            "..\sysmon.xml"                    # Parent of current (fallback)
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $sysmonXml = (Resolve-Path $path).Path
                break
            }
        }
        
        if ($sysmonXml) {
            Write-Host "Found sysmon.xml at: $sysmonXml" -ForegroundColor Green
            # Install Sysmon with the configuration file
            $installArgs = "-accepteula -i `"$sysmonXml`""
            Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -NoNewWindow
            Write-Host "Sysmon installed successfully with configuration." -ForegroundColor Green
        } else {
            Write-Host "Warning: sysmon.xml not found. Installing Sysmon without configuration." -ForegroundColor Yellow
            Write-Host "Searched in: $($possiblePaths -join ', ')" -ForegroundColor Yellow
            # Install Sysmon without config (user can configure later)
            Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula" -Wait -NoNewWindow
            Write-Host "Sysmon installed (please configure manually)." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Error: Sysmon executable not found after extraction." -ForegroundColor Red
    }
} catch {
    Write-Host "Error downloading/installing Sysmon: $_" -ForegroundColor Red
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

Write-Host "`nInstallation and configuration completed!" -ForegroundColor Cyan
Write-Host "  - Wazuh Agent installed and configured" -ForegroundColor Green
Write-Host "  - Suricata installed and configured" -ForegroundColor Green
Write-Host "  - Sysmon installed and configured" -ForegroundColor Green
