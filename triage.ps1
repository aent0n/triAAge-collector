# triAAge-collector.ps1
# Outil de triage pour la DFIR - @illumn

function Get-TriageSystemInfo {
    
    <# .SYNOPSIS
    collecte les infos système de base #>

    Write-Host "[+] gathering system info... " -ForegroundColor Cyan

    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    $tz = [TimeZoneInfo]::Local.DisplayName

    [PSCustomObject]@{
        Hostname    = $env:COMPUTERNAME
        OSName      = $os.Caption
        OSVersion   = $os.Version
        OSBuild     = $os.BuildNumber
        CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        LocalTime   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
        Timezone    = $tz
        InstallDate = $os.InstallDate
    }
    
}
    
function Get-triageProcesses {
    
    <# .SYNOPSIS
    collecte les processus actifs #>

    Write-Host "[+] gathering processes..." -ForegroundColor Cyan
    $processes = Get-CimInstance -ClassName Win32_Process
    $processlist = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($proc in $processes) {
     
        $sha256 = "N/A"
        if ($proc.ExecutablePath) {
            try {
                $hashResult = Get-FileHash -Path $proc.ExecutablePath -Algorithm SHA256 -ErrorAction Stop
                $sha256 = $hashResult.Hash
            }
            catch {
                $sha256 = "permission denied or locked"
            }
        }

        $processlist.Add([PSCustomObject]@{
                PID            = $proc.ProcessId
                PPID           = $proc.ParentProcessId
                Name           = $proc.Name
                CommandLine    = $proc.CommandLine
                ExecutablePath = $proc.ExecutablePath
                SHA256         = $sha256
                CreationDate   = $proc.CreationDate
            })
    }
    return $processlist
}

function Get-TriageNetwork {
    <# .SYNOPSIS
    collecte les infos réseau tcp/udp#>

    Write-Host "[+] gathering network connections" -ForegroundColor Cyan
    
    $networkList = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    $tcpNetConns = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }
    foreach ($conn in $tcpNetConns) {
        $networkList.Add([PSCustomObject]@{
                Protocol      = "TCP"
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
                PID           = $conn.OwningProcess
            })
    }

    $udpNetConns = Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" }
    foreach ($conn in $udpNetConns) {
        $networkList.Add([PSCustomObject]@{
                Protocol      = "UDP"
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
                PID           = $conn.OwningProcess
            })
    }

    return $networkList
}

function Get-TriagePersistence {
    <# .SYNOPSIS
    collecte les éléments de persistance #> 

    Write-Host "[+] gathering persistence objects..." -ForegroundColor Cyan
    
    $persistenceItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $properties = Get-Item -Path $path
            foreach ($valueName in $properties.GetValueNames()) {
                $persistenceItems.Add([PSCustomObject]@{
                        Type     = "Registry Run Key"
                        Location = $path
                        Name     = $valueName
                        Command  = $properties.GetValue($valueName)
                    })
            }
        }
    }    

    $startupPaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\StartUp"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -File
            foreach ($file in $files) {
                $persistenceItems.Add([PSCustomObject]@{ 
                        Type     = "Startup Folder"
                        Location = $path
                        Name     = $file.Name
                        Command  = $file.FullName
                    })
            }
        }
    }

    $nonSystemServices = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "*System32*" -and $_.PathName -notlike "*SysWOW64*" }

    foreach ($service in $nonSystemServices) {
        $persistenceItems.Add([PSCustomObject]@{
                Type     = "Auto / Non System Service"
                Location = $service.Name
                Name     = $service.DisplayName
                Command  = $service.PathName
            })
    }

    return $persistenceItems

}

function Invoke-TriAAge {
 
    <# .SYNOPSIS
    lancement global#>
    
    Write-Host "[+] TriAAge started..." -ForegroundColor Green

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[!] Please run as Administrator." -ForegroundColor Yellow
        Write-Host "[!] File hash and log collection cannot be fully performed without admin rights`n" -ForegroundColor Yellow
    }
    else {
        Write-Host "[+] Admin rights verified`n" -ForegroundColor Green
    }

    $systemInfo = Get-TriageSystemInfo
    $processes = Get-TriageProcesses
    $network = Get-TriageNetwork
    $persistence = Get-TriagePersistence
    
    $report = [PSCustomObject]@{
        Metadata    = [PSCustomObject]@{
            CollectorVersion = "v0.6"
            RunDate          = $systemInfo.LocalTime
            Analyst          = $systemInfo.CurrentUser
            AdminRights      = $isAdmin
        }
        SystemInfo  = $systemInfo
        Processes   = $processes
        Network     = $network
        Persistence = $persistence
    }

    $outputDir = Join-Path $PSScriptRoot -ChildPath "TriAAge_Reports" 

    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory | Out-Null
    }

    $timestamp = ([datetime]$report.Metadata.RunDate).ToString("yyyyMMdd_HHmmss")
    $filename = "TriAAge_$($systemInfo.hostname)_$timestamp.json"
    $outputPath = Join-Path -Path $outputDir -ChildPath $filename
    
    Write-Host "[+] saving JSON report to $outputPath`n" -ForegroundColor Green
    $reportJson = $report | ConvertTo-Json -Depth 10
    $reportJson | Out-File -FilePath $outputPath -Encoding UTF8
    
    Write-Host "[+] TriAAge completed successfully!" -ForegroundColor Green
}

Invoke-TriAAge