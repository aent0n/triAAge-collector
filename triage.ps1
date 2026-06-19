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
        LocalTime   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss:zzz")
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
