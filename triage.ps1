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
    
Get-TriageSystemInfo | Format-List