param(
    [switch]$Repair,
    [switch]$Status,
    [switch]$Test
)

$ErrorActionPreference = "Stop"
$ServiceName = "AISOCWindowsCollector"
$InstallDir = "C:\ai-soc-windows-collector"
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath = Join-Path $InstallDir "config.json"

function Get-PythonCommand {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { return @{ File = "py"; Prefix = @("-3") } }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return @{ File = "python"; Prefix = @() } }
    throw "Python 3 was not found. Install Python 3 and rerun install.ps1."
}

function Invoke-Python {
    param([hashtable]$PythonCmd, [string[]]$Args, [string]$WorkingDir)
    Push-Location $WorkingDir
    try {
        & $PythonCmd.File @($PythonCmd.Prefix + $Args)
        if ($LASTEXITCODE -ne 0) {
            throw "Python command failed: $($Args -join ' ')"
        }
    } finally {
        Pop-Location
    }
}

function Get-ServiceState {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return "not_installed" }
    if ($svc.Status -eq "Running") { return "running" }
    return "stopped"
}

function Copy-InstallFiles {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $files = @(
        "windows_event_collector.py",
        "windows_service.py",
        "requirements.txt",
        "config.example.json",
        "install.ps1",
        "README.md"
    )
    foreach ($file in $files) {
        Copy-Item (Join-Path $SourceDir $file) (Join-Path $InstallDir $file) -Force
    }
    New-Item -ItemType Directory -Path (Join-Path $InstallDir "logs") -Force | Out-Null
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return Get-Content -Raw $Path | ConvertFrom-Json
}

function Ensure-Config {
    param([switch]$ForceRewrite)

    $existing = Read-JsonFile -Path $ConfigPath
    if ($existing -and -not $ForceRewrite) {
        $required = @("backend_url", "collector_token", "source_name")
        $missing = @()
        foreach ($k in $required) {
            if (-not $existing.$k) { $missing += $k }
        }
        if ($missing.Count -eq 0) {
            Write-Host "config exists: yes"
            return
        }

        $answer = Read-Host "config.json missing fields ($($missing -join ', ')). Update now? [y/N]"
        if ($answer -notin @("y", "Y", "yes", "YES")) {
            throw "config.json is invalid. Use -Repair or confirm update."
        }
    }

    $defaultBackend = if ($existing -and $existing.backend_url) { $existing.backend_url } else { "http://127.0.0.1:8000" }
    $defaultSource = if ($existing -and $existing.source_name) { $existing.source_name } else { $env:COMPUTERNAME }

    $backendUrl = Read-Host "Backend URL [$defaultBackend]"
    if ([string]::IsNullOrWhiteSpace($backendUrl)) { $backendUrl = $defaultBackend }

    $defaultToken = if ($existing -and $existing.collector_token) { $existing.collector_token } else { "" }
    $tokenPrompt = if ($defaultToken) { "Collector token [press Enter to keep existing]" } else { "Collector token" }
    $collectorToken = Read-Host $tokenPrompt
    if ([string]::IsNullOrWhiteSpace($collectorToken)) { $collectorToken = $defaultToken }

    $sourceName = Read-Host "Source name [$defaultSource]"
    if ([string]::IsNullOrWhiteSpace($sourceName)) { $sourceName = $defaultSource }

    if ([string]::IsNullOrWhiteSpace($backendUrl) -or [string]::IsNullOrWhiteSpace($collectorToken) -or [string]::IsNullOrWhiteSpace($sourceName)) {
        throw "backend_url, collector_token and source_name are required."
    }

    $config = [ordered]@{
        backend_url = $backendUrl
        collector_token = $collectorToken
        api_token = $collectorToken
        source_name = $sourceName
        poll_interval_seconds = 5
        log_name = "Security"
        event_ids = @(4625)
        state_file = "state.json"
        logs_directory = "logs"
    }
    $config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "config exists: yes"
}

function Ensure-VenvAndDeps {
    $venvPath = Join-Path $InstallDir ".venv"
    if (-not (Test-Path $venvPath)) {
        Invoke-Python -PythonCmd $python -Args @("-m", "venv", ".venv") -WorkingDir $InstallDir
    }
    Invoke-Python -PythonCmd $python -Args @("-m", "pip", "install", "--upgrade", "pip") -WorkingDir $InstallDir
    Invoke-Python -PythonCmd $python -Args @("-m", "pip", "install", "-r", "requirements.txt") -WorkingDir $InstallDir
}

function Install-Or-RepairService {
    Push-Location $InstallDir
    try {
        $exists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($exists) {
            & $python.File @($python.Prefix + @("windows_service.py", "remove"))
        }

        & $python.File @($python.Prefix + @("windows_service.py", "--startup", "auto", "install"))
        if ($LASTEXITCODE -ne 0) { throw "Service install failed" }

        sc.exe failure $ServiceName reset= 0 actions= restart/60000/restart/60000/""/0 | Out-Null
        sc.exe failureflag $ServiceName 1 | Out-Null

        & $python.File @($python.Prefix + @("windows_service.py", "start"))
        if ($LASTEXITCODE -ne 0) { throw "Service start failed" }
    } finally {
        Pop-Location
    }
}

function Test-BackendReachable {
    $cfg = Read-JsonFile -Path $ConfigPath
    if (-not $cfg) { return $false }
    $base = [string]$cfg.backend_url
    $url = $base.TrimEnd('/') + "/health/ready"
    try {
        $res = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 6
        return ($res.StatusCode -ge 200 -and $res.StatusCode -lt 500)
    } catch {
        return $false
    }
}

function Print-Status {
    $state = Get-ServiceState
    Write-Host "service $state"

    $configOk = $false
    if (Test-Path $ConfigPath) {
        $cfg = Read-JsonFile -Path $ConfigPath
        if ($cfg -and $cfg.backend_url -and $cfg.collector_token -and $cfg.source_name) {
            $configOk = $true
        }
    }
    Write-Host ("config exists: " + ($(if ($configOk) {"yes"} else {"no"})))
    Write-Host ("backend reachable: " + ($(if (Test-BackendReachable) {"yes"} else {"no"})))
}

function Run-TestEvent {
    Push-Location $InstallDir
    try {
        & $python.File @($python.Prefix + @("windows_event_collector.py", "--test"))
        if ($LASTEXITCODE -eq 0) {
            Write-Host "test event accepted"
        } else {
            Write-Host "test event rejected"
            throw "Collector test failed"
        }
    } finally {
        Pop-Location
    }
}

$python = Get-PythonCommand

if ($Status) {
    Print-Status
    exit 0
}

if ($Test) {
    Print-Status
    Run-TestEvent
    exit 0
}

Copy-InstallFiles
Ensure-VenvAndDeps
Ensure-Config -ForceRewrite:$Repair
Install-Or-RepairService

Print-Status
Write-Host "install path: $InstallDir"
