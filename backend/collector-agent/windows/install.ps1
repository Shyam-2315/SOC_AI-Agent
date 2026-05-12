param(
    [switch]$NoService
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Get-PythonCommand {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return @{ File = "py"; Args = @("-3") }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @{ File = "python"; Args = @() }
    }
    throw "Python was not found. Install Python 3, enable 'Add Python to PATH', then rerun install.ps1."
}

function Invoke-Python {
    param(
        [hashtable]$PythonCommand,
        [string[]]$Arguments
    )
    $allArgs = @($PythonCommand.Args) + @($Arguments)
    & $PythonCommand.File @allArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $($Arguments -join ' ')"
    }
}

$python = Get-PythonCommand
Write-Host "Using Python command: $($python.File) $($python.Args -join ' ')"

Write-Host "Installing Python dependencies..."
Invoke-Python $python @("-m", "pip", "install", "-r", "requirements.txt")

$backendUrl = Read-Host "Backend URL [http://127.0.0.1]"
if ([string]::IsNullOrWhiteSpace($backendUrl)) {
    $backendUrl = "http://127.0.0.1"
}

$collectorToken = Read-Host "Collector token"
if ([string]::IsNullOrWhiteSpace($collectorToken)) {
    throw "Collector token is required. Create a collector in the AI SOC UI and paste its one-time token."
}

$defaultSource = "$env:COMPUTERNAME"
$sourceName = Read-Host "Source name [$defaultSource]"
if ([string]::IsNullOrWhiteSpace($sourceName)) {
    $sourceName = $defaultSource
}

$config = [ordered]@{
    backend_url = $backendUrl
    collector_token = $collectorToken
    source_name = $sourceName
    polling_interval_seconds = 15
    batch_size = 50
    logs_directory = "logs"
    state_file = "state.json"
}

$config | ConvertTo-Json -Depth 5 | Set-Content -Path "config.json" -Encoding UTF8
Write-Host "Wrote config.json"

if (-not $NoService) {
    Write-Host "Installing Windows service..."
    Invoke-Python $python @("windows_service.py", "install", "--startup", "auto")

    Write-Host "Starting Windows service..."
    Invoke-Python $python @("windows_service.py", "start")

    Write-Host "Service status:"
    Get-Service -Name "AISOCWindowsCollector" | Format-List Name, DisplayName, Status, StartType
} else {
    Write-Host "Skipped service install because -NoService was provided."
}

Write-Host ""
Write-Host "Installation complete."
Write-Host "Test manually with:"
Write-Host "  python windows_collector.py --test"
Write-Host "  python windows_collector.py --once"
