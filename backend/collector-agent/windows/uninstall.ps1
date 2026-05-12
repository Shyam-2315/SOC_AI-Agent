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
    throw "Python was not found on PATH."
}

function Invoke-Python {
    param(
        [hashtable]$PythonCommand,
        [string[]]$Arguments,
        [switch]$AllowFailure
    )
    $allArgs = @($PythonCommand.Args) + @($Arguments)
    & $PythonCommand.File @allArgs
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "Python command failed: $($Arguments -join ' ')"
    }
}

$python = Get-PythonCommand
$service = Get-Service -Name "AISOCWindowsCollector" -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -ne "Stopped") {
        Write-Host "Stopping AI SOC Windows Collector service..."
        Invoke-Python $python @("windows_service.py", "stop") -AllowFailure
        Start-Sleep -Seconds 2
    }

    Write-Host "Removing AI SOC Windows Collector service..."
    Invoke-Python $python @("windows_service.py", "remove")
} else {
    Write-Host "Service AISOCWindowsCollector is not installed."
}

$cleanup = Read-Host "Remove config.json, state.json and logs directory? [y/N]"
if ($cleanup -match "^(y|yes)$") {
    Remove-Item -Path "config.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "state.json" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "logs" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed config, state and logs."
} else {
    Write-Host "Kept config, state and logs."
}

Write-Host "Uninstall complete."
