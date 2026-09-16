# ET Pro Daily Downloader - Windows Scheduled Task Setup Script
param(
    [string]$Time = "00:00"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $projectRoot) {
    $projectRoot = (Get-Location).Path
}

$pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Could not find python.exe in system PATH. Please ensure Python is installed and in PATH."
    exit 1
}
$pythonExe = $pythonCmd.Source

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  ET Pro Daily Downloader - Windows Task Scheduler Setup" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  Project Directory : $projectRoot"
Write-Host "  Python Executable : $pythonExe"
Write-Host "  Daily Schedule    : Every day at $Time"
Write-Host "  Missed Runs Policy: Start immediately when available"
Write-Host ""

$taskName = "ETPro_Daily_Downloader"
$scriptPath = Join-Path $projectRoot "src\scheduler_entry.py"

if (-not (Test-Path $scriptPath)) {
    Write-Error "Cannot find scheduler entry point at: $scriptPath"
    exit 1
}

$action = New-ScheduledTaskAction -Execute $pythonExe -Argument "src\scheduler_entry.py" -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "ET Pro Suricata Rules Daily Auto Downloader & Auto-Healing Pipeline" -Force | Out-Null
    Write-Host "[+] Successfully registered Windows Scheduled Task: $taskName" -ForegroundColor Green
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit 1
}

Write-Host ""
Write-Host "[*] Verifying Task Status:" -ForegroundColor Yellow
schtasks.exe /query /tn $taskName /fo TABLE
Write-Host ""
Write-Host "[v] All set! Windows will now automatically download and update ET Pro rules daily." -ForegroundColor Green
