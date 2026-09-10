$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"

if (-not (Test-Path $PythonExe)) {
    throw "Python executable not found: $PythonExe"
}

$Oinkcode = [Environment]::GetEnvironmentVariable("ETPRO_OINKCODE", "User")
if ([string]::IsNullOrWhiteSpace($Oinkcode)) {
    $Oinkcode = [Environment]::GetEnvironmentVariable("ETPRO_OINKCODE", "Machine")
}

if ([string]::IsNullOrWhiteSpace($Oinkcode)) {
    throw "Missing required environment variable: ETPRO_OINKCODE"
}

$env:ETPRO_OINKCODE = $Oinkcode

$DeployTargetPath = [Environment]::GetEnvironmentVariable("ETPRO_DEPLOY_TARGET_PATH", "User")
if ([string]::IsNullOrWhiteSpace($DeployTargetPath)) {
    $DeployTargetPath = [Environment]::GetEnvironmentVariable("ETPRO_DEPLOY_TARGET_PATH", "Machine")
}

if (-not [string]::IsNullOrWhiteSpace($DeployTargetPath)) {
    $env:ETPRO_DEPLOY_TARGET_PATH = $DeployTargetPath
}

Set-Location $ProjectRoot
& $PythonExe (Join-Path $ProjectRoot "src\scheduler_entry.py")
exit $LASTEXITCODE
