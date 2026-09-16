$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCmd) {
    $PythonExe = $pythonCmd.Source
} else {
    $candidates = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue
    if ($candidates) {
        $PythonExe = $candidates[0].FullName
    } else {
        throw "Python executable not found. Please ensure Python is installed and added to PATH."
    }
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
