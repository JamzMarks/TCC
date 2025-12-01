# main.ps1

# Caminhos absolutos baseados no diretório do script
$AuditDir = Join-Path $PSScriptRoot "tcc_audit_ms"
$DeviceDir = Join-Path $PSScriptRoot "tcc_device-ms"
$UserDir = Join-Path $PSScriptRoot "tcc_user_ms"

function Start-DockerCompose($dir) {
    Push-Location $dir
    docker-compose up -d
    Pop-Location
}
# --- Rodar Audit ---
Write-Host "===== Starting Audit ====="
Start-DockerCompose $AuditDir

# --- Rodar User ---
Write-Host "===== Starting User ====="
Start-DockerCompose $UserDir

# --- Rodar Device ---
Write-Host "===== Starting Device ====="
Start-DockerCompose $DeviceDir

