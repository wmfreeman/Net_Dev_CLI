# Builds dist\Net_Dev_CLI.exe: one file with Python and every dependency inside,
# so it runs on a Windows machine with nothing installed.
#
# Usage, from this folder:   powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
# Needs Poetry and the dev dependencies (poetry install), which include PyInstaller.

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

poetry install --no-interaction
if ($LASTEXITCODE) { throw "poetry install failed" }

# --add-data bundles the skeleton config and health check thresholds; on first use the EXE copies
# them to config\config.yml and config\health_checks.yaml next to itself. build\ and dist\ are
# recreated each time.
poetry run pyinstaller palo_image_updater.py `
    --onefile `
    --console `
    --name Net_Dev_CLI `
    --add-data "config\skeleton_config.yml;config" `
    --add-data "config\skeleton_health_checks.yaml;config" `
    --clean `
    --noconfirm
if ($LASTEXITCODE) { throw "PyInstaller failed" }

$exe = Join-Path $PSScriptRoot 'dist\Net_Dev_CLI.exe'
Write-Host ""
Write-Host "Built $exe ($([math]::Round((Get-Item $exe).Length / 1MB, 1)) MB)"
