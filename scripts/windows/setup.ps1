# One-time setup: removes files left over from older releases, builds the Rust core, installs the
# locked Node dependencies, creates the Python virtualenv and installs its dependencies, and builds
# the React dashboard. Stops at the first failing step (native commands do not trip
# $ErrorActionPreference in Windows PowerShell, so every exit code is checked explicitly).
$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

function Invoke-Step([string]$What, [scriptblock]$Cmd) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "SETUP FAILED: $What (exit code $LASTEXITCODE). Fix the error above and run setup again." -ForegroundColor Red
    exit $LASTEXITCODE
  }
}

Write-Host "== Checking prerequisites =="
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Write-Error "cargo not found - install Rust from https://rustup.rs"; exit 1 }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Error "node not found - install Node.js 18+"; exit 1 }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Error "python not found - install Python 3.9+"; exit 1 }

Write-Host "== Removing files left over from older releases =="
& "$PSScriptRoot\remove_stale_files.ps1"

Write-Host "== Building Rust core =="
Set-Location "$RootDir\rust-core"
Invoke-Step "cargo build --release" { cargo build --release }

Write-Host "== Installing Node gateway dependencies (exact versions from package-lock.json) =="
Set-Location "$RootDir\node-server"
Invoke-Step "npm ci (node-server)" { npm ci }
Invoke-Step "npm run build (node-server)" { npm run build }

Write-Host "== Setting up Python image service =="
Set-Location "$RootDir\python-service"
if (-not (Test-Path ".\venv\Scripts\python.exe")) { Invoke-Step "python -m venv" { python -m venv venv } }
Invoke-Step "pip upgrade" { & ".\venv\Scripts\python.exe" -m pip install --upgrade pip }
Invoke-Step "pip install -r requirements.txt" { & ".\venv\Scripts\python.exe" -m pip install -r requirements.txt }

Write-Host "== Installing React dashboard dependencies (exact versions from package-lock.json) =="
Set-Location "$RootDir\web-ui"
Invoke-Step "npm ci (web-ui)" { npm ci }
Invoke-Step "npm run build (web-ui)" { npm run build }

Set-Location $RootDir
Write-Host ""
Write-Host "Setup complete. Next: .\scripts\windows\run_demo.ps1" -ForegroundColor Green
