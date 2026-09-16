# One-time setup: builds the Rust core, installs Node dependencies,
# creates the Python virtualenv and installs its dependencies, and
# installs React dashboard dependencies.
$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

Write-Host "== Checking prerequisites =="
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Write-Error "cargo not found - install Rust from https://rustup.rs"; exit 1 }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Error "node not found - install Node.js 18+"; exit 1 }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Error "python not found - install Python 3.9+"; exit 1 }

Write-Host "== Building Rust core =="
Set-Location "$RootDir\rust-core"
cargo build --release

Write-Host "== Installing Node gateway dependencies =="
Set-Location "$RootDir\node-server"
npm install
npm run build

Write-Host "== Setting up Python RAG service =="
Set-Location "$RootDir\python-service"
python -m venv venv
& ".\venv\Scripts\pip.exe" install --upgrade pip
& ".\venv\Scripts\pip.exe" install -r requirements.txt

Write-Host "== Installing React dashboard dependencies =="
Set-Location "$RootDir\web-ui"
npm install
npm run build

Write-Host ""
Write-Host "Setup complete. Next: .\scripts\windows\run_demo.ps1"
