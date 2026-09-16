# One-command demo launch: starts the Rust core, Python RAG service, and
# Node gateway (in that dependency order, with short delays). Run
# scripts\windows\setup.ps1 first if you haven't already. Leaves all
# three services running as background processes; use stop_demo.ps1 to
# stop them.
#
# NOTE: Start-Process has NO -Environment parameter in either Windows
# PowerShell 5.1 or PowerShell 7+ (an earlier draft of this script
# incorrectly assumed one existed). The correct way to pass environment
# variables to a child process here is to set $env:VARNAME in the
# current session before calling Start-Process -- the child inherits
# the parent's environment block automatically.
$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path
$PidDir = "$RootDir\.demo-pids"
New-Item -ItemType Directory -Force -Path $PidDir | Out-Null

$DbPath = if ($env:IOD_DB_PATH) { $env:IOD_DB_PATH } else { "$RootDir\iod_simulation.db" }
$BindAddr = if ($env:IOD_BIND_ADDR) { $env:IOD_BIND_ADDR } else { "127.0.0.1:8787" }
$PyPort = if ($env:IOD_PYTHON_PORT) { $env:IOD_PYTHON_PORT } else { "5001" }
$NodePort = if ($env:IOD_NODE_PORT) { $env:IOD_NODE_PORT } else { "4000" }

Write-Host "== Starting Rust core (iod-server) on $BindAddr, db=$DbPath =="
$env:IOD_DB_PATH = $DbPath
$env:IOD_BIND_ADDR = $BindAddr
$rustProc = Start-Process -FilePath "$RootDir\rust-core\target\release\iod-server.exe" `
    -WorkingDirectory "$RootDir\rust-core" -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$RootDir\.demo-rust.log" -RedirectStandardError "$RootDir\.demo-rust.err.log"
$rustProc.Id | Out-File "$PidDir\rust.pid"
Start-Sleep -Seconds 1

Write-Host "== Starting Python RAG service on 127.0.0.1:$PyPort =="
$env:IOD_PYTHON_PORT = $PyPort
$pyProc = Start-Process -FilePath "$RootDir\python-service\venv\Scripts\python.exe" -ArgumentList "src\app.py" `
    -WorkingDirectory "$RootDir\python-service" -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$RootDir\.demo-python.log" -RedirectStandardError "$RootDir\.demo-python.err.log"
$pyProc.Id | Out-File "$PidDir\python.pid"
Start-Sleep -Seconds 1

Write-Host "== Starting Node gateway on 127.0.0.1:$NodePort =="
$env:IOD_NODE_PORT = $NodePort
$env:IOD_RUST_BASE_URL = "http://$BindAddr"
$env:IOD_PYTHON_BASE_URL = "http://127.0.0.1:$PyPort"
$nodeProc = Start-Process -FilePath "node" -ArgumentList "dist\index.js" `
    -WorkingDirectory "$RootDir\node-server" -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$RootDir\.demo-node.log" -RedirectStandardError "$RootDir\.demo-node.err.log"
$nodeProc.Id | Out-File "$PidDir\node.pid"
Start-Sleep -Seconds 1

Write-Host ""
Write-Host "All backend services started. PIDs recorded in $PidDir\"
Write-Host "Logs: $RootDir\.demo-{rust,python,node}.log"
Write-Host ""
Write-Host "Now start the dashboard:"
Write-Host "  cd $RootDir\web-ui; npm run dev"
Write-Host "Then open http://127.0.0.1:5173"
Write-Host ""
Write-Host "Stop all backend services with: .\scripts\windows\stop_demo.ps1"
