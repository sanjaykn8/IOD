$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

Write-Host "== Rust core =="
Set-Location "$RootDir\rust-core"; cargo build --release

Write-Host "== Node gateway =="
Set-Location "$RootDir\node-server"; npm run build

Write-Host "== React dashboard =="
Set-Location "$RootDir\web-ui"; npm run build

Write-Host "Build complete."
