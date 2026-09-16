$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

Write-Host "== Rust: unit + integration + security-negative tests =="
Set-Location "$RootDir\rust-core"; cargo test

Write-Host ""
Write-Host "== Python: RAG pipeline unit tests =="
Set-Location "$RootDir\python-service"; & ".\venv\Scripts\python.exe" -m pytest tests\ -v

Write-Host ""
Write-Host "== React: type-check + production build =="
Set-Location "$RootDir\web-ui"; npx tsc -b; npx vite build

Write-Host ""
Write-Host "All test suites passed."
