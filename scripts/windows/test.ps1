$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

Write-Host "== Rust: unit + integration + security-negative tests =="
Set-Location "$RootDir\rust-core"; cargo test

Write-Host ""
Write-Host "== Python: RAG + steganography unit/integration tests =="
Set-Location "$RootDir\python-service"; & ".\venv\Scripts\python.exe" -m pytest tests\ -v

Write-Host ""
Write-Host "== Standalone steganography project tests (compat wrappers) =="
Set-Location "$RootDir\tools\stego-standalone"; & "$RootDir\python-service\venv\Scripts\python.exe" -m unittest test_latent_image -v

Write-Host ""
Write-Host "== React: type-check + production build =="
Set-Location "$RootDir\web-ui"; npx tsc -b; npx vite build

Write-Host ""
Write-Host "All test suites passed."
