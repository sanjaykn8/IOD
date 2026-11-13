# Removes files that existed before the patch-wise redesign and no longer belong to the project.
# Needed when the new release was extracted OVER an older copy: unzip adds and replaces files but
# never deletes, so old modules (e.g. src/routes/rag.tsx, src/services/pythonClient.ts) would still
# be picked up by the TypeScript build, the TanStack route generator and pytest.
# Safe to run repeatedly; it only touches the exact paths listed below.
$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path

$Stale = @(
  "docs\benchmark-results-stego-host-simulation.txt",
  "docs\benchmark-results-stego-natural-cover.json",
  "docs\rag.md",
  "docs\samples\learning-comparison-all-ten.csv",
  "docs\samples\learning-comparison-all-ten.json",
  "docs\samples\learning-comparison-all-ten.md",
  "docs\samples\learning-synthetic-bw-cover.md",
  "docs\stego-implementation-note.md",
  "docs\stego-transport.md",
  "node-server\src\services\pythonClient.ts",
  "python-service\src\llm",
  "python-service\src\rag",
  "python-service\src\state.py",
  "python-service\src\stego\selector.py",
  "python-service\tests\test_fusion.py",
  "python-service\tests\test_mock_llm.py",
  "python-service\tests\test_rag_explain.py",
  "python-service\tests\test_retrieval.py",
  "python-service\tests\test_stego_algorithms.py",
  "python-service\tests\test_stego_bootstrap.py",
  "python-service\tests\test_stego_boundaries.py",
  "python-service\tests\test_stego_new_algorithms.py",
  "python-service\tests\test_stego_selector.py",
  "python-service\tests\test_stego_service_api.py",
  "python-service\tests\test_validation.py",
  "rust-core\src\transport\explain.rs",
  "web-ui\src\pages\RagPage.tsx",
  "web-ui\src\routes\rag.tsx",
  # stale build state that still refers to the removed modules
  "web-ui\tsconfig.tsbuildinfo",
  "web-ui\.tanstack",
  "web-ui\.output",
  "web-ui\.wrangler",
  "node-server\dist"
)

$removed = 0
foreach ($rel in $Stale) {
  $p = Join-Path $RootDir $rel
  if (Test-Path -LiteralPath $p) {
    Remove-Item -LiteralPath $p -Recurse -Force
    Write-Host "removed $rel"
    $removed++
  }
}
Write-Host "Stale-file cleanup: $removed path(s) removed."
