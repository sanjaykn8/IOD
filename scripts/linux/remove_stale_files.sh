#!/usr/bin/env bash
# Removes files that existed before the patch-wise redesign (see scripts/windows/remove_stale_files.ps1
# for why: unzipping a release over an older copy never deletes files). Safe to run repeatedly.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STALE=(
  docs/benchmark-results-stego-host-simulation.txt docs/benchmark-results-stego-natural-cover.json docs/rag.md
  docs/samples/learning-comparison-all-ten.csv docs/samples/learning-comparison-all-ten.json
  docs/samples/learning-comparison-all-ten.md docs/samples/learning-synthetic-bw-cover.md
  docs/stego-implementation-note.md docs/stego-transport.md
  node-server/src/services/pythonClient.ts
  python-service/src/llm python-service/src/rag python-service/src/state.py python-service/src/stego/selector.py
  python-service/tests/test_fusion.py python-service/tests/test_mock_llm.py python-service/tests/test_rag_explain.py
  python-service/tests/test_retrieval.py python-service/tests/test_stego_algorithms.py python-service/tests/test_stego_bootstrap.py
  python-service/tests/test_stego_boundaries.py python-service/tests/test_stego_new_algorithms.py
  python-service/tests/test_stego_selector.py python-service/tests/test_stego_service_api.py python-service/tests/test_validation.py
  rust-core/src/transport/explain.rs
  web-ui/src/pages/RagPage.tsx web-ui/src/routes/rag.tsx
  web-ui/tsconfig.tsbuildinfo web-ui/.tanstack web-ui/.output web-ui/.wrangler node-server/dist
)
removed=0
for rel in "${STALE[@]}"; do
  if [ -e "$ROOT_DIR/$rel" ]; then rm -rf "${ROOT_DIR:?}/$rel"; echo "removed $rel"; removed=$((removed+1)); fi
done
echo "Stale-file cleanup: $removed path(s) removed."
