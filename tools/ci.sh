#!/usr/bin/env bash
# Everything CI checks, runnable locally: bash tools/ci.sh
# Fails if any implementation disagrees, a generated file drifted from its source, or a test fails.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== reference implementations vs golden vectors"
python3 spec/ref/check_vectors.py
node spec/ref/check_vectors.mjs

echo "== golden vectors are exactly what the generator produces"
(cd spec && python3 tools/gen_vectors.py >/dev/null)
git diff --exit-code -- spec/vectors || { echo "spec/vectors drifted from spec/tools/gen_vectors.py"; exit 1; }

echo "== bin/verify.py is exactly the bundle of gpcanon/"
python3 tools/bundle_verify.py >/dev/null
git diff --exit-code -- bin/verify.py || { echo "bin/verify.py is stale: run tools/bundle_verify.py and commit"; exit 1; }

echo "== verifier stays stdlib-only"
if grep -nE "^\s*(import|from)\s+(cryptography|nacl|requests)" bin/verify.py gpcanon/canon.py gpcanon/schema.py gpcanon/ed25519_verify.py gpcanon/verify.py; then
  echo "the verifier side must not import third-party packages"; exit 1
fi

echo "== tests"
python3 -m pytest test/ -q
