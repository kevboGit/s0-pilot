#!/usr/bin/env bash
# PREPARATION HELPER (synthetic only). Builds a SYNTHETIC Job-A-shaped submission
# (submission.json + a source/**-only patch.diff) and runs the REAL, UNMODIFIED S0-a
# validate-submission.py against it, proving Job A's artifact FORMAT is consumable by the
# existing verifier WITHOUT changing any verification component and WITHOUT executing Claude
# Code or any candidate. No network, no creds, no agent, no candidate, no model call.
#
# Usage: jobA-format-check.sh [path-to-validate-submission.py]
#   default validator: ../s0-truth/validation/validate-submission.py relative to the repo root
#   (i.e. $script_dir/../../s0-truth/... — a sibling checkout of s0-truth)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
VALIDATOR="${1:-$HERE/../../s0-truth/validation/validate-submission.py}"
[ -f "$VALIDATOR" ] || {
	echo "SKIP: validator not found at $VALIDATOR (pass its path as arg 1)"
	exit 3
}

D=$(mktemp -d "${TMPDIR:-/tmp}/jobAfmt.XXXX")
trap 'rm -rf "$D"' EXIT

# Synthetic C1-shaped submission (format only; the validator never applies the patch).
BASE=$(printf 'a%.0s' $(seq 1 40)) # synthetic 40-hex base; format check only
cat >"$D/submission.json" <<JSON
{"schema":"s0.submission/v1","task":"C1","attempt":1,"base":"$BASE","patch":"patch.diff"}
JSON
cat >"$D/patch.diff" <<'DIFF'
diff --git a/source/index.ts b/source/index.ts
index 1111111..2222222 100644
--- a/source/index.ts
+++ b/source/index.ts
@@ -1 +1,2 @@
 const x = 1;
+const y = 2;
DIFF

set +e
OUT=$(python3 -I "$VALIDATOR" "$D" 2>&1)
RC=$?
set -e
echo "validator output (rc=$RC): $OUT"
# The validator's exit status matches ok; require BOTH rc==0 AND the ok:true line so a validator
# that errors while incidentally printing the substring cannot false-PASS.
if [ "$RC" = 0 ] && printf '%s' "$OUT" | grep -q '"ok": true'; then
	echo "PASS: synthetic Job-A submission accepted by the real validator (format compatible)"
	exit 0
fi
echo "FAIL: synthetic Job-A submission REJECTED — format incompatible"
exit 1
