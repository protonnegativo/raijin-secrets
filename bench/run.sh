#!/usr/bin/env bash
# Reproducible token benchmark: trufflehog output vs raijin-secrets output on the same local fixtures.
#
# usage: bench/run.sh [workdir]
# needs: go, git, trufflehog, python3 with tiktoken (pip install tiktoken)
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, TRUFFLEHOG=<path>
#
# Safety: the fixtures are local files and a local git repository that gen_fixtures.py fills with FAKE
# secrets (random strings from a fixed seed). trufflehog always runs with --no-verification, so no
# secret is sent to any provider, and --no-update, so it does not check for updates. Nothing leaves
# the machine.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
TRUFFLEHOG=${TRUFFLEHOG:-trufflehog}
mkdir -p "$W"
W=$(cd "$W" && pwd)
echo "workdir: $W"
echo "trufflehog: $("$TRUFFLEHOG" --version 2>&1)"

(cd "$ROOT" && go build -o "$W/raijin-secrets" ./cmd/raijin-secrets)

# Fixtures: the same files and the same commit hashes on every run (fixed seed, fixed git dates).
python3 "$HERE/gen_fixtures.py" "$W/src"
SRC=$W/src
echo "$SRC" > "$W/scope.txt"
th() { (cd "$SRC" && "$TRUFFLEHOG" "$@" --no-update --no-verification 2>/dev/null); }

# Scenarios:
#   noisy:    trufflehog filesystem on a project tree; most secrets are in vendored packages, test
#             fixtures and docs, copied many times; 4 are in the application's own config
#   findings: trufflehog git on a repository whose history adds, copies, rotates and deletes secrets
#   verified: SYNTHETIC. The findings run's JSON with Verified set to true on its AWS, Github, Stripe
#             (the first key) and Postgres results, and a VerificationError on its Slack results, to
#             exercise the verified and unknown paths without verifying anything. trufflehog never
#             wrote this file, so it has no text output row.
mkdir -p "$W/noisy" "$W/findings" "$W/verified"
th filesystem --json noisy > "$W/noisy/trufflehog.jsonl"
th filesystem --no-color noisy > "$W/noisy/trufflehog.txt"
th git --json "file://$SRC/findings" > "$W/findings/trufflehog.jsonl"
th git --no-color "file://$SRC/findings" > "$W/findings/trufflehog.txt"
python3 - "$W/findings/trufflehog.jsonl" "$W/verified/trufflehog.jsonl" <<'EOF'
import json, sys
first_stripe = None
with open(sys.argv[2], "w") as out:
    for line in open(sys.argv[1]):
        e = json.loads(line)
        if e["DetectorName"] == "Stripe" and first_stripe is None:
            first_stripe = e["Raw"]
        if e["DetectorName"] in ("AWS", "Github", "Postgres") or e["Raw"] == first_stripe:
            e["Verified"] = True
        if e["DetectorName"] == "Slack":
            e["VerificationError"] = "synthetic: verification timed out"
        out.write(json.dumps(e, separators=(",", ":")) + "\n")
EOF

# The live path gives the same findings and groups as the replay below (trufflehog's output order
# changes between runs; the reducer's does not).
(cd "$SRC" && "$W/raijin-secrets" --scope "$W/scope.txt" --raw "$W/noisy/live.raw.jsonl" -p noisy > "$W/noisy/live.json")
(cd "$SRC" && "$W/raijin-secrets" --scope "$W/scope.txt" --raw "$W/findings/live.raw.jsonl" -g findings > "$W/findings/live.json")

scenario() {
  local name=$1 o=$W/$1
  # raijin-secrets replays the saved trufflehog JSON with --input, from the fixtures' directory so it
  # can read the context lines, so every row sees the same results.
  (cd "$SRC" && "$W/raijin-secrets" --scope "$W/scope.txt" --input "../$name/trufflehog.jsonl") > "$o/raijin.json"
  (cd "$SRC" && "$W/raijin-secrets" --scope "$W/scope.txt" --input "../$name/trufflehog.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$SRC" && "$W/raijin-secrets" --scope "$W/scope.txt" --input "../$name/trufflehog.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$o/trufflehog.jsonl" "$o/raijin.json"
  if [ -f "$o/live.json" ]; then
    python3 -c 'import json,sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
same = a["findings"] == b["findings"] and a["groups"] == b["groups"]
print("live run == replay:", same)
sys.exit(0 if same else 1)' "$o/live.json" "$o/raijin.json"
  fi
  local rows=("trufflehog --json=$o/trufflehog.jsonl")
  [ -f "$o/trufflehog.txt" ] && rows+=("trufflehog text=$o/trufflehog.txt")
  "$PY" "$HERE/count_tokens.py" "${rows[@]}" \
    "raijin-secrets JSON (default)=$o/raijin.json" \
    "raijin-secrets --pretty=$o/raijin_pretty.json" \
    "raijin-secrets --format table=$o/raijin_table.txt"
}

for s in noisy findings verified; do scenario "$s"; done
