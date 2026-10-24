"""Checks that every trufflehog result is in a raijin-secrets result, and that no secret value leaked.

The engine output is trufflehog's JSON (one result per line; the `raw` file raijin-secrets saves, or
`trufflehog ... --json` output). A result is the triple

  (detector, SHA-256 of the secret, location)

plus its verification status. The secret is RawV2 when trufflehog sets it, Raw otherwise. The location
is "file:line" for a filesystem result and "commit:file:line" for a git result (the commit cut to 12
hex digits, the repository first when there is more than one), with " [DECODER]" when it is not PLAIN.
It is present when a finding or group has the detector (`title` or `detector`), an `id` that ends in
the first 8 hex digits of that SHA-256 (plus "-<status>" when the same secret has two statuses), the
same status (confidence "verified", status "unknown", or neither for unverified) and the location in
its `locations`.

It also checks that no Raw or RawV2 value appears anywhere in the raijin-secrets output.

usage: python verify.py <trufflehog.jsonl> <raijin.json>
"""
import hashlib
import json
import sys

raw, out = sys.argv[1], sys.argv[2]
text = open(out, encoding="utf-8").read()
o = json.loads(text)

entries = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        det = x.get("title") if kind == "findings" else x.get("detector")
        status = "verified" if x.get("confidence") == "verified" else x.get("status") or "unverified"
        prefix = det.lower() + "-"
        h = x["id"][len(prefix):len(prefix) + 8] if x["id"].startswith(prefix) else ""
        for loc in x.get("locations", []):
            entries.setdefault((det, h, status), set()).add(loc)

results = []
for line in open(raw, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if not isinstance(e, dict) or not e.get("DetectorName") or not (e.get("Raw") or e.get("RawV2")):
        continue
    results.append(e)


def meta(e):
    data = (e.get("SourceMetadata") or {}).get("Data") or {}
    for kind, d in data.items():
        return kind, d or {}
    return "", {}


repos = {meta(e)[1].get("repository") for e in results if meta(e)[1].get("commit")}


def location(e):
    _, d = meta(e)
    f, commit, ln = d.get("file") or d.get("path") or "", d.get("commit") or "", d.get("line") or 0
    if f:
        s = (commit[:12] + ":" if commit else "") + f + (f":{ln}" if ln > 0 else "")
    elif commit:
        s = commit[:12]
    else:
        s = d.get("link") or ""
    if len(repos) > 1 and commit and d.get("repository"):
        s = d["repository"] + " " + s
    dec = e.get("DecoderName") or ""
    if dec and dec != "PLAIN":
        s += f" [{dec}]"
    return s[:300]


triples, miss, leaked = set(), [], set()
for e in results:
    value = e.get("RawV2") or e["Raw"]
    h = hashlib.sha256(value.encode()).hexdigest()[:8]
    status = "verified" if e.get("Verified") else "unknown" if e.get("VerificationError") else "unverified"
    t = (e["DetectorName"], h, location(e), status)
    if t in triples:
        continue
    triples.add(t)
    if t[2] not in entries.get((t[0], t[1], t[3]), set()):
        miss.append(t)
    for v in (e.get("Raw"), e.get("RawV2")):
        if v and len(v) >= 6 and v in text:
            leaked.add(v[:4] + "...")

print(f"{len(results)} trufflehog results, {len(triples)} distinct (detector, secret hash, location) triples, "
      f"{len(miss)} missing from output, {len(leaked)} secret values leaked", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
for v in sorted(leaked)[:5]:
    print("  LEAKED", v)
sys.exit(1 if miss or leaked else 0)
