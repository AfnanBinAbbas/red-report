#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/checkpoint.sh"

parse_common_args "$@"
init_workspace

REPORT="$WS/report"
mkdir -p "$REPORT"

python3 - "$WS" "$TARGET" <<'PY'
import json, re, sys, os, glob
from datetime import datetime, timezone
ws, target = sys.argv[1], sys.argv[2]

findings = []
fid = 0
raw = os.path.join(ws, "exploit", "findings-raw.md")
if os.path.exists(raw):
    text = open(raw, errors="ignore").read()
    for m in re.finditer(r"\*\*(.+?)\*\*\s*(.*)", text):
        title, rest = m.group(1).strip(), m.group(2).strip()
        fid += 1
        sev = "High"
        low = title.lower()
        if any(k in low for k in ("pii", "idor", "rce", "upload rce", "command")): sev = "Critical"
        elif any(k in low for k in ("lfi", "exposure", "secret", "actuator", "dump")): sev = "High"
        elif any(k in low for k in ("candidate", "possible", "info")): sev = "Medium"
        elif any(k in low for k in ("negative", "soft404")): sev = "Info"
        findings.append({
            "id": f"F-{fid:03d}",
            "title": title,
            "severity": sev,
            "cvss": "",
            "cwe": "",
            "location": target,
            "evidence": [rest[:500]] if rest else [],
            "impact": "",
            "repro": "",
            "remediation": "",
            "status": "unproven"
        })

for d in glob.glob(os.path.join(ws, "loot", "dbdump", "FULL-*.sql")):
    fid += 1
    findings.append({
        "id": f"F-{fid:03d}",
        "title": f"SQL dump achieved: {os.path.basename(d)}",
        "severity": "Critical", "cvss": "", "cwe": "CWE-200",
        "location": target, "evidence": [f"{d} ({os.path.getsize(d)}B)"],
        "impact": "full table extract", "repro": "", "remediation": "",
        "status": "confirmed"
    })

for pat, title in (("loot/idor_record_*.html", "IDOR record read"), ("loot/pii_emails.txt", "PII email harvest"), ("loot/log_*.txt", "log exposure")):
    hits = glob.glob(os.path.join(ws, pat))
    hits = [h for h in hits if os.path.getsize(h) > 0]
    if hits:
        fid += 1
        findings.append({
            "id": f"F-{fid:03d}",
            "title": f"{title} ({len(hits)} files)",
            "severity": "Critical" if "idor" in pat or "pii" in pat else "High",
            "cvss": "", "cwe": "CWE-639" if "idor" in pat else "CWE-200",
            "location": target, "evidence": hits[:5],
            "impact": "", "repro": "", "remediation": "", "status": "unproven"
        })

out = {
    "engagement": target,
    "phase": "validate",
    "generated": datetime.now(timezone.utc).isoformat(),
    "findings": findings
}
oj = os.path.join(ws, "report", "findings.json")
json.dump(out, open(oj, "w"), indent=2)

required = {"id","title","severity","cwe","location","evidence","impact","repro","remediation","status"}
errors = []
for f in findings:
    missing = required - set(f)
    if missing: errors.append(f"{f.get('id','?')} missing {sorted(missing)}")
    if f["status"] not in ("confirmed","unproven"): errors.append(f"{f['id']} bad status")
    if f["severity"] not in ("Critical","High","Medium","Low","Info"): errors.append(f"{f['id']} bad severity")

md = [f"# Report — {target}", "", f"Generated: {out['generated']}", "", "## Findings", ""]
for f in findings:
    md.append(f"### {f['id']} — {f['title']}")
    md.append(f"- Severity: {f['severity']} | Status: {f['status']}")
    if f["evidence"]: md.append(f"- Evidence: {f['evidence'][0]}")
    md.append(f"- Repro: {'(fill from findings-raw.md)' if not f['repro'] else f['repro']}")
    md.append("")
md += ["## Validation checklist", "- [ ] every finding re-reproduced standalone",
       "- [ ] impact proved (data row / command output), not just status-code diff",
       "- [ ] unproven items flagged Low", ""]
open(os.path.join(ws, "report", "report.md"), "w").write("\n".join(md))

print(f"findings.json: {len(findings)} findings, schema errors: {len(errors)}")
for e in errors: print("  ERR", e)
sys.exit(0)
PY

mark_phase_done report
log "report: report/findings.json + report/report.md (AI: fill repro/remediation, validate)"
