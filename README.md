# red-report

Phase 6 — aggregates `report/findings.json` (playbook schema) + `report/report.md`
skeleton from findings-raw + loot markers. Validates schema fields (id, severity,
cwe, evidence, status) and prints errors.

```bash
./phases/06-report.sh --target host --ws ~/redteam-runs/<target>/<ts>
```

AI fills repro/remediation/CVSS and runs the validation checklist afterward.
Authorized targets only.
