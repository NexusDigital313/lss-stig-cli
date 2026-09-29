# Changelog

## 1.0.0 — 2026-09-29

First release. Canonical Ubuntu 24.04 LTS STIG, Version 1, Release 6
(benchmark date 01 Jul 2026).

### Coverage
- All 194 rules have an automated check (16 CAT I, 161 CAT II, 17 CAT III).
  Where the verdict is organizational, the evidence is collected and the
  rule is marked Not Reviewed.
- `harden` applies the automatic fixes it can make safely; `--skip`,
  `--rule`, `--cat` and `-i` (ask before each fix) narrow a run.
- Site values (`lss-stig site`) for the time source, audit collector,
  administrator email and an optional SSH management allow-list ahead of
  the ufw rate limit.

### Rollback
- Every change is journaled; `rollback --last`, `--run-id` or `--rule`
  undoes it.
- Packages that harden installed, including pulled-in dependencies, are
  purged on rollback.
- Harden and rollback keep running if the SSH session drops; rollback
  records each rule as it is undone, so a rerun skips finished rules.
- Package operations wait for the dpkg lock and are never killed.

### Licensing
- `harden --confirm` needs a license. Audit, checklists, `list`, `site`,
  `harden --dry-run` and `rollback` are free.
- Licenses are signed files verified on the host with no network access,
  optionally bound to host IDs and given an expiry date.

### Output
- DISA tool conventions: STIG Viewer status words (Open, Not a Finding,
  Not Reviewed, Not Applicable), CAT I (High) / CAT II (Medium) /
  CAT III (Low), plain ASCII and the eight standard terminal colors.
- STIG Viewer 3 (`.cklb`) checklist written by every audit.

### Packaging
- Offline artifacts for air-gapped hosts: a `.deb`, a single-file `.pyz`
  and `SHA256SUMS` (`tools/build_bundle.py`).

### Verified
- Full cycle on a clean Ubuntu 24.04.5 VM: audit, harden (104 fixes,
  0 errors), reboot, account lockout, rollback to the pre-harden package
  and unit state.
