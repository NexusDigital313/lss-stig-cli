# LSS STIG

`lss-stig` audits, hardens and rolls back Linux hosts against **DISA STIGs**, and
writes a **STIG Viewer 3 checklist (`.cklb`)** from every audit.

It is the STIG edition of The Linux Security Suite. LSS targets the CIS Benchmark;
lss-stig targets DISA STIGs — separate package (`lss_stig`), command (`lss-stig`),
state (`/var/log/lss-stig/`) and SSH drop-in (`00-lss-stig.conf`), so both can be
installed on the same host without touching each other.

## Supported benchmarks

| Benchmark | Release | Rules | Automated |
|---|---|---|---|
| Canonical Ubuntu 24.04 LTS STIG | V1R6 (01 Jul 2026) | 194 (16 CAT I · 161 CAT II · 17 CAT III) | all 16 CAT I |

The rule catalog is imported verbatim from DISA's XCCDF, so IDs, severities and
check/fix text match the published STIG exactly. Rules without an automated check
still appear in every audit and checklist as **Not Reviewed** — the checklist is
always complete.

## Install

No third-party dependencies (built for air-gapped hosts). Python ≥ 3.10.

```bash
pip install .            # or: pipx install .
```

## Use

```bash
sudo lss-stig audit                     # read-only; writes ~/.local/share/lss-stig/checklists/*.cklb
sudo lss-stig audit --cat I             # CAT I only
sudo lss-stig audit --rule V-270708     # any ID form: V-ID, UBTU-24-xxxxxx, SV-…_rule
sudo lss-stig harden --dry-run          # what would change
sudo lss-stig harden --confirm [-i]     # apply (every change journaled)
sudo lss-stig rollback --last           # undo the last harden run
sudo lss-stig checklist -o host.cklb    # rebuild a checklist from the last audit
lss-stig list [--cat I] [--automated]
```

Audit exits `1` when any finding is open, `0` otherwise.

### Result statuses

| lss-stig | CKLB | Meaning |
|---|---|---|
| ✓ pass | Not a Finding | requirement met |
| ✗ fail | Open | not met; `harden` can fix it |
| ◐ manual | Open | not met; needs an operator decision (FIPS, GRUB password, PKI) |
| ? review | Not Reviewed | evidence collected; the verdict is organizational (e.g. who belongs in `sudo`) |
| - na | Not Applicable | doesn't apply to this host (e.g. no GNOME) |
| · | Not Reviewed | no automated check yet |

Evidence for every automated check (the lines, values and command output it
looked at) is written to the checklist's *Finding Details*.

## What it checks beyond the STIG text

- **SSH conflicts.** The assessor greps every `sshd_config*` file; a stray
  `X11Forwarding yes` in `50-cloud-init.conf` is a finding even when `sshd -T` says
  `no`. lss-stig checks both, and the fix comments conflicting lines out (backed up)
  instead of only adding a drop-in. `sshd -t` must pass or every file is reverted.
- **Ubuntu 24.04 socket-activated SSH** fails V-270666 as written. It's reported
  with the exact commands instead of being switched over remotely.
- **dconf settings that never took effect** — keyfile written but `dconf update`
  not run, or the profile doesn't read `system-db:local`.
- **GRUB password (V-270675)** — DISA's fix alone makes GRUB prompt on every boot
  unless normal entries are `--unrestricted`; test a reboot before leaving it.

## New STIG release

```bash
python3 tools/import_xccdf.py U_CAN_Ubuntu_24-04_LTS_V1R7_Manual-xccdf.xml \
    lss_stig/benchmarks/ubuntu2404_v1r7.json
```

then review the diff against the previous catalog and move the controls over.

## Development

```bash
python3 -m unittest discover -s tests
```
