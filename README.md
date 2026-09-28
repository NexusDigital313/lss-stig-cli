# LSS STIG

`lss-stig` audits, hardens and rolls back Linux hosts against **DISA STIGs**, and
writes a **STIG Viewer 3 checklist (`.cklb`)** from every audit.

It is the STIG edition of The Linux Security Suite. LSS targets the CIS Benchmark;
lss-stig targets DISA STIGs — separate package (`lss_stig`), command (`lss-stig`),
state (`/var/log/lss-stig/`, backups in `/var/lib/lss-stig/`) and SSH drop-in (`00-lss-stig.conf`), so both can be
installed on the same host without touching each other.

## Supported benchmarks

| Benchmark | Release | Rules | Automated |
|---|---|---|---|
| Canonical Ubuntu 24.04 LTS STIG | V1R6 (01 Jul 2026) | 194 (16 CAT I · 161 CAT II · 17 CAT III) | all 194 |

The rule catalog is imported verbatim from DISA's XCCDF, so IDs, severities and
check/fix text match the published STIG exactly. Every rule has an automated
check; where the verdict is organizational (who belongs in `sudo`, the PPSM CLSA)
the evidence is collected and the rule is marked for review.

## Site values

A few rules can only pass against *your* infrastructure. Set them once:

```bash
sudo lss-stig site time_server=<DOD NTP server> \
                   audit_remote_server=<audit collector> \
                   admin_email=<SA/ISSO address>
lss-stig site                                   # show current values
```

Until a value is set, the rules that need it (V-270751, V-270658, V-270818/819)
stay open with the exact command to run — nothing is guessed.

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
sudo lss-stig harden --confirm --skip V-270655   # leave rules out (any ID form)
sudo lss-stig rollback --last           # undo the last harden run
sudo lss-stig checklist -o host.cklb    # rebuild a checklist from the last audit
lss-stig list [--cat I] [--automated]
```

Audit exits `1` when any finding is open, `0` otherwise. Add `-v` to list
passing and not-applicable rules too.

`--theme dod` (or `LSS_STIG_THEME=dod`) switches to DISA-tool conventions:
the 8 standard terminal colors only, no banner art, STIG Viewer status words
(Open, Not a Finding, Not Reviewed, Not Applicable) and CAT I (High) style
severities. `--no-color` and piped output are plain text in either theme.

## License

`harden --confirm` needs a license. Everything else is free without one:
audit, checklists, `list`, `site`, `harden --dry-run` and `rollback`, so a
host can always be undone even after its license lapses.

A license is a signed file checked locally, with no network access, so it
works on air-gapped hosts. It can be issued for specific hosts and can
carry an expiry date.

```bash
lss-stig license id                     # this host's ID, to send for a host-bound license
sudo lss-stig license install host.lic  # install it (/etc/lss-stig/license.lic)
sudo lss-stig license                   # show the license state
sudo lss-stig license remove
```

Without a license, `harden --confirm` exits `3`.

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

### Where DISA's own text is wrong or dangerous

lss-stig implements what each rule's **check** verifies, and never applies a fix
text that would damage the host:

| Rule | DISA text | lss-stig |
|---|---|---|
| V-270824 | `chmod -R 755` on command directories | strips setuid from `sudo`, `su`, `passwd` — only the directory's write bits are removed |
| V-270701 | `chmod 755` on writable commands | would drop setuid/setgid — only `go-w` is removed |
| V-270678 | fix sets `idle-delay=900`, `lock-delay=600` | fails DISA's own check (≤600, 0) — the check's values are used |
| V-270679, V-274872, V-274873 | lock the GNOME setting | GNOME defaults are automount on / autorun allowed / removal does nothing; locking alone freezes them — the secure value is set, then locked |
| V-270655 | `ufw enable` | would lock out a remote admin — SSH ports get `ufw limit` first |
| V-270758 | `chmod 740 journalctl` | reverted by the next systemd update — held with `dpkg-statoverride` |
| V-270757 vs V-270762 | journal dirs `0640` / journal files group `systemd-journal` | `0640` clears the setgid bit journald relies on, so every rotated file becomes `root:root` — journald also gets `Group=systemd-journal` |
| V-270649 | install `aide` | `aide.conf` is in `aide-common`, only a *Recommends* — both are installed, without the mailer aide-common recommends |
| V-270651 vs V-270831 | aide.conf must equal the package default / must add audit-tool lines | can't both hold — reported as *review* when that is the only difference |
| V-270731 | "less than 60 is a finding" | typo for a 60-day maximum — set to exactly 60, which passes either reading |
| V-270690 | add faillock lines "below pam_unix" | shifts Ubuntu's `success=N` jumps — with pam_sss a good login lands on `pam_deny`. Jumps are recomputed; the tally lives in `/var/lib/faillock` because the default tmpfs dir unlocks everyone at reboot |
| V-270645 | purge systemd-timesyncd | a host with no time daemon drifts — chrony is installed first; `rc` config remnants count as present, as DISA's `dpkg -l` grep sees them |
| V-270818 | `space_left_action = email` | with no mail transfer agent that alerts nobody — falls back to an `exec` notifier (syslog alert + wall + mail if possible) |
| V-270658, V-270819 | `systemctl restart auditd` | Ubuntu refuses it — auditd is reloaded with SIGHUP |
| V-274868, V-270707, V-274869 | remove NOPASSWD / `!authenticate` / `ALL ALL` | check-only: cloud images' default user has NOPASSWD and no password, so removing it deletes the only admin path |

Also checked beyond the letter of the rule: audit rules must be **loaded** (not
just present in `rules.d`); `-e 2` is compiled but takes effect at next boot so it
can't lock out rules added later in the same run; existing yescrypt password
hashes are counted (switching PAM to sha512 only affects passwords set afterwards).

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

### Issuing licenses (vendor)

```bash
tools/issue_license.py issue --key ~/lss-stig-signing.key \
    --licensee "Example Program Office" --tier Enclave \
    --host 1A2B-3C4D-5E6F-7A8B --expires 2027-09-30 --out example.lic
```

Omit `--host` for a site license, and `--expires` for a perpetual one. The
signing key must match `OFFLINE_PUBLIC_KEY` in `lss_stig/lib/license.py`.
It never goes in this repository. To replace it, run
`tools/issue_license.py keygen --out FILE` and put the printed public key
into `license.py`; licenses signed with the old key then stop verifying.
