# CSC3106 Mini-Project - Authentication Log Analysis and Defensive Response

This folder contains the reproducibility package for both parts of the mini-project: the Part 1 analysis script, the Part 2 detection/response script, their generated outputs, and this README.

## Files

```
README.md
analysis.py                 # Part 1: parses the log, produces evidence tables/figures
detect_and_respond.py       # Part 2: detection logic + generated blocking rules (imports analysis.py)
2_auth.log                  # assigned raw log extract
output/
  unmatched_lines.csv       # log lines that did not match any known template
  tables/
    top_source_ips_failed.csv
    top_targeted_usernames.csv
    failed_attempts_by_day.csv
    accepted_logins_by_user.csv
    accepted_logins_by_ip.csv
    accounts_targeted_and_later_accepted.csv
    max_auth_exceeded_by_ip.csv
    preauth_connections_closed_by_ip.csv
    sudo_commands_by_user.csv
    alerts.csv               # Part 2: CRITICAL/HIGH alerts
  figures/
    top_source_ips_failed.png
    top_targeted_usernames.png
    failed_attempts_by_day.png
  response/
    fail2ban_filter.conf     # Part 2: detection rule for fail2ban
    fail2ban_jail.local      # Part 2: jail applying the filter, pre-seeded with flagged IPs
    blocklist_iptables.sh    # Part 2: fallback firewall rules
```

## Requirements

- Python 3.9 or later
- `pandas`
- `matplotlib` (only needed for analysis.py)

Install with:

```bash
pip install pandas matplotlib
```

`detect_and_respond.py` needs only `pandas` (it imports `parse_log` and `build_dataframe` from `analysis.py` rather than re-parsing the log itself, so it must be run from the same folder as `analysis.py`).

## How to run

From this folder, with `2_auth.log` present:

```bash
python analysis.py --input 2_auth.log --outdir output
python detect_and_respond.py --input 2_auth.log --outdir output
```

Run `analysis.py` first, `detect_and_respond.py` reuses its parsing code but does not depend on its output files, so the two can technically run in either order, but keeping this order matches the report's narrative (Part 1 findings, then Part 2 response built on them).

Arguments (same for both scripts):
- `--input` - path to the raw auth.log extract (default: `2_auth.log`)
- `--outdir` - directory to write tables/figures/response files into (default: `output`)

Both scripts print a console summary and (re)generate their outputs. Re-running is safe — files are overwritten each time, so the output always reflects the current version of `2_auth.log`.

## Input format expected

Syslog-style lines of the form:

```
<Mon> <DD> <HH:MM:SS> <host> <process>[<pid>]: <message>
```

e.g.

```
Jul 06 00:02:36 db01 sshd[3907]: Failed password for backup from 198.51.100.60 port 38701 ssh2
```

The scripts recognise `sshd`, `sudo`, and `CRON` message bodies matching the templates listed in `analysis.py` (failed/accepted password, invalid user, max-auth-exceeded, preauth connection closed, pam session open/close, sudo command lines).

## Key assumptions and decisions

### Part 1 (analysis.py)

1. **Defining a "failed authentication attempt."**
OpenSSH logs a dedicated `Failed password for <user> from <ip> port <port> ssh2` line for every rejected password (for both real and non-existent usernames), and separately logs a one-off `Invalid user <user> from <ip> port <port>` line the first time it sees an unrecognised account on a connection. In this extract, PIDs are reused across the week (small PID space relative to ~12,000 events), so an `Invalid user` line cannot be reliably paired back to its matching `Failed password for invalid user` line by PID. To avoid double-counting the same rejected attempt, **only `Failed password for ...` lines are counted as failed authentication attempts**; `Invalid user` announce lines are tracked separately.

2. **Username and source IP extraction.**
Pulled directly from the regex capture groups on the `Failed password for [invalid user] <user> from <ip> port <port> ssh2` and `Accepted password for <user> from <ip> port <port> ssh2` templates. Usernames from invalid-user failures are attacker-supplied free text and are not validated against any known account list.

3. **No year in the timestamps.**
The log uses syslog-style `Mon DD HH:MM:SS` timestamps with no year. The script assigns a fixed placeholder year (2026) purely so timestamps can be parsed and sorted for the time-series chart; the year has no evidentiary meaning and will not be quoted in the report as only relative day-to-day patterns should be drawn from `failed_attempts_by_day.png`.

4. **Unmatched / ambiguous lines are not discarded silently.**
Any line whose message body doesn't match a known template is written verbatim with its line number to `output/unmatched_lines.csv` for manual review. On the assigned extract this file is currently empty (all 12,000 lines matched a known template), which is itself worth noting as a characteristic of this synthetic dataset.

5. **Accounts flagged as higher-priority evidence.**
All six accounts that ever had a successful login (`alice`, `ops`, `backup`, `mei`, `dinesh`, `postgres`) were also targeted by failed password attempts at some point in the extract (`accounts_targeted_and_later_accepted.csv`). This overlap is presented as supporting evidence only, as it does not by itself prove a successful compromise, since the failed and accepted attempts may originate from different, unrelated source IPs.

### Part 2 (detect_and_respond.py)

6. **Why the detection rule is based on "invalid user" behaviour, not attempt count.**
The first version of this detector flagged any source IP with 3+ failed attempts against a username shortly before a success from that IP. Run against this extract it produced 404 alerts, because several ordinary source IPs occasionally mistype a password 3+ times for one of the 6 real accounts before logging in correctly, a same-user-only rule mostly caught normal typo behaviour, not attacks. The extract has a cleaner, purely behavioural signal instead: exactly 8 source IPs ever produce a `Failed password for invalid user ...` event, i.e. they guess at least one username that does not exist on the host (`admin`, `mysql`, `oracle`, `root`, `test`). No ordinary user ever attempts a non-existent account, so **"has guessed at least one invalid username" is used to separate dictionary/scanning attackers from normal login noise**, without hardcoding any IP ranges.

8. **Alert severities.** A **CRITICAL** alert fires when a dictionary-attacking IP (per point 6) also achieved a successful login for one of the real accounts it targeted on this extract (exactly one: `203.0.113.48 -> postgres`). A **HIGH** alert fires for the remaining dictionary-attacking IPs that have not yet succeeded(7 on this extract). Alert evidence (prior failed attempts, timing) is written to `output/tables/alerts.csv`.

9. **Response rules are generated, not just recommended.** For every flagged IP, the script writes a fail2ban filter + jail pair and a plain iptables fallback script under `output/response/`, so each alert produces a directly deployable artifact rather than only a report line.

## Limitations

- The extract has no year and no evidence of log rotation/gaps, so coverage completeness (i.e. whether any events were dropped before this extract was taken) cannot be verified from the file alone.
- PID reuse (see point 1 above) means per-connection event correlation (e.g. linking a specific `Invalid user` line to the exact `Failed password` line it produced) is not possible with the fields available in this log format; all counts are therefore at the line/event level, not the connection level.
- The script does not attempt geolocation, reverse DNS, or threat-intel lookups on source IPs.
- The Part 2 detector depends on attackers guessing at least one non-existent username; an attacker with an accurate account list who only guesses real usernames would not trigger this signal and would need a different (e.g. velocity-based) detection rule.
- `detect_and_respond.py` runs in batch/offline mode against a static extract, not as a real-time log-tailing service; only the generated fail2ban filter runs in real time once deployed.
