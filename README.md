# CSC3106 Mini-Project - Part 1: Authentication Log Analysis

This folder contains the reproducibility package for Part 1 (Data-Driven Authentication Log Analysis): the analysis script, its generated outputs, and this README.

## Files

```
README.md
analysis.py
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
  figures/
    top_source_ips_failed.png
    top_targeted_usernames.png
    failed_attempts_by_day.png
```

## Requirements

- Python 3.9 or later
- `pandas`
- `matplotlib`

Install with:

```bash
pip install pandas matplotlib
```

## How to run

From this folder, with `2_auth.log` present:

```bash
python analysis.py --input 2_auth.log --outdir output
```

Arguments:
- `--input` - path to the raw auth.log extract (default: `2_auth.log`)
- `--outdir` - directory to write tables/figures into (default: `output`)

The script prints a console summary (total events, failed/accepted counts, top offenders) and (re)generates everything under `output/`. Re-running is safe, files are overwritten each time, so the output always reflects the
current version of `2_auth.log`.

## Input format expected

Syslog-style lines of the form:

```
<Mon> <DD> <HH:MM:SS> <host> <process>[<pid>]: <message>
```

e.g.

```
Jul 06 00:02:36 db01 sshd[3907]: Failed password for backup from 198.51.100.60 port 38701 ssh2
```

The script recognises `sshd`, `sudo`, and `CRON` message bodies matching the templates listed in `analysis.py` (failed/accepted password, invalid user, max-auth-exceeded, preauth connection closed, pam session open/close, sudo command lines).

## Key assumptions and decisions

1. **Defining a "failed authentication attempt."** 
OpenSSH logs adedicated `Failed password for <user> from <ip> port <port> ssh2` line for every rejected password (for both real and non-existent usernames), and separately logs a one-off `Invalid user <user> from <ip> port <port>` line the first time it sees an unrecognised account on a connection. In this extract, PIDs are reused across the week (small PID space relative to ~12,000 events), so an `Invalid user` line cannot be reliably paired back to its matching `Failed password for invalid user` line by PID. To avoid double-counting the same rejected attempt, **only `Failed password for ...` lines are counted as failed authentication attempts**; `Invalid user` announce lines are tracked separately.

2. **Username and source IP extraction.** 
Pulled directly from the regex capture groups on the `Failed password for [invalid user] <user> from <ip> port <port> ssh2` and `Accepted password for <user> from <ip> port <port> ssh2` templates. Usernames from invalid-user failures are attacker-supplied free text and are not validated against any known account list.

3. **No year in the timestamps.** 
The log uses syslog-style `Mon DD HH:MM:SS` timestamps with no year. The script assigns a fixed placeholder year (2026) purely so timestamps can be parsed and sorted for the time-series chart; the year has no evidentiary meaning and will not be quoted in the report. only relative day-to-day patterns should be drawn from `failed_attempts_by_day.png`.

4. **Unmatched / ambiguous lines are not discarded silently.** 
Any line whose message body doesn't match a known template is written verbatim with its line number to `output/unmatched_lines.csv` for manual review. On the assigned extract this file is currently empty (all 12,000 lines matched a known template), which is itself worth noting as a characteristic of this synthetic dataset.

5. **Accounts flagged as higher-priority evidence.** 
All six accounts that ever had a successful login (`alice`, `ops`, `backup`, `mei`, `dinesh`, `postgres`) were also targeted by failed password attempt at some point in the extract  (`accounts_targeted_and_later_accepted.csv`). This overlap is presented as supporting evidence only as it does not by itself prove a successful compromise, since the failed and accepted attempts may originate from different, unrelated source IPs.

## Limitations

- The extract has no year and no evidence of log rotation/gaps, so coverage completeness (i.e. whether any events were dropped before this extract was taken) cannot be verified from the file alone.
- PID reuse (see point 1 above) means per-connection event correlation (e.g. linking a specific `Invalid user` line to the exact `Failed password` line it produced) is not possible with the fields available in this log format; all counts are therefore at the line/event level, not the connection level.
- The script does not attempt geolocation, reverse DNS, or threat-intel lookups on source IPs.
