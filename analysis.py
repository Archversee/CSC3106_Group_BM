import argparse
import csv
import re
from collections import Counter
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------

# Generic syslog-style line prefix: "Jul 06 00:02:36 db01 sshd[3907]: <msg>"
LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w.\-]+)(\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

PATTERNS = {
    "failed_password_valid": re.compile(
        r"^Failed password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2$"
    ),
    "failed_password_invalid": re.compile(
        r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2$"
    ),
    "accepted_password": re.compile(
        r"^Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2$"
    ),
    "invalid_user_announce": re.compile(
        r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)$"
    ),
    "max_auth_exceeded": re.compile(
        r"^error: maximum authentication attempts exceeded for"
        r"( invalid user)? (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "preauth_closed": re.compile(
        r"^Connection closed by authenticating user (?P<user>\S+) (?P<ip>[\d.]+) port (?P<port>\d+) \[preauth\]$"
    ),
    "session_opened": re.compile(
        r"^pam_unix\(\w+:session\): session opened for user (?P<user>\S+) by"
    ),
    "session_closed": re.compile(
        r"^pam_unix\(\w+:session\): session closed for user (?P<user>\S+)$"
    ),
    "sudo_command": re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
        r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
    ),
}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_log(path: Path):
    """Parse the raw log file into a list of structured event dicts.

    Returns (events, unmatched) where `events` is a list of dicts with
    at least keys {line_no, timestamp, proc, event_type, user, ip} and
    `unmatched` is a list of (line_no, raw_line) for lines whose
    message body did not match any known template.
    """
    events = []
    unmatched = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue

            m = LINE_RE.match(line)
            if not m:
                unmatched.append((line_no, line))
                continue

            month = MONTHS.get(m.group("month"))
            day = int(m.group("day"))
            time_str = m.group("time")
            proc = m.group("proc")
            msg = m.group("msg")

            # Assume all events fall in a single year (not present in
            # syslog-style timestamps); we keep month/day/time as given
            # and build a sortable string using a fixed placeholder year.
            timestamp = f"2026-{month:02d}-{day:02d} {time_str}" if month else None

            matched_type = None
            fields = {}
            for event_type, pattern in PATTERNS.items():
                pm = pattern.match(msg)
                if pm:
                    matched_type = event_type
                    fields = pm.groupdict()
                    break

            if matched_type is None:
                unmatched.append((line_no, line))
                continue

            events.append({
                "line_no": line_no,
                "timestamp": timestamp,
                "proc": proc,
                "event_type": matched_type,
                "user": fields.get("user") or fields.get("target_user"),
                "ip": fields.get("ip"),
                "command": fields.get("command"),
            })

    return events, unmatched


def build_dataframe(events):
    df = pd.DataFrame(events)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def write_csv(rows, path: Path, header):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Analyse an auth.log extract for CSC3106 mini-project.")
    ap.add_argument("--input", default="2_auth.log", help="Path to the raw auth.log extract")
    ap.add_argument("--outdir", default="output", help="Directory to write tables/figures to")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.outdir)
    tables_dir = out_dir / "tables"
    figures_dir = out_dir / "figures"
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    events, unmatched = parse_log(in_path)
    df = build_dataframe(events)

    # -------------------------------------------------------------
    # 1. Unmatched / ambiguous lines -> written for transparency
    # -------------------------------------------------------------
    write_csv(unmatched, out_dir / "unmatched_lines.csv", ["line_no", "raw_line"])

    # -------------------------------------------------------------
    # 2. Failed authentication attempts (canonical definition, see
    #    module docstring point 2)
    # -------------------------------------------------------------
    failed = df[df["event_type"].isin(["failed_password_valid", "failed_password_invalid"])].copy()
    failed["target_type"] = failed["event_type"].map({
        "failed_password_valid": "existing_or_unknown_account",
        "failed_password_invalid": "invalid_account",
    })

    # Top source IPs by failed attempts (REQUIRED visualisation)
    top_ips = failed["ip"].value_counts().head(10)
    write_csv(
        list(top_ips.items()),
        tables_dir / "top_source_ips_failed.csv",
        ["source_ip", "failed_attempts"],
    )

    plt.figure(figsize=(8, 5))
    top_ips.sort_values().plot(kind="barh", color="#c0392b")
    plt.xlabel("Failed authentication attempts")
    plt.ylabel("Source IP")
    plt.title("Top source IPs by failed authentication attempts")
    plt.tight_layout()
    plt.savefig(figures_dir / "top_source_ips_failed.png", dpi=150)
    plt.close()

    # Top targeted usernames in failed attempts (second visualisation)
    top_users = failed["user"].value_counts().head(10)
    write_csv(
        list(top_users.items()),
        tables_dir / "top_targeted_usernames.csv",
        ["username", "failed_attempts"],
    )

    plt.figure(figsize=(8, 5))
    top_users.sort_values().plot(kind="barh", color="#2980b9")
    plt.xlabel("Failed authentication attempts")
    plt.ylabel("Targeted username")
    plt.title("Top targeted usernames in failed authentication attempts")
    plt.tight_layout()
    plt.savefig(figures_dir / "top_targeted_usernames.png", dpi=150)
    plt.close()

    # Failed attempts over time (supporting visualisation)
    if not failed.empty and failed["timestamp"].notna().any():
        by_day = failed.dropna(subset=["timestamp"]).set_index("timestamp").resample("D").size()
        write_csv(
            [(d.date().isoformat(), c) for d, c in by_day.items()],
            tables_dir / "failed_attempts_by_day.csv",
            ["date", "failed_attempts"],
        )
        plt.figure(figsize=(8, 5))
        by_day.plot(kind="line", marker="o", color="#8e44ad")
        plt.xlabel("Date")
        plt.ylabel("Failed authentication attempts")
        plt.title("Failed authentication attempts over time")
        plt.tight_layout()
        plt.savefig(figures_dir / "failed_attempts_by_day.png", dpi=150)
        plt.close()

    # -------------------------------------------------------------
    # 3. Successful logins
    # -------------------------------------------------------------
    accepted = df[df["event_type"] == "accepted_password"].copy()
    accepted_by_user = accepted["user"].value_counts()
    write_csv(
        list(accepted_by_user.items()),
        tables_dir / "accepted_logins_by_user.csv",
        ["username", "accepted_logins"],
    )
    accepted_by_ip = accepted["ip"].value_counts()
    write_csv(
        list(accepted_by_ip.items()),
        tables_dir / "accepted_logins_by_ip.csv",
        ["source_ip", "accepted_logins"],
    )

    # Accounts that were both brute-forced (failed) AND later had a
    # successful login -- higher-priority evidence of possible compromise.
    failed_targets = set(failed["user"].dropna())
    accepted_users = set(accepted["user"].dropna())
    overlap = sorted(failed_targets & accepted_users)
    write_csv(
        [(u,) for u in overlap],
        tables_dir / "accounts_targeted_and_later_accepted.csv",
        ["username"],
    )

    # -------------------------------------------------------------
    # 4. Brute-force / lockout indicators per source IP
    # -------------------------------------------------------------
    max_auth = df[df["event_type"] == "max_auth_exceeded"]
    max_auth_by_ip = max_auth["ip"].value_counts()
    write_csv(
        list(max_auth_by_ip.items()),
        tables_dir / "max_auth_exceeded_by_ip.csv",
        ["source_ip", "count"],
    )

    preauth = df[df["event_type"] == "preauth_closed"]
    preauth_by_ip = preauth["ip"].value_counts()
    write_csv(
        list(preauth_by_ip.items()),
        tables_dir / "preauth_connections_closed_by_ip.csv",
        ["source_ip", "count"],
    )

    # -------------------------------------------------------------
    # 5. Privileged activity (sudo) per user
    # -------------------------------------------------------------
    sudo = df[df["event_type"] == "sudo_command"]
    sudo_by_user = sudo["user"].value_counts()
    write_csv(
        list(sudo_by_user.items()),
        tables_dir / "sudo_commands_by_user.csv",
        ["username", "sudo_command_count"],
    )

    # -------------------------------------------------------------
    # 6. Console summary
    # -------------------------------------------------------------
    print("=" * 60)
    print(f"Parsed {len(df)} matched events, {len(unmatched)} unmatched lines")
    print(f"Total failed authentication attempts: {len(failed)}")
    print(f"Total accepted (successful) logins:    {len(accepted)}")
    print(f"Distinct source IPs (failed attempts): {failed['ip'].nunique()}")
    print(f"Distinct usernames targeted (failed):  {failed['user'].nunique()}")
    print(f"'max authentication attempts exceeded' events: {len(max_auth)}")
    print(f"Preauth connections closed: {len(preauth)}")
    print(f"Sudo commands run: {len(sudo)}")
    print(f"Accounts both targeted by failures AND later accepted: {len(overlap)} -> {overlap}")
    print("-" * 60)
    print("Top 5 source IPs by failed attempts:")
    print(top_ips.head(5).to_string())
    print("-" * 60)
    print("Top 5 targeted usernames:")
    print(top_users.head(5).to_string())
    print("=" * 60)
    print(f"Tables written to:   {tables_dir}")
    print(f"Figures written to:  {figures_dir}")


if __name__ == "__main__":
    main()
