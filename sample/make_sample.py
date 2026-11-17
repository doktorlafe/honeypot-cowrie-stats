#!/usr/bin/env python3
"""
Vygeneruje syntetický archiv honeypotu pro vyzkoušení cowrie-stats.

Žádná reálná data: všechny IP adresy jsou z rozsahů vyhrazených dokumentací
(RFC 5737 — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), takže je nikomu
nepřiřazujeme útok. Výsledkem je ale databáze se stejnou strukturou, jakou
vyrábí archiver, takže se nad ní dají zkoušet všechny dotazy i generování.

Použití:
    python3 sample/make_sample.py --out sample.db --days 30
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema.sql")

USERNAMES = ["root", "admin", "support", "ubuntu", "user", "guest", "test",
             "postgres", "oracle", "pi", "admin1", "ftpuser"]
PASSWORDS = ["123456", "admin", "password", "12345678", "root", "qwerty",
             "ubuntu", "letmein", "1234", "test", "raspberry", "abc123"]
COMMANDS = ["shell", "system", "enable", "linuxshell", "/bin/busybox",
            "echo -e \"\\x6F\\x6B\"", "sh", "uname -a", "cd /tmp", "wget",
            "chmod +x", "cat /etc/passwd"]
PROTOCOLS = ["ssh", "telnet", "ssh", "ssh"]
PORTS = {"ssh": [22, 2222, 8022, 2022], "telnet": [23, 2223]}
SIZE_RANGES = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]


def rand_ip(rng: random.Random) -> str:
    a, b, c = rng.choice(SIZE_RANGES)
    return f"{a}.{b}.{c}.{rng.randint(1, 254)}"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def main() -> int:
    ap = argparse.ArgumentParser(description="Syntetický archiv pro cowrie-stats")
    ap.add_argument("--out", default="sample.db")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if os.path.exists(args.out):
        os.remove(args.out)

    conn = sqlite3.connect(args.out)
    with open(SCHEMA, encoding="utf-8") as f:
        conn.executescript(f.read())

    # Syntetický honeypot: 86 400 snímků za den je moc, držíme se realistických
    # stovek sessions denně a rostoucího trendu.
    start = datetime.now(timezone.utc) - timedelta(days=args.days)
    line = 0
    sessions = []

    for day in range(args.days):
        base = start + timedelta(days=day)
        count = rng.randint(120, 900) + day * 8
        for _ in range(count):
            ts = base + timedelta(seconds=rng.randint(0, 86399))
            sid = "%012x" % rng.getrandbits(48)
            proto = rng.choice(PROTOCOLS)
            ip = rand_ip(rng)
            port = rng.choice(PORTS[proto])
            sessions.append((sid, iso(ts), ip, proto, port))

            conn.execute(
                "INSERT INTO events (timestamp, eventid, session, protocol, src_ip,"
                " src_port, dst_ip, dst_port, sensor, data, file_id, src_file, line_no)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts.isoformat() + "Z", "cowrie.session.connect", sid, proto, ip,
                 rng.randint(1024, 65535), "192.0.2.10", port, "sample",
                 None, 1, "cowrie.json.sample", line := line + 1))

            conn.execute(
                "INSERT INTO sessions (id, starttime, sensor, ip) VALUES (?,?,?,?)",
                (sid, ts.isoformat(), 1, ip))

            user = rng.choice(USERNAMES)
            pwd = rng.choice(PASSWORDS)
            success = rng.random() < 0.08
            conn.execute(
                "INSERT INTO events (timestamp, eventid, session, protocol, src_ip,"
                " username, password, file_id, src_file, line_no)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ts.isoformat() + "Z",
                 "cowrie.login.success" if success else "cowrie.login.failed",
                 sid, proto, ip, user, pwd, 1, "cowrie.json.sample", line := line + 1))

            # Úspěšné přihlášení pokračuje zadanými příkazy.
            if success:
                conn.execute(
                    "INSERT INTO auth (session, success, username, password, timestamp)"
                    " VALUES (?,?,?,?,?)",
                    (sid, 1, user, pwd, ts.isoformat()))
                for _ in range(rng.randint(1, 6)):
                    cmd = rng.choice(COMMANDS)
                    conn.execute(
                        "INSERT INTO input (session, timestamp, realm, success, input)"
                        " VALUES (?,?,?,?,?)",
                        (sid, ts.isoformat(), None, 1, cmd))
                    conn.execute(
                        "INSERT INTO events (timestamp, eventid, session, input,"
                        " file_id, src_file, line_no) VALUES (?,?,?,?,?,?,?)",
                        (ts.isoformat() + "Z", "cowrie.command.input", sid, cmd,
                         1, "cowrie.json.sample", line := line + 1))
            else:
                conn.execute(
                    "INSERT INTO auth (session, success, username, password, timestamp)"
                    " VALUES (?,?,?,?,?)",
                    (sid, 0, user, pwd, ts.isoformat()))

            if rng.random() < 0.01:
                sha = "%064x" % rng.getrandbits(256)
                conn.execute(
                    "INSERT OR IGNORE INTO files (shasum, size, path, kind, url,"
                    " first_seen, last_seen, seen_count) VALUES (?,?,?,?,?,?,?,?)",
                    (sha, rng.randint(1000, 500000), "/tmp/payload", "download",
                     "http://example.invalid/payload", iso(ts), iso(ts), 1))

    conn.commit()
    n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    n_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    conn.close()

    print(f"hotovo: {args.out} — {n_sessions} sessions, {n_events} eventů")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
