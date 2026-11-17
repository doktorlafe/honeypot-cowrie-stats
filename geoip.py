#!/usr/bin/env python3
"""
GeoIP nad volně dostupnými databázemi DB-IP Lite.

Proč vlastní implementace a ne knihovna: potřebujeme jen dvě věci — zemi a
organizaci (ASN) k IP adrese. DB-IP Lite jsou obyčejná CSV s rozsahy adres,
takže je načteme do SQLite a hledáme binárně přes index. Žádná závislost,
žádný licence klíč.

Licence: CC BY 4.0 — attribution na stránce je povinná (viz render).
Aktualizace: DB-IP vydává novou verzi každý měsíc; držíme ji 30 dní.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import io
import ipaddress
import os
import sqlite3
import sys
import time
import urllib.request

BASE = "https://download.db-ip.com/free"
PUBLISHER = "DB-IP"
MAX_AGE_DAYS = 30


def _month_tag(ts: float | None = None) -> str:
    t = time.gmtime(ts)
    return f"{t.tm_year}-{t.tm_mon:02d}"


def _download(url: str) -> io.BytesIO:
    req = urllib.request.Request(url, headers={"User-Agent": "cowrie-stats/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return io.BytesIO(r.read())


def _ip_to_int(s: str) -> int | None:
    """IPv4 jako 32bit integer. IPv6 přeskočíme — do SQLite INTEGER se nevejde
    a honeypot IPv6 provoz prakticky nemá."""
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    return int(addr) if addr.version == 4 else None


def build(db_path: str, ts: float | None = None) -> None:
    """Stáhne CSV z DB-IP a postaví z nich SQLite s rozsahy."""
    tag = _month_tag(ts)
    tmp = db_path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)

    conn = sqlite3.connect(tmp)
    conn.execute("""CREATE TABLE iprange (
        start   INTEGER NOT NULL,
        end     INTEGER NOT NULL,
        country TEXT,
        org     TEXT
    )""")

    print(f"[geoip] stahuji DB-IP Lite {tag}…", flush=True)
    country_csv = _download(f"{BASE}/dbip-country-lite-{tag}.csv.gz")
    asn_csv = _download(f"{BASE}/dbip-asn-lite-{tag}.csv.gz")

    # 1) země: start_ip,end_ip,kód země
    rows = []
    with gzip.open(country_csv, "rt", encoding="utf-8") as f:
        for rec in csv.reader(f):
            if len(rec) < 3:
                continue
            start, end = _ip_to_int(rec[0]), _ip_to_int(rec[1])
            if start is None or end is None:
                continue
            rows.append((start, end, rec[2] or None, None))
    print(f"[geoip] země: {len(rows)} rozsahů", flush=True)

    # 2) ASN: start_ip,end_ip,asn,organizace — doplníme do stejných rozsahů,
    #    i když se hranice rozsahů mezi oběma databázemi mírně liší.
    asn_rows = []
    with gzip.open(asn_csv, "rt", encoding="utf-8") as f:
        for rec in csv.reader(f):
            if len(rec) < 4:
                continue
            start, end = _ip_to_int(rec[0]), _ip_to_int(rec[1])
            if start is None or end is None:
                continue
            asn_rows.append((start, end, rec[3] or None))
    print(f"[geoip] ASN: {len(asn_rows)} rozsahů", flush=True)

    # ASN se ukládá jako samostatná tabulka — spojování rozsahů by bylo drahé
    # a chyby v hranicích by zkreslily výsledek.
    conn.executemany("INSERT INTO iprange VALUES (?,?,?,?)", rows)
    conn.execute("CREATE INDEX iprange_start ON iprange(start)")
    conn.execute("CREATE TABLE asnrange (start INTEGER NOT NULL, end INTEGER NOT NULL, org TEXT)")
    conn.executemany("INSERT INTO asnrange VALUES (?,?,?)", asn_rows)
    conn.execute("CREATE INDEX asnrange_start ON asnrange(start)")
    conn.commit()
    conn.close()

    os.replace(tmp, db_path)
    print(f"[geoip] hotovo: {db_path}", flush=True)


def ensure(db_path: str, ts: float | None = None) -> str:
    """Postaví databázi, pokud chybí nebo je starší než MAX_AGE_DAYS."""
    if os.path.exists(db_path):
        age_days = (time.time() - os.path.getmtime(db_path)) / 86400
        if age_days < MAX_AGE_DAYS:
            return db_path
    build(db_path, ts)
    return db_path


class Resolver:
    """
    Vyhledávání rozsahů v paměti (bisect), ne SQL dotazem na každou IP.

    Pro 15 tisíc adres znamenají dva dotazy na adresu 30 tisíc dotazů do
    SQLite — generování pak trvá desítky sekund. Načtení rozsahů do seznamů
    je jednorázové a stejnou práci zvládne za zlomek času.
    """

    def __init__(self, path: str):
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
        try:
            c = conn.execute("SELECT start, end, country FROM iprange ORDER BY start").fetchall()
            a = conn.execute("SELECT start, end, org FROM asnrange ORDER BY start").fetchall()
        finally:
            conn.close()
        self.c_start = [r[0] for r in c]
        self.c_end = [r[1] for r in c]
        self.c_val = [r[2] for r in c]
        self.a_start = [r[0] for r in a]
        self.a_end = [r[1] for r in a]
        self.a_val = [r[2] for r in a]

    @staticmethod
    def _find(starts, ends, values, v: int):
        i = bisect.bisect_right(starts, v) - 1
        if i >= 0 and ends[i] >= v:
            return values[i]
        return None

    def lookup(self, ip: str) -> tuple[str | None, str | None]:
        v = _ip_to_int(ip)
        if v is None:
            return (None, None)
        return (
            self._find(self.c_start, self.c_end, self.c_val, v),
            self._find(self.a_start, self.a_end, self.a_val, v),
        )

    def resolve(self, ips: list[str]) -> dict[str, tuple[str | None, str | None]]:
        return {ip: self.lookup(ip) for ip in ips}


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "geo/ip.db"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ensure(path, ts=time.time() if "--rebuild" in sys.argv else None)
