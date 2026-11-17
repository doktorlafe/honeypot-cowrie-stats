#!/usr/bin/env python3
"""
cowrie-stats — statistiky z archivu Cowrie honeypotu.

Čte archivní SQLite (jen SELECTy, read-only) a vypíše statické HTML + JSON.
Databáze se nikdy nevystavuje — ven jde jen to, co tenhle skript spočítá.
Publikují se výhradně agregace: žádné jednotlivé IP adresy.

Použití:
    python3 generate.py --db archiv.db --out ./out
    SITE_NAME="Můj web" SITE_LABEL="stats.example.com" python3 generate.py
"""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timezone

# -I (izolovaný režim) nebere adresář skriptu do sys.path, takže si ho
# musíme přidat sami — geoip.py je sourozenec.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import geoip  # noqa: E402

PRAGMA: tuple[str, ...] = ("cowrie.session.connect",)
DB = os.environ.get("ARCHIVE_DB", "/var/lib/honeypot-archive/cowrie.db")
OUT = os.environ.get("REPORT_OUT", "/var/lib/honeypot-archive/public")
FONT_SRC = os.environ.get("FONT_SRC", "/fonts")

# Texty na stránce držíme mimo kód, aby šel nástroj použít pro jakýkoli web.
SITE_NAME = os.environ.get("SITE_NAME", "Honeypot")
SITE_URL = os.environ.get("SITE_URL", "")
SITE_LABEL = os.environ.get("SITE_LABEL", "cowrie-stats")

# Jen tyhle řezy potřebujeme; při kopírování se ignoruje zbytek.
FONT_FILES = (
    "inter-400-latin.woff2", "inter-400-latin-ext.woff2",
    "inter-600-latin.woff2", "inter-600-latin-ext.woff2",
    "inter-700-latin.woff2", "inter-700-latin-ext.woff2",
    "jetbrains-mono-400-latin.woff2", "jetbrains-mono-400-latin-ext.woff2",
    "jetbrains-mono-500-latin.woff2", "jetbrains-mono-500-latin-ext.woff2",
)


def q(conn, sql, *args):
    return conn.execute(sql, args).fetchall()


def one(conn, sql, *args, default=0):
    row = conn.execute(sql, args).fetchone()
    return row[0] if row and row[0] is not None else default


def num(n) -> str:
    return f"{int(n):,}".replace(",", " ")


def esc(s) -> str:
    return html.escape(str(s), quote=True)


COUNTRY_NAMES = {
    "RU": "Rusko", "CN": "Čína", "US": "USA", "BR": "Brazílie", "IN": "Indie",
    "VN": "Vietnam", "NL": "Nizozemsko", "DE": "Německo", "FR": "Francie",
    "GB": "Velká Británie", "UA": "Ukrajina", "TR": "Turecko", "ID": "Indonésie",
    "TH": "Thajsko", "PK": "Pákistán", "BD": "Bangladéš", "RO": "Rumunsko",
    "PL": "Polsko", "KR": "Jižní Korea", "JP": "Japonsko", "SG": "Singapur",
    "HK": "Hongkong", "TW": "Tchaj-wan", "IR": "Írán", "IQ": "Irák",
    "EG": "Egypt", "ZA": "Jihoafrická rep.", "NG": "Nigérie", "MX": "Mexiko",
    "AR": "Argentina", "CO": "Kolumbie", "CL": "Chile", "PE": "Peru",
    "CA": "Kanada", "AU": "Austrálie", "IT": "Itálie", "ES": "Španělsko",
    "SE": "Švédsko", "FI": "Finsko", "NO": "Norsko", "DK": "Dánsko",
    "CZ": "Česko", "SK": "Slovensko", "HU": "Maďarsko", "BG": "Bulharsko",
    "GR": "Řecko", "IL": "Izrael", "AE": "SAE", "SA": "Saúdská Arábie",
    "KZ": "Kazachstán", "BY": "Bělorusko", "MD": "Moldavsko", "GE": "Gruzie",
    "AM": "Arménie", "AZ": "Ázerbájdžán", "LV": "Lotyšsko", "LT": "Litva",
    "EE": "Estonsko", "CH": "Švýcarsko", "AT": "Rakousko", "BE": "Belgie",
    "IE": "Irsko", "PT": "Portugalsko", "NZ": "Nový Zéland", "MY": "Malajsie",
    "PH": "Filipíny", "MM": "Myanmar", "LK": "Srí Lanka", "NP": "Nepál",
    "MA": "Maroko", "TN": "Tunisko", "DZ": "Alžírsko", "KE": "Keňa",
    "GH": "Ghana", "ET": "Etiopie", "SA": "Saúdská Arábie", "JO": "Jordánsko",
    "KW": "Kuvajt", "QA": "Katar", "CY": "Kypr", "MT": "Malta", "IS": "Island",
}


def country_code(cc: str | None) -> str:
    """Kód země pro tabulku.

    Emoji vlajky se na Linuxu bez emoji fontu vykreslují jako dvě písmena
    v rámečku, což vypadá jako chyba. Dvoupísmenný kód v mono je čistší
    a lépe sedí k terminálovému vzhledu.
    """
    return cc.upper() if cc and len(cc) == 2 else "—"


def collect_geo(conn, geo_path: str) -> dict:
    """
    Rozšíří každou útočící IP o zemi a organizaci a spočítá žebříčky.

    Počítá se váženě podle počtu sessions, ne podle počtu IP — jinak by
    jeden scanner s tisíci pokusy a jeden s jedním vypadali stejně.
    """
    rows = q(conn, """
        SELECT src_ip, COUNT(*) AS n FROM events
        WHERE eventid = 'cowrie.session.connect' GROUP BY src_ip
    """)
    if not rows:
        return {"countries": [], "asns": [], "resolved": 0, "unknown": 0}

    os.makedirs(os.path.dirname(geo_path), exist_ok=True)
    geoip.ensure(geo_path)
    mapping = geoip.Resolver(geo_path).resolve([r[0] for r in rows])

    by_country: Counter[str] = Counter()
    by_org: Counter[str] = Counter()
    resolved = 0
    for ip, n in rows:
        cc, org = mapping.get(ip, (None, None))
        if cc:
            by_country[cc] += n
            resolved += n
        if org:
            by_org[org] += n

    total = sum(n for _, n in rows)
    countries = [
        {"code": country_code(cc), "name": COUNTRY_NAMES.get(cc, cc),
         "count": n, "share": round(n / resolved * 100, 1) if resolved else 0}
        for cc, n in by_country.most_common(15)
    ]
    asns = [
        {"value": org, "count": n, "share": round(n / total * 100, 1) if total else 0}
        for org, n in by_org.most_common(10)
    ]
    return {
        "countries": countries,
        "asns": asns,
        "resolved": resolved,
        "unknown": total - resolved,
        "distinct_countries": len(by_country),
    }


def collect(conn) -> dict:
    sessions = one(conn, "SELECT COUNT(*) FROM sessions")
    ips = one(conn, "SELECT COUNT(DISTINCT src_ip) FROM events")
    logins = one(conn, "SELECT COUNT(*) FROM auth")
    logins_ok = one(conn, "SELECT COUNT(*) FROM auth WHERE success = 1")
    commands = one(conn, "SELECT COUNT(*) FROM input")
    samples = one(conn, "SELECT COUNT(*) FROM files")
    first = one(conn, "SELECT MIN(timestamp) FROM events", default="")
    last = one(conn, "SELECT MAX(timestamp) FROM events", default="")

    daily = q(conn, """
        SELECT substr(timestamp, 1, 10) AS d, COUNT(*) AS n
        FROM events WHERE eventid = 'cowrie.session.connect'
        GROUP BY d ORDER BY d
    """)
    # Útočníci posílají stejné hodnoty s jinými bílými znaky (CR, mezery na
    # konci). Bez normalizace se pak "sh" a "sh\r" počítají jako dvě položky.
    trim = "TRIM({col}, ' ' || char(9) || char(10) || char(13))"
    users = q(conn, f"""SELECT {trim.format(col='username')} AS v, COUNT(*) FROM auth
                        GROUP BY v ORDER BY 2 DESC LIMIT 12""")
    passwords = q(conn, f"""SELECT {trim.format(col='password')} AS v, COUNT(*) FROM auth
                            GROUP BY v ORDER BY 2 DESC LIMIT 12""")
    cmds = q(conn, f"""SELECT {trim.format(col='input')} AS v, COUNT(*) FROM input
                       GROUP BY v ORDER BY 2 DESC LIMIT 12""")
    ports = q(conn, """
        SELECT dst_port, COUNT(*) FROM events WHERE eventid = 'cowrie.session.connect'
        GROUP BY 1 ORDER BY 2 DESC LIMIT 8
    """)
    protocols = q(conn, """
        SELECT protocol, COUNT(*) FROM events WHERE eventid = 'cowrie.session.connect'
        GROUP BY 1 ORDER BY 2 DESC
    """)
    hourly = q(conn, """
        SELECT substr(timestamp, 12, 2) AS h, COUNT(*) AS n FROM events
        WHERE eventid = 'cowrie.session.connect' GROUP BY h ORDER BY h
    """)
    by_hour = {int(h): n for h, n in hourly if h and h.isdigit()}

    busiest = max(daily, key=lambda r: r[1]) if daily else ("", 0)

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "range": {"from": first, "to": last},
        "totals": {
            "sessions": sessions, "ips": ips, "logins": logins,
            "logins_ok": logins_ok, "commands": commands, "samples": samples,
        },
        "daily": [{"date": d, "sessions": n} for d, n in daily],
        "hourly": [{"hour": h, "sessions": by_hour.get(h, 0)} for h in range(24)],
        "busiest": {"date": busiest[0], "sessions": busiest[1]},
        "avg_per_day": round(sum(n for _, n in daily) / len(daily)) if daily else 0,
        "top_usernames": [{"value": u, "count": n} for u, n in users],
        "top_passwords": [{"value": p, "count": n} for p, n in passwords],
        "top_commands": [{"value": c, "count": n} for c, n in cmds],
        "ports": [{"value": p, "count": n} for p, n in ports],
        "protocols": [{"value": p, "count": n} for p, n in protocols],
    }


def setup_fonts(dst: str) -> None:
    os.makedirs(dst, exist_ok=True)
    for name in FONT_FILES:
        src = os.path.join(FONT_SRC, name)
        target = os.path.join(dst, name)
        if os.path.exists(src) and not os.path.exists(target):
            shutil.copyfile(src, target)


def font_css() -> str:
    faces = [
        ("Inter", 400, "inter-400"), ("Inter", 600, "inter-600"), ("Inter", 700, "inter-700"),
        ("JetBrains Mono", 400, "jetbrains-mono-400"), ("JetBrains Mono", 500, "jetbrains-mono-500"),
    ]
    out = []
    for family, weight, slug in faces:
        for subset in ("latin", "latin-ext"):
            out.append(
                f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};"
                f"font-display:swap;src:url(fonts/{slug}-{subset}.woff2) format('woff2');}}"
            )
    return "\n".join(out)


def bars(daily: list[dict], height: int = 120) -> str:
    if not daily:
        return "<p class=\"muted\">Zatím žádná data.</p>"
    peak = max(d["sessions"] for d in daily) or 1
    cells = []
    for d in daily:
        h = max(2, round(d["sessions"] / peak * height))
        cells.append(
            f'<span class="bar" style="height:{h}px" '
            f'title="{esc(d["date"])}: {num(d["sessions"])}"></span>'
        )
    first, last = daily[0]["date"], daily[-1]["date"]
    return (
        f'<div class="bars" role="img" aria-label="Sessions per day from {esc(first)} to {esc(last)}">'
        + "".join(cells)
        + "</div>"
        + f'<div class="axis"><span>{esc(first)}</span><span>maximum {num(peak)} / den</span>'
          f'<span>{esc(last)}</span></div>'
    )


def country_table(rows: list[dict]) -> str:
    if not rows:
        return '<p class="muted">Geolokace zatím není k dispozici.</p>'
    peak = max(r["share"] for r in rows) or 1
    out = ['<table class="rank"><tbody>']
    for r in rows:
        w = max(2, round(r["share"] / peak * 100))
        share = str(r["share"]).replace(".", ",")
        out.append(
            f'<tr><td class="code">{esc(r["code"])}</td>'
            f'<td class="nm">{esc(r["name"])}</td>'
            f'<td class="barcell"><span class="sbar" style="width:{w}%"></span></td>'
            f'<td class="n">{num(r["count"])}</td>'
            f'<td class="n">{share} %</td></tr>'
        )
    out.append("</tbody></table>")
    return "".join(out)


def hour_chart(hourly: list[dict]) -> str:
    peak = max((h["sessions"] for h in hourly), default=0) or 1
    cells = "".join(
        f'<span class="bar" style="height:{max(2, round(h["sessions"] / peak * 80))}px" '
        f'title="{h["hour"]:02d}:00 — {num(h["sessions"])}"></span>'
        for h in hourly
    )
    labels = "".join(
        f'<span>{h:02d}</span>' if h % 6 == 0 else "<span></span>" for h in range(24)
    )
    return (f'<div class="bars hours">{cells}</div>'
            f'<div class="axis hours-axis">{labels}</div>')


def table(rows: list[dict], empty: str = "—") -> str:
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    items = "".join(
        f"<tr><td class=\"mono\" title=\"{esc(r['value'])}\">{esc(r['value'])}</td>"
        f"<td class=\"n\">{num(r['count'])}</td></tr>"
        for r in rows
    )
    return f'<table><tbody>{items}</tbody></table>'


def render(data: dict, fonts_ok: bool = True) -> str:
    t = data["totals"]
    geo = data["geo"]
    top3 = ", ".join(c["name"] for c in geo["countries"][:3]) or "—"
    frm, to = data["range"]["from"][:10], data["range"]["to"][:10]
    gen = data["generated"].replace("T", " ").replace("Z", " UTC")
    proto = " · ".join(f"{p['value']} {num(p['count'])}" for p in data["protocols"])

    face_css = font_css() if fonts_ok else ""

    return f"""<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Honeypot — reálné útoky</title>
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<meta name="description" content="Agregovaná data z honeypotu: počty útoků, zkoušená hesla, příkazy a země původu.">
<style>
{face_css}
:root {{
    --bg:#0b0e14; --surface:#0f131b; --fg:#e6e9ef; --muted:#8a93a6;
    --line:#1f2733; --accent:#f0a500; --ok:#3ddc97;
    --display:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color-scheme: dark;
}}
* {{ box-sizing:border-box; }}
body {{
    margin:0; background:var(--bg); color:var(--fg);
    font-family:var(--display); font-size:16px; line-height:1.6;
    padding-left:max(16px,env(safe-area-inset-left,0px));
    padding-right:max(16px,env(safe-area-inset-right,0px));
    -webkit-font-smoothing:antialiased;
}}
.wrap {{ max-width:1120px; margin-inline:auto; }}
a {{ color:inherit; text-decoration:none; }}
a:hover {{ color:var(--accent); }}
a:focus-visible {{ outline:2px solid var(--accent); outline-offset:3px; }}
.mono {{ font-family:var(--mono); }}
.muted {{ color:var(--muted); }}

header.site {{
    border-bottom:1px solid var(--line);
    padding:16px 0;
}}
.nav {{ display:flex; align-items:baseline; gap:16px; max-width:1120px; margin-inline:auto; }}
.logo {{ font-family:var(--mono); font-weight:700; font-size:15px; }}
.logo span {{ color:var(--accent); }}
.nav .right {{ margin-left:auto; font-size:13px; color:var(--muted); }}

.hero {{ padding:64px 0 48px; border-bottom:1px solid var(--line); }}
.prompt {{ font-family:var(--mono); font-size:13px; color:var(--muted); margin:0 0 18px; }}
.prompt .ok {{ color:var(--ok); }}
h1 {{
    font-size:clamp(2rem,4.2vw,3.2rem); line-height:1.06; letter-spacing:-0.035em;
    font-weight:700; margin:0 0 18px; text-wrap:balance;
}}
.lead {{ max-width:62ch; color:var(--muted); margin:0 0 12px; }}
.range {{ font-family:var(--mono); font-size:12px; color:var(--muted); }}

.counters {{
    display:grid; grid-template-columns:repeat(5,1fr);
    border-bottom:1px solid var(--line);
}}
.counter {{ padding:22px 20px 22px 0; border-right:1px solid var(--line); }}
.counter:last-child {{ border-right:0; }}
.counter .n {{ display:block; font-family:var(--mono); font-size:24px; font-weight:700;
    letter-spacing:-0.03em; font-variant-numeric:tabular-nums; }}
.counter .l {{ display:block; font-size:13px; color:var(--muted); margin-top:2px; }}

section {{ padding:56px 0; border-bottom:1px solid var(--line); }}
h2 {{ font-size:clamp(1.3rem,2.2vw,1.7rem); letter-spacing:-0.02em; margin:0 0 8px; }}
.section-note {{ color:var(--muted); margin:0 0 28px; max-width:60ch; }}

.bars {{ display:flex; align-items:flex-end; gap:2px; height:120px; }}
.bar {{ flex:1; background:var(--accent); opacity:.75; border-radius:1px 1px 0 0; min-width:1px; }}
.bar:hover {{ opacity:1; }}
.axis {{ display:flex; justify-content:space-between; font-family:var(--mono);
    font-size:11px; color:var(--muted); margin-top:8px; }}

.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:40px; }}

/* Žebříček zemí s pruhem podílu */
table.rank td {{ vertical-align:middle; }}
table.rank td.code {{ width:34px; font-family:var(--mono); font-size:12px;
    color:var(--muted); letter-spacing:.04em; }}
table.rank td.nm {{ width:1%; white-space:nowrap; padding-right:16px; }}
table.rank td.barcell {{ width:100%; padding:0 16px 0 0; }}
.sbar {{ display:block; height:6px; background:var(--accent); opacity:.7; border-radius:2px; }}
.attrib {{ font-size:12px; color:var(--muted); margin:14px 0 0; }}
.attrib a {{ border-bottom:1px solid var(--line); }}
.hours {{ height:80px; }}
.hours-axis span {{ flex:1; text-align:left; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
td {{ padding:9px 0; border-bottom:1px solid var(--line); }}
td.n {{ text-align:right; font-family:var(--mono); font-variant-numeric:tabular-nums;
    color:var(--muted); white-space:nowrap; padding-left:16px; }}
td.mono {{ font-family:var(--mono); font-size:13px; max-width:52ch;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}

.note {{
    background:var(--surface); border:1px solid var(--line); border-left:3px solid var(--accent);
    padding:18px 20px; font-size:14px; color:var(--muted); max-width:70ch;
}}
.note strong {{ color:var(--fg); font-weight:500; }}

footer {{ padding:28px 0 48px; font-size:13px; color:var(--muted);
    display:flex; flex-wrap:wrap; gap:10px 24px; justify-content:space-between;
    max-width:1120px; margin-inline:auto; }}

@media (max-width:860px) {{
    .counters {{ grid-template-columns:repeat(2,1fr); }}
    .counter {{ border-right:0; border-bottom:1px solid var(--line); }}
    .counter:nth-child(odd) {{ padding-right:16px; }}
    .grid2 {{ grid-template-columns:1fr; gap:32px; }}
}}
</style>
</head>
<body>

<header class="site">
    <nav class="nav">
        <a class="logo" href="{esc(SITE_URL) or '#'}">{esc(SITE_NAME)}</a>
        <span class="right mono">{esc(SITE_LABEL)}</span>
    </nav>
</header>

<main class="wrap">

    <section class="hero">
        <p class="prompt"><span class="ok">$</span> cowrie --summary --since {esc(frm)}</p>
        <h1>Co se děje na honeypotu</h1>
        <p class="lead">Veřejně vystavený SSH a Telnet honeypot sbírá data o tom, kdo se pokouší přihlásit a co zkouší dělat. Tohle jsou agregované výsledky — bez konkrétních IP adres.</p>
        <p class="range">data {esc(frm)} → {esc(to)} · aktualizováno {esc(gen)}</p>
    </section>

    <div class="counters">
        <div class="counter"><span class="n">{num(t["sessions"])}</span><span class="l">sessions</span></div>
        <div class="counter"><span class="n">{num(t["ips"])}</span><span class="l">unikátních IP</span></div>
        <div class="counter"><span class="n">{num(t["logins"])}</span><span class="l">pokusů o přihlášení</span></div>
        <div class="counter"><span class="n">{num(t["commands"])}</span><span class="l">zadaných příkazů</span></div>
        <div class="counter"><span class="n">{num(t["samples"])}</span><span class="l">stažených vzorků</span></div>
    </div>

    <section>
        <h2>Útoky v čase</h2>
        <p class="section-note">Počet navázaných sessions za den. {esc(proto)}. Nejvytíženější den {esc(data["busiest"]["date"])} ({num(data["busiest"]["sessions"])} sessions), průměr {num(data["avg_per_day"])} denně.</p>
        {bars(data["daily"])}
    </section>

    <section>
        <h2>Odkud se útočí</h2>
        <p class="section-note">Nejvíc pokusů přichází z {esc(top3)}. Počítá se počet navázaných sessions, ne počet IP adres. Zastoupeno {num(geo["distinct_countries"])} zemí; geolokace pokrývá {num(geo["resolved"])} sessions.</p>
        {country_table(geo["countries"])}
        <p class="attrib">Geolokace: <a href="https://db-ip.com" rel="noopener">DB-IP</a> (CC BY 4.0)</p>
    </section>

    <section>
        <div class="grid2">
            <div>
                <h2>Nejaktivnější sítě</h2>
                <p class="section-note">Autonomní systémy s nejvyšším počtem sessions. Velká část patří hostingům a cloudům.</p>
                {table(geo["asns"])}
            </div>
            <div>
                <h2>Kdy se útočí</h2>
                <p class="section-note">Rozložení sessions podle hodiny dne (UTC). Provoz jede nepřetržitě — útočníci nespí.</p>
                {hour_chart(data["hourly"])}
            </div>
        </div>
    </section>

    <section>
        <div class="grid2">
            <div>
                <h2>Zkoušená uživatelská jména</h2>
                <p class="section-note">Nejčastější loginy, které útočníci zkoušejí.</p>
                {table(data["top_usernames"])}
            </div>
            <div>
                <h2>Zkoušená hesla</h2>
                <p class="section-note">Nejčastější hesla. {num(t["logins_ok"])} pokusů honeypot „přijal“ — je to past, ne úspěch.</p>
                {table(data["top_passwords"])}
            </div>
        </div>
    </section>

    <section>
        <h2>Co se útočníci snaží spustit</h2>
        <p class="section-note">Nejčastější příkazy zadané v napadené shell session.</p>
        {table(data["top_commands"])}
    </section>

    <section>
        <h2>Na které porty se útočí</h2>
        <p class="section-note">Rozložení pokusů podle cílového portu.</p>
        {table(data["ports"])}
    </section>

    <section style="border-bottom:0;">
        <h2>Metodika</h2>
        <div class="note">
            <p style="margin:0 0 10px"><strong>Co je zdrojem dat:</strong> Cowrie honeypot na veřejné IP adrese, logy od {esc(frm)}. Každý event se ukládá do vlastní archivní databáze, která je oddělená od produkčního serveru.</p>
            <p style="margin:0 0 10px"><strong>Co se nepublikuje:</strong> jednotlivé IP adresy, obsah nahraných souborů a osobní údaje. Jen agregace a nejčastější hodnoty.</p>
            <p style="margin:0 0 10px"><strong>Proč:</strong> honeypot je past. Cílem není útočníky blokovat, ale zaznamenat, jaké techniky se dnes používají v praxi.</p>
            <p style="margin:0"><strong>Geolokace:</strong> databáze <a href="https://db-ip.com" rel="noopener">DB-IP Lite</a> (CC BY 4.0), aktualizovaná měsíčně. Země je odhad podle rozsahu IP adres, ne přesná poloha.</p>
        </div>
    </section>

</main>

<footer>
    <span>{esc(SITE_NAME)} · data z vlastního honeypotu</span>
    <span class="mono">aktualizováno {esc(gen)}</span>
</footer>

</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Vygeneruje statické statistiky z archivu honeypotu")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--db", default=DB)
    ap.add_argument("--no-fonts", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"archiv neexistuje: {args.db}", file=sys.stderr)
        return 1

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=60)
    try:
        data = collect(conn)
        data["geo"] = collect_geo(
            conn, os.path.join(os.path.dirname(os.path.abspath(args.db)), "geo", "ip.db"))
    finally:
        conn.close()

    if not data["totals"]["sessions"]:
        print("archiv je prázdný — stránku negeneruji", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    fonts_dir = os.path.join(args.out, "fonts")
    if not args.no_fonts:
        setup_fonts(fonts_dir)

    # Bez dostupných woff2 nemá smysl emitovat @font-face — prohlížeč by jen
    # stahoval soubory, které neexistují. Radši systémový font.
    fonts_ok = os.path.isdir(fonts_dir) and any(
        f.endswith(".woff2") for f in os.listdir(fonts_dir))

    html_path = os.path.join(args.out, "index.html")
    json_path = os.path.join(args.out, "data.json")
    favicon_path = os.path.join(args.out, "favicon.svg")

    # Jednoduchý hexagon — odkaz na plástve, ale bez zbytečné grafiky.
    with open(favicon_path, "w", encoding="utf-8") as f:
        f.write(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
            '<rect width="32" height="32" rx="6" fill="#0b0e14"/>'
            '<path d="M16 5l9 5.2v10.4L16 26l-9-5.4V10.2z" fill="none" '
            'stroke="#f0a500" stroke-width="2.2" stroke-linejoin="round"/>'
            '</svg>'
        )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render(data, fonts_ok=fonts_ok))
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} vygenerováno: {html_path} "
          f"({data['totals']['sessions']} sessions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
