# CLAUDE.md — cowrie-stats

## Účel

Veřejný open-source nástroj: přečte archiv Cowrie honeypotu v SQLite a vygeneruje
statickou stránku se statistikami útoků (časová osa, země, ASN, zkoušená hesla
a příkazy) plus `data.json`.

Projekt je **veřejný** — README anglicky, kód a komentáře česky. Nikdy do něj
nepatří reálná data z provozu ani osobní cesty a domény; vše jde přes proměnné
prostředí (`SITE_NAME`, `SITE_URL`, `SITE_LABEL`).

## Struktura

```
generate.py          generátor stránky (stdlib, žádné závislosti)
geoip.py             DB-IP Lite → země a ASN, hledání přes bisect
schema.sql           očekávané schéma archivu (zdroj: Cowrie, BSD-3-Clause)
sample/make_sample.py syntetická data pro vyzkoušení (RFC 5737 adresy)
docs/                screenshot a poznámky
```

## Pravidla

- **Žádná reálná data v repu** — archivy, výstupy ani IP adresy. Hlídat i screenshoty.
- Python 3.10+, jen standardní knihovna. Novou závislost dobře zdůvodnit.
- Stránka nesmí obsahovat JavaScript (CSP `script-src 'none'` u nasazení).
- `README.md` anglicky a pravdivě — čísla a postupy aktualizovat po změně.
- Commituj po každém dokončeném úkolu.

## Nasazení

Tenhle projekt je zdroj pravdy i pro ostrý provoz: kontejner `cowrie-report`
v `~/projects/honeypot` mountuje tento adresář do `/app` a volá `generate.py`
každou hodinu. Neupravovat kopii — žádná neexistuje.

## Spouštění

```bash
python3 sample/make_sample.py --out sample.db --days 30
python3 generate.py --db sample.db --out out
```
