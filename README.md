# 🍯 honeypot-cowrie-stats

[![Live example](https://img.shields.io/badge/LIVE-attacks.laferrari.eu-f0a500?style=for-the-badge&labelColor=0b0e14)](https://attacks.laferrari.eu)

Turn a [Cowrie](https://github.com/cowrie/cowrie) honeypot archive into a static
statistics page: attack timeline, countries, networks, credentials tried,
commands executed and malware sample counts. 📊

No dependencies beyond Python 3.10+, no database server, no JavaScript on the
output page. It reads an SQLite archive read-only and writes plain HTML + JSON. ⚡

> ### 🌐 [See it running on my own server](https://attacks.laferrari.eu)
>
> Every number on [**attacks.laferrari.eu**](https://attacks.laferrari.eu) comes
> from this tool reading a real Cowrie archive: **~320 000 sessions** from
> **15 000+ unique IPs** since August 2026. Nothing is mocked. 🛡️

<img width="2752" height="1536" alt="Gemini_Generated_Image_jlyxxnjlyxxnjlyx" src="https://github.com/user-attachments/assets/026db7e1-ca14-43e7-ac8c-09ed4dc2cbe0" />

## 🤔 Why

Cowrie keeps one day per log file and rotates it. Most dashboards read only the
current `cowrie.json`, so every day the older attacks disappear from view. If you
first archive every event into SQLite (the schema this tool expects is in
[`schema.sql`](schema.sql)), you can ask questions that span months:

- 📈 How many attacks per day, and is it getting worse?
- 🌍 Which countries and hosting providers send them?
- 🔑 Which passwords do attackers try most often?
- 💻 What do they run once they think they are in?

This tool answers those questions and publishes the answers as a static page.

## 🚀 Quick start

```bash
# 1) Synthetic archive: 30 days of fake attacks, no real data involved
python3 sample/make_sample.py --out sample.db --days 30

# 2) Generate the page
python3 generate.py --db sample.db --out out

# 3) Look at it
python3 -m http.server -d out 8000
# → [http://127.0.0.1:8000](http://127.0.0.1:8000)
