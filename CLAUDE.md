# CLAUDE.md — cowrie-stats

Pravidla pro Claude agenty pracující v tomto projektu.

## Účel

_Co projekt dělá a proč existuje. Doplň první._

## Jak rozjet paralelní agenty

```bash
bash scripts/paralelni-agenti.sh "Zadání 1" "Zadání 2" [...]
```

- Každý agent pracuje JEN ve své složce `results/agenti/agentN/` → žádné konflikty.
- Log agenta: `results/agenti/agentN.log`.
- Volitelný model: `MODEL=claude-sonnet-5 bash scripts/paralelni-agenti.sh "..."`.

## Pravidla

- Texty **česky**.
- **Commituj po každém dokončeném úkolu.**
- Úlohy mezi agenty jsou nezávislé — žádné sdílené soubory.
- Dokumentace zůstává pravdivá — výsledky a čísla aktualizuj.

## Doporučené další čtení

- `docs/` — design, plány, poznámky
- `README.md` — přehled projektu
