# cowrie-stats

Jednovětový popis projektu.

## Co je hotové

- _doplň_

## Jak rozjet multi-agent

```bash
bash scripts/paralelni-agenti.sh "úkol A" "úkol B"
```

Každý agent dostane vlastní složku `results/agenti/agentN/` (žádné konflikty), logy v `results/agenti/agentN.log`.

## Struktura

```
├── README.md
├── CLAUDE.md
├── scripts/paralelni-agenti.sh   ← spouštěč paralelních agentů
└── docs/
```

## Reference

- `docs/` — design, plány, poznámky
- `CLAUDE.md` — pravidla pro agenty v tomto projektu
