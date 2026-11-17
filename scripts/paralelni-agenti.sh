#!/usr/bin/env bash
# Paralelní agenti na jednom projektu — univerzální spouštěč.
#
# Použití (z jednoho terminálu, bez interaktivního Clauda):
#   bash scripts/paralelni-agenti.sh \
#     "Zadání pro agenta 1 (co má vytvořit a kam)" \
#     "Zadání pro agenta 2" \
#     ["Zadání pro agenta 3 ..."]
#
# Každý agent dostane VLASTNÍ podsložku results/agenti/agentN/ a pracuje JEN tam
# → žádné konflikty se sdílenými soubory. Log agenta je results/agenti/agentN.log.
#
# Volitelné: MODEL=claude-sonnet-5 bash scripts/paralelni-agenti.sh "..."
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENTI="$ROOT/results/agenti"
mkdir -p "$AGENTI"

MODEL="${MODEL:-deepseek-v4-flash}"
PERM="${PERM:---permission-mode bypassPermissions}"
N=${#@}

if [ "$N" -lt 1 ]; then
    echo "Použití: bash scripts/paralelni-agenti.sh \"zadání 1\" [\"zadání 2\" ...]"
    exit 1
fi

echo "=== Paralelní agenti: $N úloh ==="
echo "Model: $MODEL"
echo "Výstupy/logy: $AGENTI"
START=$(date +%s%N)

i=1
for zadani in "$@"; do
    DIR="$AGENTI/agent$i"
    mkdir -p "$DIR"
    cat > "$DIR/prompt.txt" <<EOF
Jsi agent $i z $N na projektu $(basename "$ROOT").
Pracuj JEN ve složce $DIR a výstup vytvářej tam.
Neměň nic mimo svou složku.

Zadání:
$zadani

Po dokončení stručně shrň, co jsi vytvořil (soubory + funkce).
EOF

    (
        if claude -p "$(cat "$DIR/prompt.txt")" --model "$MODEL" $PERM \
            --add-dir "$DIR" --allowedTools "Bash,Read,Write,Edit" \
            > "$AGENTI/agent$i.log" 2>&1; then
            echo "  ✓ agent$i hotov ($(date +%H:%M:%S))"
        else
            echo "  ⚠ agent$i selhal (viz $AGENTI/agent$i.log)"
        fi
    ) &
    i=$((i+1))
done

wait || true

END=$(date +%s%N)
T=$(( (END - START) / 1000000 ))

echo ""
echo "=== Výsledek ==="
echo "Celkový čas: ${T} ms ($(awk "BEGIN{printf \"%.1f\", $T/1000}") s)"
echo "Výstupy: $AGENTI/agentN/"
echo "Logy:   $AGENTI/agentN.log"
echo "Ověř výstupy a případně je přesuň do projektu."
