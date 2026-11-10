#!/usr/bin/env bash
# run_main.sh — FASE 4: bateria principal + estudo de estabilidade. Roda no macOS.
# Retomável: se parar no meio, rode de novo e ele continua de onde parou.
set -euo pipefail
cd "$(dirname "$0")/.."

CWE79=data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv
CWE89=data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv
CFG=prompts/prompt_config.json
NUM_CTX=8192; SEED=2026
GEMMA="gemma:7b-instruct"; CODEGEMMA="codegemma:7b-instruct"
digest () { ollama list | awk -v m="$1" '$1==m{print $3}'; }
GD="$(digest "$GEMMA")"; CD="$(digest "$CODEGEMMA")"
QUANT="$(ollama show "$CODEGEMMA" 2>/dev/null | grep -i quantization | awk '{print $NF}' | head -1)"

# --- congelamento: registra o ambiente exato da coleta ---
mkdir -p results logs
if [ ! -f results/run_metadata.txt ]; then
  {
    echo "inicio: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "ollama: $(ollama --version 2>/dev/null)"
    echo "hardware: $(sysctl -n machdep.cpu.brand_string 2>/dev/null) | RAM $(($(sysctl -n hw.memsize)/1073741824)) GB"
    echo "macOS: $(sw_vers -productVersion 2>/dev/null)"
    echo "modelos:"; ollama list | grep -E 'gemma'
    for m in "$GEMMA" "$CODEGEMMA"; do echo "--- $m"; ollama show "$m"; done
    echo "num_ctx=$NUM_CTX seed=$SEED temperature=0"
    echo "md5 (prompts e scripts):"
    md5 -r prompts/prompt_config.json prompts/P0_original.txt scripts/*.py data/sample_manifest.csv 2>/dev/null
  } > results/run_metadata.txt
  echo "== ambiente registrado em results/run_metadata.txt =="
fi

caffeinate -dimsu -w $$ &

echo "===== FASE 4a: BATERIA PRINCIPAL (484 arquivos x 2 modelos x 4 prompts) ====="
python3 scripts/run_inference.py --config "$CFG" --cwe79 "$CWE79" --cwe89 "$CWE89" \
  --manifest data/sample_manifest.csv \
  --models "${GEMMA}=${GD},${CODEGEMMA}=${CD}" \
  --quantization "$QUANT" --num-ctx "$NUM_CTX" --seed "$SEED" \
  --out logs/main.jsonl --repeat-index 1

echo "===== FASE 4b: ESTABILIDADE (24 pares, execuções 2 a 10) ====="
[ -f data/stability_manifest.csv ] || python3 scripts/build_stability.py \
  --manifest data/sample_manifest.csv --out data/stability_manifest.csv --seed "$SEED"
for k in 2 3 4 5 6 7 8 9 10; do
  echo "--- execução $k/10"
  python3 scripts/run_inference.py --config "$CFG" --cwe79 "$CWE79" --cwe89 "$CWE89" \
    --manifest data/stability_manifest.csv \
    --models "${GEMMA}=${GD},${CODEGEMMA}=${CD}" \
    --quantization "$QUANT" --num-ctx "$NUM_CTX" --seed "$SEED" \
    --out logs/stability.jsonl --repeat-index "$k"
done

echo "===== PARSE ====="
python3 scripts/parse_outputs.py --in logs/main.jsonl --out logs/main_parsed.jsonl
python3 scripts/parse_outputs.py --in logs/stability.jsonl --out logs/stability_parsed.jsonl
python3 - <<'PY'
import json
for f in ("logs/main_parsed.jsonl", "logs/stability_parsed.jsonl"):
    rows = [json.loads(l) for l in open(f)]
    print(f, "| linhas:", len(rows), "| cortadas (context_overflow):", sum(1 for r in rows if r.get("context_overflow")))
PY
echo "FASE 4 OK. Me avise para eu ler os logs e fazer a Fase 5."
