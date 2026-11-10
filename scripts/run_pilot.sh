#!/usr/bin/env bash
# run_pilot.sh — FASE 1 (elegibilidade) + FASE 3 (piloto). Roda no macOS.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

CWE79=data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv
CWE89=data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv
CFG=prompts/prompt_config.json
NUM_CTX=8192
RESERVE=512
SEED=2026
GEMMA="gemma:7b-instruct"
CODEGEMMA="codegemma:7b-instruct"

# hash (coluna ID do ollama list) para rastreabilidade
digest () { ollama list | awk -v m="$1" '$1==m{print $3}'; }
GD="$(digest "$GEMMA")"; CD="$(digest "$CODEGEMMA")"
# quantização real do codegemma (usado como tokenizer de referência do filtro)
QUANT="$(ollama show "$CODEGEMMA" 2>/dev/null | grep -i quantization | awk '{print $NF}' | head -1)"
[ -z "${QUANT:-}" ] && QUANT="unknown"

echo "== caffeinate ligado (Mac não dorme) =="
caffeinate -dimsu -w $$ &

echo; echo "===== FASE 1: ELEGIBILIDADE (tokenizer real via Ollama, prompt P3, reserva ${RESERVE}) ====="
python3 scripts/build_sample.py \
  --cwe79 "$CWE79" --cwe89 "$CWE89" --prompts "$CFG" \
  --tokenizer-mode ollama --tokenizer-model "$CODEGEMMA" \
  --num-ctx "$NUM_CTX" --response-reserve "$RESERVE" --seed "$SEED" \
  --out data/sample_manifest.csv --dropped data/dropped_pairs.csv \
  --report results/phase1_sample_report.json \
  $( [ -f data/token_counts_v2_ctx8192.csv ] && echo "--counts-cache data/token_counts_v2_ctx8192.csv --cache-trunc-value 4099" )

echo; echo "===== FASE 3: PILOTO (10 pares por CWE x 2 modelos x 4 prompts) ====="
python3 scripts/run_inference.py \
  --config "$CFG" --cwe79 "$CWE79" --cwe89 "$CWE89" \
  --manifest data/sample_manifest.csv \
  --models "${GEMMA}=${GD},${CODEGEMMA}=${CD}" \
  --quantization "$QUANT" --num-ctx "$NUM_CTX" --seed "$SEED" \
  --out logs/pilot.jsonl --limit-per-cwe 5 --repeat-index 1

echo; echo "===== PARSE (taxa de não-parseáveis) ====="
python3 scripts/parse_outputs.py --in logs/pilot.jsonl --out logs/pilot_parsed.jsonl

echo; echo "PILOTO OK. Resultados em logs/ e results/. Pode me avisar que eu leio e faço o relatório."
