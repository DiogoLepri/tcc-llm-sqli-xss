#!/usr/bin/env bash
# run_new_models.sh — mesma bateria (242 pares x 2 versões x 4 prompts) com modelos atuais. Roda no macOS.
#
# Uso:
#   bash scripts/run_new_models.sh pilot      # 5 pares por CWE, para ver se o modelo respeita o formato (uns 15 min)
#   bash scripts/run_new_models.sh            # bateria completa (retomável: se parar, rode de novo)
#
# Para trocar ou acrescentar modelos:  MODELS="gemma4:12b devstral-small-2:24b" bash scripts/run_new_models.sh
#
# Diferenças em relação à coleta original (registradas em results/run_metadata_new_models.txt):
#   - num_ctx = 16384 (a janela original, 8192, valia para o tokenizador do Gemma 7B; outro tokenizador
#     pode gerar mais tokens para o mesmo arquivo, e o Ollama corta sem avisar);
#   - think = off (o Gemma 4 tem modo de raciocínio; desligado para manter uma resposta única, como antes).
# Temperatura 0, semente 2026, prompts e pares são os mesmos.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-full}"
MODELS="${MODELS:-gemma4:12b}"
CWE79=data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv
CWE89=data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv
CFG=prompts/prompt_config.json
NUM_CTX=16384; SEED=2026
mkdir -p results logs

[ -f "$CWE79" ] || { echo "Faltam os dados do estudo-base em data/sovrano (veja o README)."; exit 1; }

# 1) completa as 2 inferências que ficaram faltando na coleta original (Gemma 7B, par 378 de CWE-89)
if [ "${COMPLETE_ORIGINAL:-0}" = "1" ] && [ "$MODE" != "pilot" ] && ollama list | grep -q '^gemma:7b-instruct'; then
  GD="$(ollama list | awk '$1=="gemma:7b-instruct"{print $2}')"; CD="$(ollama list | awk '$1=="codegemma:7b-instruct"{print $2}')"
  echo "===== completando a coleta original (só o que falta) ====="
  python3 scripts/run_inference.py --config "$CFG" --cwe79 "$CWE79" --cwe89 "$CWE89" \
    --manifest data/sample_manifest.csv --models "gemma:7b-instruct=${GD},codegemma:7b-instruct=${CD}" \
    --quantization Q4_0 --num-ctx 8192 --seed "$SEED" --out logs/main.jsonl --repeat-index 1
fi

caffeinate -dimsu -w $$ &

for M in $MODELS; do
  echo "===== modelo: $M ====="
  ollama pull "$M"
  D="$(ollama list | awk -v m="$M" '$1==m{print $2}')"
  Q="$(ollama show "$M" 2>/dev/null | grep -i quantization | awk '{print $NF}' | head -1)"
  THINK=default; case "$M" in gemma4*) THINK=off;; esac
  {
    echo "=== $M | inicio: $(date -u +%Y-%m-%dT%H:%M:%SZ) | modo: $MODE"
    echo "ollama: $(ollama --version 2>/dev/null)"
    echo "hardware: $(sysctl -n machdep.cpu.brand_string 2>/dev/null) | RAM $(($(sysctl -n hw.memsize)/1073741824)) GB"
    echo "digest=$D quantization=$Q num_ctx=$NUM_CTX seed=$SEED temperature=0 think=$THINK"
    ollama show "$M"
  } >> results/run_metadata_new_models.txt
  if [ "$MODE" = "pilot" ]; then OUT=logs/pilot_new_models.jsonl; LIM="--limit-per-cwe 5"; else OUT=logs/new_models.jsonl; LIM=""; fi
  python3 scripts/run_inference.py --config "$CFG" --cwe79 "$CWE79" --cwe89 "$CWE89" \
    --manifest data/sample_manifest.csv --models "${M}=${D}" \
    --quantization "${Q:-desconhecida}" --num-ctx "$NUM_CTX" --seed "$SEED" --think "$THINK" \
    --out "$OUT" --repeat-index 1 $LIM
done

python3 - "$MODE" <<'PY'
import json, sys, collections
sys.path.insert(0, "scripts")
from parse_outputs import parse
f = "logs/pilot_new_models.jsonl" if sys.argv[1] == "pilot" else "logs/new_models.jsonl"
n = collections.Counter(); un = collections.Counter(); yes = collections.Counter(); ov = collections.Counter(); lat = collections.Counter()
for l in open(f, encoding="utf-8"):
    d = json.loads(l); k = (d["model_tag"], d["prompt_id"]); v, _ = parse(d["raw_response"])
    n[k] += 1; un[k] += v is None; yes[k] += v == "vulnerable"; ov[k] += bool(d.get("context_overflow")); lat[k] += d["latency_ms"]
print("\nmodelo | prompt | respostas | sem veredito | YES | possível corte | segundos por resposta")
for k in sorted(n):
    print(f"{k[0]} | {k[1]} | {n[k]} | {un[k]} | {yes[k]} | {ov[k]} | {lat[k]/n[k]/1000:.1f}")
print("\nPronto. Avise o Claude para ler", f)
PY
