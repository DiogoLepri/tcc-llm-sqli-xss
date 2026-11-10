#!/usr/bin/env bash
# setup_mac.sh — prepara o projeto no macOS (roda UMA vez).
# Clona os artefatos, confere/baixa os modelos e registra tag + hash.
set -euo pipefail
cd "$(dirname "$0")/.."           # raiz do TCC/
ROOT="$(pwd)"
echo "== TCC em: $ROOT =="

# --- Ollama vivo? ---
if ! command -v ollama >/dev/null; then
  echo "ERRO: ollama não encontrado. Instale em https://ollama.com e rode de novo."; exit 1
fi
if ! curl -s -m 5 http://localhost:11434/api/tags >/dev/null; then
  echo "ERRO: servidor Ollama não responde em localhost:11434. Abra o app Ollama e tente de novo."; exit 1
fi

# --- Artefatos ---
mkdir -p data logs results
if [ ! -d data/sovrano ]; then
  echo "== clonando artefato Sovrano =="
  git clone --depth 1 https://github.com/Francesco-Sovrano/llms_for_vulnerability_detection_are_lost_in_the_end.git data/sovrano
fi
if [ ! -d data/secllmholmes ]; then
  echo "== clonando SecLLMHolmes =="
  git clone --depth 1 https://github.com/ai4cloudops/SecLLMHolmes.git data/secllmholmes
fi

# --- Modelos (variantes instruct) ---
MODELS=("gemma:7b-instruct" "codegemma:7b-instruct")
for m in "${MODELS[@]}"; do
  if ollama list | awk '{print $1}' | grep -qx "$m"; then
    echo "== já instalado: $m =="
  else
    echo "== baixando $m (~5 GB) =="
    ollama pull "$m"
  fi
done

echo; echo "== VERSÕES/HASH (registrar no artigo) =="
ollama list | grep -E 'gemma' || true
for m in "${MODELS[@]}"; do
  echo "--- $m ---"; ollama show "$m" 2>/dev/null | grep -iE 'architecture|parameters|quantization|context' || true
done

echo; echo "Setup OK. Agora rode: bash scripts/run_pilot.sh"
