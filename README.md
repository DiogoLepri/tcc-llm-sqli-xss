# LLMs na detecção de SQL Injection e XSS: replicação e comparação de prompts

Material do Trabalho de Conclusão de Curso de **Diogo Lepri Moreira** (Ciência da Computação, Centro Universitário Filadélfia – UniFil), orientado pelo Prof. João Vitor da Costa Andrade.

O trabalho tem duas etapas:

1. **Reprodução parcial** de Sovrano, Bauer e Bacchelli (2025): as métricas do artigo são recalculadas a partir das respostas publicadas pelos autores (48 valores, todos iguais aos reportados).
2. **Nova execução**: Gemma 7B e CodeGemma 7B, rodando localmente no Ollama, classificam 242 pares de arquivos vulnerável/corrigido (121 de XSS e 121 de SQL Injection) com quatro prompts: P0 (original do estudo-base), P1 (pergunta do SecLLMHolmes), P2 (P1 + papel de especialista) e P3 (P2 + definição da falha).

## Resultado principal

| Modelo | Prompt | VP | FN | FP | VN | Acurácia | Recall | F1 | Taxa de FP | Pares separados / invertidos |
|---|---|---|---|---|---|---|---|---|---|---|
| Gemma 7B | P0 | 199 | 43 | 200 | 42 | 0,498 | 0,822 | 0,621 | 0,826 | 8 / 9 |
| Gemma 7B | P1 | 184 | 57 | 189 | 52 | 0,490 | 0,763 | 0,599 | 0,784 | 13 / 18 |
| Gemma 7B | P2 | 188 | 54 | 191 | 51 | 0,494 | 0,777 | 0,605 | 0,789 | 11 / 14 |
| Gemma 7B | P3 | 205 | 37 | 203 | 39 | 0,504 | 0,847 | 0,631 | 0,839 | 9 / 7 |
| CodeGemma 7B | P0 | 218 | 24 | 217 | 25 | 0,502 | 0,901 | 0,644 | 0,897 | 2 / 1 |
| CodeGemma 7B | P1 | 220 | 22 | 222 | 20 | 0,496 | 0,909 | 0,643 | 0,917 | 3 / 5 |
| CodeGemma 7B | P2 | 227 | 15 | 228 | 14 | 0,498 | 0,938 | 0,651 | 0,942 | 3 / 4 |
| CodeGemma 7B | P3 | 231 | 11 | 231 | 11 | 0,500 | 0,955 | 0,656 | 0,955 | 1 / 1 |

484 arquivos por condição (242 vulneráveis e 242 corrigidos; 482 no Gemma 7B com P1, em que duas respostas não foram registradas). Um classificador que responde sempre "vulnerável" teria F1 de 0,667. O teste exato de McNemar não apontou diferença entre os modelos nem entre os prompts (p ajustado = 1,000 nas dez comparações). Todos os números estão em `results/analysis_full.json`.

As versões anteriores do artigo usavam uma subamostra de 60 pares e dois prompts (`results/analysis60.json` e `results/analysis242.json`); a conclusão é a mesma.

## Estrutura

```
├── data/
│   ├── sample_manifest.csv        # 242 pares analisados no artigo (121 por tipo de falha)
│   ├── sample60_manifest.csv      # subamostra de 60 pares das versões anteriores
│   ├── stability_manifest.csv     # pares das execuções repetidas (não usadas no artigo)
│   ├── dropped_pairs.csv          # pares descartados por não caberem na janela de contexto
│   └── token_counts_*.csv         # contagem de tokens de cada par
├── prompts/
│   ├── P0_original.txt            # prompt original do estudo-base, sem alterações
│   ├── prompt_config.json         # P0 a P3: mensagens de sistema e do usuário, definições das CWEs
│   └── *.preview.txt              # pré-visualização de cada prompt
├── scripts/                       # preparação, coleta e análise
├── logs/                          # respostas brutas dos modelos (JSONL), sem edição
└── results/                       # métricas, relatório da amostra e metadados da execução
```

O conjunto de dados do estudo-base e o SecLLMHolmes **não** estão neste repositório; `scripts/setup_mac.sh` os baixa das fontes originais para `data/sovrano` e `data/secllmholmes`.

## Como refazer a análise

Requer Python 3.10 ou superior, sem bibliotecas externas.

```bash
python3 scripts/analyze_full.py --root .
```

O script lê `logs/main.jsonl` (e `logs/new_models.jsonl`, se existir), calcula as métricas, o resultado por par e o teste de McNemar para os 242 pares e os quatro prompts, e grava `results/analysis_full.json`. Não precisa do conjunto de dados do estudo-base.

Para a reprodução do estudo-base:

```bash
python3 scripts/metrics.py reproduce \
  --outputs data/sovrano/1_all_files_analysis/model_outputs \
  --reported data/sovrano/1_all_files_analysis/results/performance_summary.csv \
  --cwe79 data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv \
  --cwe89 data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv \
  --out results/phase2_reproduction.csv
```

## Como refazer a coleta

Requer macOS com Ollama. `scripts/setup_mac.sh` baixa os artefatos e os modelos; `scripts/run_pilot.sh` filtra os pares por tamanho e roda o piloto; `scripts/run_main.sh` roda a bateria completa. `scripts/run_new_models.sh` repete a mesma bateria com outros modelos do Ollama (por padrão, `gemma4:12b`) e grava em `logs/new_models.jsonl`.

Configuração usada (registrada em `results/run_metadata.txt`): Ollama 0.40.11; `gemma:7b-instruct` (a72c7f4d0a15) e `codegemma:7b-instruct` (0c96700aaada), quantização Q4_0; temperatura 0, semente 2026, janela de 8.192 tokens; MacBook Pro M4 Pro com 24 GB de memória unificada.

## Observações sobre os registros

- `logs/main.jsonl` contém 1.091 linhas repetidas, geradas por uma falha na retomada de uma execução interrompida. A análise usa a **primeira** ocorrência de cada inferência; as repetições têm resposta idêntica.
- A coleta incluiu quatro prompts (P0 a P3) e 242 pares. O artigo analisa P0 e P3 em 60 pares, por decisão de escopo. As demais respostas e `logs/stability.jsonl` (execuções repetidas) estão aqui, mas não foram usados no artigo.
- Respostas sem a linha `BUG FOUND` são contadas como "não sinalizou", como no estudo-base.
- Os campos de cada registro estão descritos no Apêndice B do artigo.

## Referências

- SOVRANO, F.; BAUER, A.; BACCHELLI, A. Large language models for in-file vulnerability localization can be "lost in the end". *Proceedings of the ACM on Software Engineering*, v. 2, n. FSE, 2025. DOI: 10.1145/3715758. Artefato: DOI 10.5281/zenodo.14840519.
- ULLAH, S. et al. LLMs cannot reliably identify and reason about security vulnerabilities (yet?). *IEEE Symposium on Security and Privacy*, 2024. DOI: 10.1109/SP54263.2024.00210.

## RQ3: Gemma 4 (`gemma4:12b`)

Mesmos 484 arquivos e quatro prompts; quantização nvfp4, Ollama 0.40.15, janela de 16.384 tokens, modo de raciocínio desligado. 1.935 das 1.936 respostas previstas foram registradas (ver `docs/formato_dos_registros.md`).

| Condição | VP | FN | FP | VN | Acurácia | Precisão | Recall | F1 | Taxa de FP | Pares certos |
|---|---|---|---|---|---|---|---|---|---|---|
| Gemma 4 12B · P0 | 223 | 19 | 201 | 41 | 0,545 | 0,526 | 0,921 | 0,670 | 0,831 | 28 de 242 |
| Gemma 4 12B · P1 | 201 | 41 | 164 | 77 | 0,576 | 0,551 | 0,831 | 0,662 | 0,680 | 42 de 241 |
| Gemma 4 12B · P2 | 206 | 36 | 167 | 75 | 0,581 | 0,552 | 0,851 | 0,670 | 0,690 | 46 de 242 |
| Gemma 4 12B · P3 | 210 | 32 | 178 | 64 | 0,566 | 0,541 | 0,868 | 0,667 | 0,736 | 39 de 242 |
