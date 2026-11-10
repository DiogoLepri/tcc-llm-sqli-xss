# LLMs na detecção de SQL Injection e XSS: replicação e comparação de prompts

Material do Trabalho de Conclusão de Curso de **Diogo Lepri Moreira** (Ciência da Computação, Centro Universitário Filadélfia – UniFil), orientado pelo Prof. João Vitor da Costa Andrade.

O trabalho tem duas etapas:

1. **Reprodução parcial** de Sovrano, Bauer e Bacchelli (2025): as métricas do artigo são recalculadas a partir das respostas publicadas pelos autores (48 valores, todos iguais aos reportados).
2. **Nova execução**: Gemma 7B e CodeGemma 7B, rodando localmente no Ollama, classificam 60 pares de arquivos vulnerável/corrigido (30 de CWE-79 e 30 de CWE-89) com dois prompts, P0 (original do estudo-base) e P3 (papel de especialista + definição da CWE, adaptado do template D2 do SecLLMHolmes).

## Resultado principal

| Modelo | Prompt | Acurácia | Precisão | Recall | F1 | FPR | FN |
|---|---|---|---|---|---|---|---|
| Gemma 7B | P0 | 0,500 | 0,500 | 0,783 | 0,610 | 0,783 | 13 |
| Gemma 7B | P3 | 0,500 | 0,500 | 0,850 | 0,630 | 0,850 | 9 |
| CodeGemma 7B | P0 | 0,508 | 0,505 | 0,917 | 0,651 | 0,900 | 5 |
| CodeGemma 7B | P3 | 0,508 | 0,504 | 0,967 | 0,663 | 0,950 | 2 |

120 arquivos por condição (60 vulneráveis e 60 corrigidos). Um classificador que responde sempre "vulnerável" teria F1 de 0,667 nesta amostra. O teste exato de McNemar não apontou diferença entre modelos nem entre prompts (p = 1,000 nas quatro comparações). Todos os números estão em `results/analysis60.json`.

### Confirmação com a amostra completa

A mesma análise, repetida sobre os 242 pares coletados (484 arquivos por condição), levou à mesma conclusão:

| Modelo | Prompt | Acurácia | Precisão | Recall | F1 | FPR | Pares separados / invertidos |
|---|---|---|---|---|---|---|---|
| Gemma 7B | P0 | 0,498 | 0,499 | 0,822 | 0,621 | 0,826 | 8 / 9 |
| Gemma 7B | P3 | 0,504 | 0,502 | 0,847 | 0,631 | 0,839 | 9 / 7 |
| CodeGemma 7B | P0 | 0,502 | 0,501 | 0,901 | 0,644 | 0,897 | 2 / 1 |
| CodeGemma 7B | P3 | 0,500 | 0,500 | 0,955 | 0,656 | 0,955 | 1 / 1 |

O teste de McNemar também não apontou diferença (p ajustado = 1,000 nas quatro comparações). Os números estão em `results/analysis242.json`.

## Estrutura

```
├── data/
│   ├── sample_manifest.csv        # 242 pares coletados (121 por CWE)
│   ├── sample60_manifest.csv      # 60 pares analisados no artigo
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
git clone --depth 1 https://github.com/Francesco-Sovrano/llms_for_vulnerability_detection_are_lost_in_the_end.git data/sovrano
python3 scripts/analyze60.py --root .
```

O script sorteia os 60 pares (semente 2026, estratificados por quartil de tamanho, usando só o tamanho dos arquivos), lê `logs/main.jsonl`, calcula as métricas e o teste de McNemar e grava `results/analysis60.json`.

Para a confirmação com os 242 pares coletados (não precisa do conjunto de dados do estudo-base):

```bash
python3 scripts/analyze242.py --root .
```

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

Requer macOS com Ollama. `scripts/setup_mac.sh` baixa os artefatos e os modelos; `scripts/run_pilot.sh` filtra os pares por tamanho e roda o piloto; `scripts/run_main.sh` roda a bateria completa.

Configuração usada (registrada em `results/run_metadata.txt`): Ollama 0.40.11; `gemma:7b-instruct` (a72c7f4d0a15) e `codegemma:7b-instruct` (0c96700aaada), quantização Q4_0; temperatura 0, semente 2026, janela de 8.192 tokens; MacBook Pro M4 Pro com 24 GB de memória unificada.

## Observações sobre os registros

- `logs/main.jsonl` contém 1.091 linhas repetidas, geradas por uma falha na retomada de uma execução interrompida. A análise usa a **primeira** ocorrência de cada inferência; as repetições têm resposta idêntica.
- A coleta incluiu quatro prompts (P0 a P3) e 242 pares. O artigo analisa P0 e P3 em 60 pares, por decisão de escopo. As demais respostas e `logs/stability.jsonl` (execuções repetidas) estão aqui, mas não foram usados no artigo.
- Respostas sem a linha `BUG FOUND` são contadas como "não sinalizou", como no estudo-base.
- Os campos de cada registro estão descritos no Apêndice B do artigo.

## Referências

- SOVRANO, F.; BAUER, A.; BACCHELLI, A. Large language models for in-file vulnerability localization can be "lost in the end". *Proceedings of the ACM on Software Engineering*, v. 2, n. FSE, 2025. DOI: 10.1145/3715758. Artefato: DOI 10.5281/zenodo.14840519.
- ULLAH, S. et al. LLMs cannot reliably identify and reason about security vulnerabilities (yet?). *IEEE Symposium on Security and Privacy*, 2024. DOI: 10.1109/SP54263.2024.00210.
