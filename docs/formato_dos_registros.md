# Formato dos registros (`logs/*.jsonl`)

Cada linha é uma execução (um arquivo enviado a um modelo com um prompt).

| Campo | Descrição |
|---|---|
| `run_id` | Identificador único (modelo, prompt, CWE, arquivo, versão). |
| `file_id` / `pair_id` | Identificador do arquivo no artefato e do par vulnerável/corrigido. |
| `cwe` / `type` / `ground_truth` | CWE-79 ou CWE-89; `buggy` ou `not_buggy`; `vulnerable` ou `safe`. |
| `model_tag` / `model_digest` | Nome do modelo no Ollama e identificador (hash) dos pesos. |
| `quantization` / `num_ctx` | Q4_0 e janela de 8.192 tokens nos modelos de 7B; nvfp4 e 16.384 no Gemma 4. |
| `prompt_id` | P0, P1, P2 ou P3. |
| `temperature` / `seed` | 0 e 2026. |
| `input_tokens` / `output_tokens` | Contagens informadas pelo Ollama. |
| `latency_ms` | Tempo total da execução (registrado, não analisado). |
| `context_overflow` | Indica entrada perto do limite ou com o sinal de corte do Ollama. |
| `raw_response` | Resposta original, sem edição. |
| `repeat_index` | 1 na bateria principal. |
| `think` / `raw_thinking` | Só em `new_models.jsonl`: modo de raciocínio do modelo (desligado no Gemma 4) e o texto de raciocínio, se houver. |

O veredito e a classificação (VP, FP, VN ou FN) são calculados a partir de `raw_response` pelos scripts de análise, sem alterar o log.

Uma interrupção durante a coleta de `main.jsonl` fez 1.091 execuções serem repetidas; a análise usa a primeira ocorrência de cada uma, e todas as repetições tiveram resposta idêntica à primeira.

Em `new_models.jsonl` (Gemma 4, `gemma4:12b`), 1.931 das 1.936 respostas previstas foram registradas. Faltam cinco, todas de versões corrigidas de XSS: arquivo 7625 com P0; arquivo 61 com P2; arquivo 7804 com P1, P2 e P3.
