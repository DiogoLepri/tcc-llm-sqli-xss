#!/usr/bin/env python3
"""
build_sample.py — FASE 1: elegibilidade + amostragem determinística.

Regra de elegibilidade (Seção 3 / Apêndice A do TCC):
  Um PAR entra na amostra somente se o arquivo inteiro + o prompt couberem no
  contexto, SEM TRUNCAR. Como cada par gera 2 inferências (file_before e
  file_after) e rodamos 4 prompts, o par só é elegível se AMBOS os arquivos
  couberem sob o PROMPT MAIS LONGO (P3/D2, que injeta a definição MITRE),
  deixando uma reserva para a resposta do modelo.

  cabe  <=>  n_tokens(prompt_render(arquivo)) + response_reserve <= num_ctx

Amostra:
  - CWE-89: todos os pares ELEGÍVEIS.
  - CWE-79: o MESMO número de pares, estratificado por quartil de tamanho
    (tokens do maior dos dois arquivos), sorteio determinístico com seed 2026.

Contagem de tokens: usa o tokenizer REAL do modelo via transformers
(SentencePiece do Gemma/CodeGemma). NUNCA estima por caractere — se o tokenizer
não estiver disponível, o script aborta. Gemma 7B e CodeGemma 7B compartilham o
mesmo tokenizer, então um só é suficiente, mas confirme com --tokenizer.

Uso:
  python build_sample.py \
      --cwe79 ../data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv \
      --cwe89 ../data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv \
      --prompts ../prompts/prompt_config.json \
      --tokenizer-mode ollama --tokenizer-model codegemma:7b-instruct \
      --num-ctx 8192 --response-reserve 512 \
      --seed 2026 \
      --out ../data/sample_manifest.csv \
      --dropped ../data/dropped_pairs.csv \
      --report ../results/phase1_sample_report.json
"""
import argparse, csv, json, os, random, sys, statistics as st, urllib.request
csv.field_size_limit(10**9)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def load_pairs(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


TRUNC = 10 ** 6  # sentinela: prompt cortado pelo runtime (não cabe na janela)


def p3_messages(prompt_cfg, cwe, code, key="P3_D2"):
    """Mensagens do prompt MAIS LONGO (P3/D2) — o filtro usa o pior caso.
    key='P1_S1' é usado só para confirmar a assinatura de truncamento."""
    spec = prompt_cfg["prompts"][cwe][key]
    if not spec["system"]:
        return [{"role": "user", "content": spec["user"].replace("{code}", code)}]
    return [{"role": "system", "content": spec["system"]},
            {"role": "user", "content": spec["user"].replace("{code}", code)}]


def make_counter(mode, model, num_ctx=8192):
    """Retorna fn(cfg,cwe,code)->n_tokens. Sem estimativa por caractere.
       mode='ollama'  -> usa o tokenizer REAL do modelo via prompt_eval_count.
       mode='hf'      -> usa transformers AutoTokenizer (modelo gated no HF)."""
    if mode == "ollama":
        def count(cfg, cwe, code, key="P3_D2"):
            # num_predict=1: só precisamos de prompt_eval_count (tokens do prompt);
            # gerar 1 token é instantâneo. num_predict=0 NÃO limita a geração nesta
            # versão do Ollama (gerava resposta inteira -> lentidão de horas).
            payload = {"model": model, "keep_alive": "10m",
                       "messages": p3_messages(cfg, cwe, code, key),
                       "stream": False,
                       # num_ctx EXPLÍCITO: sem ele o Ollama usa o padrão (2048), corta o
                       # prompt em silêncio e devolve a contagem já cortada (bug do 1º filtro:
                       # 94 pares travaram em 2.051 tokens). Com 8192, um prompt que não cabe
                       # volta com contagem >= num_ctx e é excluído pelo orçamento.
                       # O Ollama limita num_ctx ao contexto de treino do modelo (8192 no Gemma):
                       # pedir mais é ignorado. Quando o prompt não cabe, ele guarda só metade
                       # da janela e devolve num_ctx/2 + 3 (2.051 com 2048; 4.099 com 8192),
                       # qualquer que seja o prompt. Essa assinatura é confirmada em main().
                       "options": {"num_predict": 1, "temperature": 0, "num_ctx": num_ctx}}
            req = urllib.request.Request(OLLAMA + "/api/chat",
                                         data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read().decode("utf-8"))
            n = resp.get("prompt_eval_count")
            if n is None:
                sys.exit("[ERRO] Ollama não retornou prompt_eval_count.")
            return n
        return count
    if mode == "hf":
        try:
            from transformers import AutoTokenizer
        except Exception as e:
            sys.exit(f"[ERRO] transformers ausente ({e}). pip install transformers sentencepiece")
        tok = AutoTokenizer.from_pretrained(model)
        def count(cfg, cwe, code, key="P3_D2"):
            msgs = p3_messages(cfg, cwe, code, key)
            text = "\n".join(m["content"] for m in msgs)
            return len(tok(text, add_special_tokens=True)["input_ids"])
        return count
    sys.exit(f"[ERRO] tokenizer-mode inválido: {mode}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cwe79", required=True)
    ap.add_argument("--cwe89", required=True)
    ap.add_argument("--prompts", required=True)
    ap.add_argument("--tokenizer-mode", default="ollama", choices=["ollama", "hf"],
                    help="ollama (prompt_eval_count, tokenizer real do modelo) | hf (transformers)")
    ap.add_argument("--tokenizer-model", required=True,
                    help="ollama: tag do modelo (ex.: codegemma:7b-instruct) | hf: id gated")
    ap.add_argument("--num-ctx", type=int, required=True)
    ap.add_argument("--response-reserve", type=int, default=512)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dropped", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--counts-cache", default=None,
                    help="CSV de contagens anteriores; reaproveita as exatas e reconta as truncadas")
    ap.add_argument("--cache-trunc-value", type=int, default=4099,
                    help="valor que denuncia truncamento no cache (4099 = rodada com num_ctx 8192)")
    args = ap.parse_args()

    cfg = json.load(open(args.prompts, encoding="utf-8"))
    counter = make_counter(args.tokenizer_mode, args.tokenizer_model, args.num_ctx)
    all_counts = []  # contagem de TODOS os pares, para citar no artigo
    budget = args.num_ctx - args.response_reserve
    if budget <= 0:
        sys.exit("[ERRO] num_ctx menor que a reserva de resposta.")

    cache = {}
    if args.counts_cache and os.path.exists(args.counts_cache):
        with open(args.counts_cache, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                cache[(r["cwe"], r["file_id"])] = (int(r["tok_before"]), int(r["tok_after"]))
        print(f"[cache] {len(cache)} pares; valores = {args.cache_trunc_value} serão recontados", flush=True)
    stats = {"reused": 0, "recounted": 0, "truncation_checks": 0, "truncated_files": 0}
    SIG = args.num_ctx // 2 + 3  # assinatura de corte observada (4.099 com 8192)

    def one(cwe, code, cached):
        """Contagem P3 exata, ou TRUNC se o runtime cortaria o prompt."""
        if cached is not None and cached != SIG:
            stats["reused"] += 1
            return cached
        n3 = cached if cached == SIG else counter(cfg, cwe, code)
        if cached is None:
            stats["recounted"] += 1
        if n3 == SIG:
            # P1 e P3 diferem em ~130 tokens (definição da CWE). Se ambos dão SIG,
            # o valor é o corte do runtime, não o tamanho real.
            stats["truncation_checks"] += 1
            if counter(cfg, cwe, code, "P1_S1") == SIG:
                stats["truncated_files"] += 1
                return TRUNC
        return n3

    def pair_tokens(cwe, row):
        c = cache.get((cwe, row["file_id"]))
        tb = one(cwe, row["file_before"] or "", c[0] if c else None)
        if tb == TRUNC:  # par já excluído; não gasta tempo com a outra versão
            return tb, (c[1] if c and c[1] != SIG else TRUNC)
        ta = one(cwe, row["file_after"] or "", c[1] if c else None)
        return tb, ta

    def eligible_set(path, cwe):
        rows = load_pairs(path)
        elig, dropped = [], []
        print(f"[CWE-{cwe}] contando tokens de {len(rows)} pares ({2*len(rows)} arquivos) via Ollama...", flush=True)
        for i, r in enumerate(rows, 1):
            if i % 25 == 0 or i == len(rows):
                print(f"  CWE-{cwe}: {i}/{len(rows)} pares", flush=True)
            tb, ta = pair_tokens(cwe, r)
            size = max(tb, ta)
            rec = {"cwe": cwe, "file_id": r["file_id"], "filename": r["filename"],
                   "ext": r["file_extension"], "tok_before": tb, "tok_after": ta,
                   "tok_max": size}
            all_counts.append(rec)
            if tb <= budget and ta <= budget:
                elig.append(rec)
            else:
                trunc = " [truncado pelo runtime: contagem = num_ctx/2+3 em P1 e P3]" if size == TRUNC else ""
                rec["reason"] = (f"excede contexto: max={size} > budget={budget} "
                                 f"(num_ctx={args.num_ctx} - reserve={args.response_reserve}){trunc}")
                dropped.append(rec)
        return rows, elig, dropped

    _, elig89, drop89 = eligible_set(args.cwe89, "89")
    all79, elig79, drop79 = eligible_set(args.cwe79, "79")

    n_target = len(elig89)  # CWE-79 recebe o mesmo número de pares elegíveis de CWE-89

    # estratificação por quartil de tamanho (tok_max) sobre os ELEGÍVEIS de CWE-79
    sizes = sorted(e["tok_max"] for e in elig79)
    if len(sizes) >= 4:
        qs = st.quantiles(sizes, n=4)  # [Q1,Q2,Q3]
    else:
        qs = [0, 0, 0]

    def quartile(x):
        if x <= qs[0]: return 0
        if x <= qs[1]: return 1
        if x <= qs[2]: return 2
        return 3

    strata = {0: [], 1: [], 2: [], 3: []}
    for e in elig79:
        e["quartile"] = quartile(e["tok_max"])
        strata[e["quartile"]].append(e)

    rng = random.Random(args.seed)
    for k in strata:
        strata[k].sort(key=lambda e: int(e["file_id"]))  # ordem estável antes do shuffle
        rng.shuffle(strata[k])

    # alocação proporcional por quartil, com distribuição determinística do resto
    chosen79 = []
    if n_target > len(elig79):
        sys.exit(f"[ERRO] elegíveis CWE-79 ({len(elig79)}) < alvo ({n_target}). "
                 f"Reveja num_ctx; não há como casar o número de pares.")
    base = {k: (len(strata[k]) * n_target) // max(1, len(elig79)) for k in strata}
    for k in strata:
        chosen79 += strata[k][:base[k]]
    # completa o que faltou para bater n_target, varrendo quartis em ordem
    remaining = n_target - len(chosen79)
    k = 0
    while remaining > 0:
        pool = strata[k % 4][base[k % 4]:]
        if pool:
            chosen79.append(pool.pop(0))
            base[k % 4] += 1
            remaining -= 1
        k += 1
        if k > 10000:
            break

    # grava manifesto
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cwe", "file_id", "filename", "ext", "tok_before", "tok_after", "tok_max", "quartile"])
        for e in elig89:
            w.writerow(["89", e["file_id"], e["filename"], e["ext"], e["tok_before"], e["tok_after"], e["tok_max"], ""])
        for e in sorted(chosen79, key=lambda e: int(e["file_id"])):
            w.writerow(["79", e["file_id"], e["filename"], e["ext"], e["tok_before"], e["tok_after"], e["tok_max"], e["quartile"]])

    with open(args.dropped, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cwe", "file_id", "filename", "ext", "tok_before", "tok_after", "tok_max", "reason"])
        for e in drop89 + drop79:
            w.writerow([e["cwe"], e["file_id"], e["filename"], e["ext"], e["tok_before"], e["tok_after"], e["tok_max"], e["reason"]])

    counts_path = os.path.join(os.path.dirname(args.dropped), "token_counts_all_pairs.csv")
    with open(counts_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cwe", "file_id", "filename", "ext", "tok_before", "tok_after", "tok_max"])
        for e in all_counts:
            w.writerow([e["cwe"], e["file_id"], e["filename"], e["ext"], e["tok_before"], e["tok_after"], e["tok_max"]])

    report = {
        "tokenizer_mode": args.tokenizer_mode, "tokenizer_model": args.tokenizer_model,
        "num_ctx": args.num_ctx, "truncation_signature": SIG,
        "counts_reused_from_cache": stats["reused"], "counts_recounted": stats["recounted"],
        "truncation_checks_P1": stats["truncation_checks"], "files_truncated": stats["truncated_files"],
        "response_reserve": args.response_reserve, "budget_tokens": budget,
        "seed": args.seed,
        "cwe89": {"total": len(elig89) + len(drop89), "eligible": len(elig89), "dropped": len(drop89)},
        "cwe79": {"total": len(all79), "eligible": len(elig79), "dropped": len(drop79),
                  "selected": len(chosen79)},
        "sample_pairs_total": len(elig89) + len(chosen79),
        "sample_files_total": 2 * (len(elig89) + len(chosen79)),
        "inferences_main_battery": 2 * (len(elig89) + len(chosen79)) * 2 * 4,
        "cwe79_quartile_counts_selected": {str(k): sum(1 for e in chosen79 if e["quartile"] == k) for k in range(4)},
    }
    json.dump(report, open(args.report, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
