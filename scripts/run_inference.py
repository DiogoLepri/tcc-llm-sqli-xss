#!/usr/bin/env python3
"""
run_inference.py — coleta de inferências via Ollama (roda no Mac).

- Cada inferência é uma sessão ISOLADA (uma chamada /api/chat stateless, sem
  carregar contexto de chamadas anteriores).
- Parâmetros FIXOS: temperature=0, seed=2026, num_ctx=8192 (iguais nos 2 modelos).
- P0: mensagem única de usuário (sem system). P1-P3: system + user.
- Ordem das 8 condições (2 modelos x 4 prompts) embaralhada POR ARQUIVO (seed 2026).
- Salva JSONL incremental e RETOMÁVEL: relê o arquivo e pula o que já foi feito.
- Guarda a resposta BRUTA sem editar. Campos do Apêndice B (parsing fica no Fase 5).

Uso (piloto):
  python run_inference.py --config ../prompts/prompt_config.json \
    --cwe79 ../data/sovrano/1_all_files_analysis/cve_data/files_CWE-79.csv \
    --cwe89 ../data/sovrano/1_all_files_analysis/cve_data/files_CWE-89.csv \
    --manifest ../data/sample_manifest.csv \
    --models "gemma:7b-instruct=<digest>,codegemma:7b-instruct=<digest>" \
    --quantization Q4_0 --num-ctx 8192 --seed 2026 \
    --out ../logs/pilot.jsonl --limit-per-cwe 10 --repeat-index 1
"""
import argparse, csv, json, os, random, sys, time, urllib.request

csv.field_size_limit(10**9)
OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/chat"


def load_csv(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return {r["file_id"]: r for r in csv.DictReader(f)}


def build_messages(cfg, cwe, prompt_id, code):
    if prompt_id == "P0":
        p0 = open(os.path.join(os.path.dirname(cfg["_path"]), "P0_original.txt"), encoding="utf-8").read()
        label = cfg["cwe_ref_P0"][cwe]
        user = p0.replace("{bug_type_id}", cwe).replace("{bug_type_label}", label).replace("{file_content}", code)
        return [{"role": "user", "content": user}]
    key = {"P1": "P1_S1", "P2": "P2_S3", "P3": "P3_D2"}[prompt_id]
    spec = cfg["prompts"][cwe][key]
    msgs = []
    if spec["system"]:
        msgs.append({"role": "system", "content": spec["system"]})
    msgs.append({"role": "user", "content": spec["user"].replace("{code}", code)})
    return msgs


def chat(model, messages, num_ctx, seed, timeout=900, think=None):
    payload = {"model": model, "messages": messages, "stream": False,
               "options": {"temperature": 0, "seed": seed, "num_ctx": num_ctx}}
    if think is not None:            # só para modelos com modo de raciocínio (ex.: gemma4)
        payload["think"] = think
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(OLLAMA, data=data, headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        resp = json.loads(r.read().decode("utf-8"))
    dt = int((time.time() - t0) * 1000)
    return resp, dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--cwe79", required=True)
    ap.add_argument("--cwe89", required=True)
    ap.add_argument("--manifest", required=True, help="sample_manifest.csv (cwe,file_id,...)")
    ap.add_argument("--models", required=True, help="tag=digest,tag=digest")
    ap.add_argument("--quantization", required=True)
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit-per-cwe", type=int, default=0, help="piloto: N pares por CWE (0=todos)")
    ap.add_argument("--repeat-index", type=int, default=1)
    ap.add_argument("--think", choices=["default", "off", "on"], default="default",
                    help="modo de raciocínio do Ollama: default = não envia o campo (coleta original)")
    args = ap.parse_args()

    cfg = json.load(open(args.config, encoding="utf-8"))
    cfg["_path"] = os.path.abspath(args.config)
    src = {"79": load_csv(args.cwe79), "89": load_csv(args.cwe89)}
    models = [m.split("=", 1) for m in args.models.split(",")]  # [[tag,digest],...]

    # manifesto -> lista de (cwe, file_id)
    pairs = []
    with open(args.manifest, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            pairs.append((r["cwe"], r["file_id"]))
    if args.limit_per_cwe:
        seen = {"79": 0, "89": 0}; keep = []
        for cwe, fid in pairs:
            if seen[cwe] < args.limit_per_cwe:
                keep.append((cwe, fid)); seen[cwe] += 1
        pairs = keep

    # retomada: chaves já feitas
    done = set()
    if os.path.exists(args.out):
        for line in open(args.out, encoding="utf-8"):
            try:
                d = json.loads(line)
                # o log grava "CWE-89"; o manifesto usa "89". Sem normalizar, a retomada
                # nunca reconhecia o que já tinha rodado e recomeçava do zero.
                c = str(d["cwe"]).replace("CWE-", "")
                done.add((d["model_tag"], d["prompt_id"], c, str(d["file_id"]), d["type"], int(d["repeat_index"])))
            except Exception:
                pass

    prompt_ids = ["P0", "P1", "P2", "P3"]
    out = open(args.out, "a", encoding="utf-8")
    n_total = n_new = 0
    for cwe, fid in pairs:
        row = src[cwe].get(fid)
        if not row:
            print(f"[WARN] file_id {fid} (CWE-{cwe}) ausente no CSV", file=sys.stderr); continue
        files = [("buggy", "vulnerable", row["file_before"] or ""),
                 ("not_buggy", "safe", row["file_after"] or "")]
        # condições (modelo x prompt) embaralhadas POR ARQUIVO (determinístico)
        conds = [(mt, md, pid) for (mt, md) in models for pid in prompt_ids]
        random.Random(f"{args.seed}:{cwe}:{fid}").shuffle(conds)
        for ftype, gt, code in files:
            for mtag, mdigest, pid in conds:
                n_total += 1
                key = (mtag, pid, cwe, fid, ftype, args.repeat_index)
                if key in done:
                    continue
                messages = build_messages(cfg, cwe, pid, code)
                try:
                    think = {"default": None, "off": False, "on": True}[args.think]
                    resp, dt = chat(mtag, messages, args.num_ctx, args.seed, think=think)
                    raw = resp.get("message", {}).get("content", "")
                    rec = {
                        "run_id": f"{mtag}|{pid}|{cwe}|{fid}|{ftype}|r{args.repeat_index}",
                        "pair_id": f"CWE-{cwe}:{fid}", "file_id": fid, "cwe": f"CWE-{cwe}",
                        "ground_truth": gt, "type": ftype,
                        "model_tag": mtag, "model_digest": mdigest,
                        "quantization": args.quantization, "num_ctx": args.num_ctx,
                        "prompt_id": pid, "temperature": 0, "seed": args.seed,
                        "input_tokens": resp.get("prompt_eval_count"),
                        "output_tokens": resp.get("eval_count"),
                        "latency_ms": dt, "raw_response": raw,
                        # proteção: entrada perto do teto = possível corte silencioso do runtime
                        # truncado = perto do teto OU na assinatura de corte do Ollama (~metade da janela)
                        "context_overflow": bool(resp.get("prompt_eval_count") and (
                            resp.get("prompt_eval_count") >= args.num_ctx - 512 or
                            args.num_ctx // 2 <= resp.get("prompt_eval_count") <= args.num_ctx // 2 + 16)),
                        "repeat_index": args.repeat_index,
                        "think": args.think, "raw_thinking": resp.get("message", {}).get("thinking"),
                        # preenchidos no Fase 5:
                        "parsed_verdict": None, "reported_bug_line": None,
                        "tp": None, "fp": None, "tn": None, "fn": None,
                        "fabricated_claim": None, "localization_hit": None,
                        "review_status": "automatic",
                    }
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n"); out.flush()
                    n_new += 1
                    print(f"  ok {mtag} {pid} CWE-{cwe}/{fid} {ftype} {dt}ms "
                          f"in={rec['input_tokens']} out={rec['output_tokens']}")
                except Exception as e:
                    print(f"[ERRO] {key}: {e}", file=sys.stderr)
    out.close()
    print(f"\nFeito. inferências novas: {n_new} | total alvo visto: {n_total} | já existiam: {n_total-n_new}")


if __name__ == "__main__":
    main()
