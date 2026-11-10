#!/usr/bin/env python3
"""
analyze60.py — análise final do TCC (escopo reduzido, decidido com o orientador).

Escopo: 60 pares (30 de CWE-79 + 30 de CWE-89) = 120 arquivos; modelos Gemma 7B e
CodeGemma 7B; prompts P0 e P3. Métricas: acurácia, precisão, recall, F1, FPR, além das
contagens TP/FP/TN/FN. Teste: McNemar exato (binomial) sobre acerto/erro por arquivo,
com correção de Holm para as 4 comparações.

Subamostra: sorteada a partir da amostra de 121 + 121 pares usando SOMENTE o tamanho
dos arquivos (tok_max = maior contagem de tokens entre as duas versões do par, com o
prompt P3) e a seed 2026 — sem olhar nenhuma resposta. Estratificada por quartil de
tamanho dentro de cada CWE (8, 8, 7 e 7 pares por quartil).

Respostas: logs/main.jsonl (bateria principal). Linhas repetidas pela retomada com bug
são descartadas mantendo a PRIMEIRA ocorrência de cada (modelo, prompt, arquivo, versão).
"""
import argparse, csv, json, math, os, random, statistics as st, sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from parse_outputs import parse            # noqa: E402
from metrics import classify_sovrano       # noqa: E402
csv.field_size_limit(10 ** 9)

MODELS = [("gemma:7b-instruct", "Gemma 7B"), ("codegemma:7b-instruct", "CodeGemma 7B")]
PROMPTS = ["P0", "P3"]
ALLOC = [8, 8, 7, 7]


def subsample(manifest, seed):
    rows = list(csv.DictReader(open(manifest, newline="", encoding="utf-8")))
    rng = random.Random(seed)
    out = []
    for cwe in ("89", "79"):
        sub = sorted([r for r in rows if r["cwe"] == cwe], key=lambda r: int(r["file_id"]))
        q = st.quantiles([int(r["tok_max"]) for r in sub], n=4)
        quart = lambda t: 0 if t <= q[0] else 1 if t <= q[1] else 2 if t <= q[2] else 3
        for k, n in enumerate(ALLOC):
            pool = [r for r in sub if quart(int(r["tok_max"])) == k]
            for r in rng.sample(pool, n):
                out.append({**r, "q60": k, "q_cut": ";".join(str(int(v)) for v in q)})
    return out


def metrics(lbl):
    c = Counter(lbl)
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if tp + fp else None          # TP+FP = 0 -> indefinida (n/a)
    rec = tp / (tp + fn) if tp + fn else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else (0.0 if prec == 0 or rec == 0 else None)
    return {"n": n, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "acuracia": (tp + tn) / n if n else None, "precisao": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else None}


def mcnemar_exact(a_correct, b_correct):
    """a_correct, b_correct: listas booleanas pareadas. Retorna b (A certo, B errado),
    c (A errado, B certo) e o p-valor bilateral exato."""
    b = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
    c = sum(1 for x, y in zip(a_correct, b_correct) if y and not x)
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return b, c, min(1.0, p)


def holm(pvals):
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    adj, running = [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvals) - rank) * pvals[i]))
        adj[i] = running
    return adj


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(HERE, ".."))
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    R = a.root
    sample = subsample(os.path.join(R, "data/sample_manifest.csv"), a.seed)
    with open(os.path.join(R, "data/sample60_manifest.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(sample[0].keys()))
        w.writeheader(); w.writerows(sample)
    keep = {(r["cwe"], r["file_id"]) for r in sample}

    patches = {}
    for c in ("79", "89"):
        p = os.path.join(R, f"data/sovrano/1_all_files_analysis/cve_data/files_CWE-{c}.csv")
        for r in csv.DictReader(open(p, newline="", encoding="utf-8", errors="replace")):
            if (c, r["file_id"]) in keep:
                patches[(c, r["file_id"])] = r["patch"]

    first, dup, dup_same = {}, 0, 0
    for line in open(os.path.join(R, "logs/main.jsonl"), encoding="utf-8"):
        d = json.loads(line)
        k = (d["model_tag"], d["prompt_id"], d["cwe"].replace("CWE-", ""), str(d["file_id"]), d["type"])
        if k in first:
            dup += 1
            dup_same += first[k]["raw_response"] == d["raw_response"]
            continue
        first[k] = d

    res = {"seed": a.seed, "pairs": len(sample), "files": 2 * len(sample),
           "pairs_by_cwe": dict(Counter(r["cwe"] for r in sample)),
           "quartile_cuts": {c: next(r["q_cut"] for r in sample if r["cwe"] == c) for c in ("79", "89")},
           "duplicates_in_log": dup, "duplicates_identical": dup_same,
           "conditions": {}, "by_cwe": {}, "sovrano_P0": {}, "mcnemar": []}
    correct = {}
    unparsed = overflow = 0
    for mtag, mname in MODELS:
        for pid in PROMPTS:
            lab, lab_cwe, lab_sov, corr = [], defaultdict(list), [], []
            lat, tin, tout = [], [], []
            for r in sorted(sample, key=lambda r: (r["cwe"], int(r["file_id"]))):
                for ftype in ("buggy", "not_buggy"):
                    d = first[(mtag, pid, r["cwe"], r["file_id"], ftype)]
                    overflow += bool(d.get("context_overflow"))
                    v, _ = parse(d["raw_response"])
                    if v is None:
                        unparsed += 1
                    vuln = ftype == "buggy"
                    said = v == "vulnerable"            # sem veredito conta como "não detectou"
                    l = ("TP" if said else "FN") if vuln else ("FP" if said else "TN")
                    lab.append(l); lab_cwe[r["cwe"]].append(l); corr.append(l in ("TP", "TN"))
                    if pid == "P0":
                        lab_sov.append(classify_sovrano(ftype, patches[(r["cwe"], r["file_id"])], d["raw_response"]))
                    lat.append(d["latency_ms"]); tin.append(d["input_tokens"]); tout.append(d["output_tokens"])
            key = f"{mname}|{pid}"
            res["conditions"][key] = metrics(lab)
            res["conditions"][key]["latencia_mediana_s"] = st.median(lat) / 1000
            res["by_cwe"][key] = {f"CWE-{c}": metrics(v) for c, v in sorted(lab_cwe.items())}
            if pid == "P0":
                res["sovrano_P0"][mname] = metrics(lab_sov)
            correct[key] = corr
    res["unparsed"] = unparsed
    res["context_overflow"] = overflow

    comps = [("Gemma 7B|P0", "CodeGemma 7B|P0"), ("Gemma 7B|P3", "CodeGemma 7B|P3"),
             ("Gemma 7B|P0", "Gemma 7B|P3"), ("CodeGemma 7B|P0", "CodeGemma 7B|P3")]
    raw = [mcnemar_exact(correct[x], correct[y]) for x, y in comps]
    adj = holm([p for _, _, p in raw])
    for (x, y), (b, c, p), pa in zip(comps, raw, adj):
        res["mcnemar"].append({"A": x, "B": y, "A_certo_B_errado": b, "A_errado_B_certo": c,
                               "p": p, "p_holm": pa})

    out = os.path.join(R, "results/analysis60.json")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
