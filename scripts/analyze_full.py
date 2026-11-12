#!/usr/bin/env python3
"""
analyze_full.py — análise principal do artigo: 242 pares x 4 prompts x modelos.

Lê logs/main.jsonl (Gemma 7B e CodeGemma 7B) e, se existir, logs/new_models.jsonl (modelos
atuais). Usa a primeira ocorrência de cada inferência. Respostas sem veredito contam como
"não sinalizou". Saída: results/analysis_full.json
"""
import argparse, csv, json, os, sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from parse_outputs import parse                                   # noqa: E402
from analyze60 import metrics, mcnemar_exact, holm                # noqa: E402
csv.field_size_limit(10 ** 9)

NAMES = {"gemma:7b-instruct": "Gemma 7B", "codegemma:7b-instruct": "CodeGemma 7B",
         "gemma4:12b": "Gemma 4 12B", "devstral-small-2:24b": "Devstral Small 2 24B"}
PROMPTS = ["P0", "P1", "P2", "P3"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(HERE, ".."))
    R = ap.parse_args().root
    sample = sorted(csv.DictReader(open(os.path.join(R, "data/sample_manifest.csv"), newline="", encoding="utf-8")),
                    key=lambda r: (r["cwe"], int(r["file_id"])))
    first, order = {}, []
    for fn in ("logs/main.jsonl", "logs/new_models.jsonl"):
        p = os.path.join(R, fn)
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            d = json.loads(line)
            if d["model_tag"] not in order:
                order.append(d["model_tag"])
            k = (d["model_tag"], d["prompt_id"], d["cwe"].replace("CWE-", ""), str(d["file_id"]), d["type"])
            first.setdefault(k, d)

    res = {"pairs": len(sample), "pairs_by_cwe": dict(Counter(r["cwe"] for r in sample)), "models": [],
           "conditions": {}, "by_cwe": {}, "pairs_outcome": {}, "unparsed": {}, "explicit_no": {},
           "excl": {}, "missing": {}, "tokens": {}, "mcnemar": []}
    correct = {}
    for mtag in order:
        mname = NAMES.get(mtag, mtag); res["models"].append(mname)
        for pid in PROMPTS:
            lab, lab_cwe, lab_excl, corr, outcome = [], defaultdict(list), [], {}, Counter()
            un = miss = overflow = exno = 0; max_in = max_sum = 0
            for r in sample:
                said = {}
                for ftype in ("buggy", "not_buggy"):
                    d = first.get((mtag, pid, r["cwe"], r["file_id"], ftype))
                    if d is None:
                        miss += 1
                        continue
                    overflow += bool(d.get("context_overflow"))
                    max_in = max(max_in, d["input_tokens"] or 0)
                    max_sum = max(max_sum, (d["input_tokens"] or 0) + (d["output_tokens"] or 0))
                    v, _ = parse(d["raw_response"])
                    un += v is None
                    exno += (v == "safe")
                    s = v == "vulnerable"
                    said[ftype] = s
                    l = ("TP" if s else "FN") if ftype == "buggy" else ("FP" if s else "TN")
                    lab.append(l); lab_cwe[r["cwe"]].append(l)
                    if v is not None:
                        lab_excl.append(l)
                    corr[(r["cwe"], r["file_id"], ftype)] = l in ("TP", "TN")
                if len(said) == 2:
                    outcome[("Y" if said["buggy"] else "N") + ("Y" if said["not_buggy"] else "N")] += 1
            key = f"{mname}|{pid}"
            res["conditions"][key] = metrics(lab)
            res["by_cwe"][key] = {f"CWE-{c}": metrics(v) for c, v in sorted(lab_cwe.items())}
            res["pairs_outcome"][key] = {"separou": outcome["YN"], "duas_vulneraveis": outcome["YY"],
                                         "duas_seguras": outcome["NN"], "invertido": outcome["NY"],
                                         "pares": sum(outcome.values())}
            res["unparsed"][key] = un; res["explicit_no"][key] = exno
            res["excl"][key] = metrics(lab_excl)
            res["missing"][key] = miss
            res["tokens"][key] = {"max_input": max_in, "max_input_plus_output": max_sum, "context_overflow": overflow}
            correct[key] = corr

    comps = []
    names = res["models"]
    for i in range(len(names)):                      # modelos, dois a dois, em cada prompt
        for j in range(i + 1, len(names)):
            for pid in PROMPTS:
                comps.append(("modelo", f"{names[i]}|{pid}", f"{names[j]}|{pid}"))
    for n in names:                                  # cada prompt contra o original, em cada modelo
        for pid in PROMPTS[1:]:
            comps.append(("prompt", f"{n}|P0", f"{n}|{pid}"))
    raw = []
    for _, x, y in comps:
        keys = sorted(set(correct[x]) & set(correct[y]))
        raw.append(mcnemar_exact([correct[x][k] for k in keys], [correct[y][k] for k in keys]) + (len(keys),))
    adj = holm([p for _, _, p, _ in raw])
    for (kind, x, y), (b, c, p, n), pa in zip(comps, raw, adj):
        res["mcnemar"].append({"tipo": kind, "A": x, "B": y, "A_certo_B_errado": b, "A_errado_B_certo": c,
                               "p": p, "p_holm": pa, "arquivos": n})

    out = os.path.join(R, "results/analysis_full.json")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    for k, c in res["conditions"].items():
        o = res["pairs_outcome"][k]
        print(f"{k:22s} TP {c['TP']:3d} FN {c['FN']:3d} FP {c['FP']:3d} TN {c['TN']:3d} acc {c['acuracia']:.3f} f1 {c['f1']:.3f} "
              f"fpr {c['fpr']:.3f} sep {o['separou']} inv {o['invertido']} semver {res['unparsed'][k]} falt {res['missing'][k]}")
    for m in res["mcnemar"]:
        print(m["tipo"], m["A"], "x", m["B"], m["A_certo_B_errado"], m["A_errado_B_certo"], round(m["p"], 3), round(m["p_holm"], 3))


if __name__ == "__main__":
    main()
