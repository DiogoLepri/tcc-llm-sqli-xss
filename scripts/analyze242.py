#!/usr/bin/env python3
"""
analyze242.py — confirmação com a amostra completa coletada (121 + 121 pares).

Mesma análise de analyze60.py (métricas, McNemar exato com Holm, resultado por par),
aplicada a todos os pares de data/sample_manifest.csv, sem sorteio. Serve para verificar
se a conclusão obtida com os 60 pares se mantém quando se usa toda a amostra coletada.

Saída: results/analysis242.json
"""
import argparse, csv, json, os, sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from parse_outputs import parse                       # noqa: E402
from analyze60 import metrics, mcnemar_exact, holm, MODELS, PROMPTS   # noqa: E402
csv.field_size_limit(10 ** 9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(HERE, ".."))
    R = ap.parse_args().root
    sample = list(csv.DictReader(open(os.path.join(R, "data/sample_manifest.csv"), newline="", encoding="utf-8")))

    first = {}
    for line in open(os.path.join(R, "logs/main.jsonl"), encoding="utf-8"):
        d = json.loads(line)
        k = (d["model_tag"], d["prompt_id"], d["cwe"].replace("CWE-", ""), str(d["file_id"]), d["type"])
        first.setdefault(k, d)          # primeira ocorrência (as repetições são idênticas)

    res = {"pairs": len(sample), "files": 2 * len(sample),
           "pairs_by_cwe": dict(Counter(r["cwe"] for r in sample)),
           "conditions": {}, "by_cwe": {}, "pairs_outcome": {}, "unparsed": {}, "mcnemar": []}
    correct, overflow, missing = {}, 0, 0
    for mtag, mname in MODELS:
        for pid in PROMPTS:
            lab, lab_cwe, corr, outcome, un = [], defaultdict(list), [], Counter(), 0
            for r in sorted(sample, key=lambda r: (r["cwe"], int(r["file_id"]))):
                said = {}
                for ftype in ("buggy", "not_buggy"):
                    d = first.get((mtag, pid, r["cwe"], r["file_id"], ftype))
                    if d is None:
                        missing += 1
                        continue
                    overflow += bool(d.get("context_overflow"))
                    v, _ = parse(d["raw_response"])
                    un += v is None
                    s = v == "vulnerable"            # sem veredito conta como "não sinalizou"
                    said[ftype] = s
                    l = ("TP" if s else "FN") if ftype == "buggy" else ("FP" if s else "TN")
                    lab.append(l); lab_cwe[r["cwe"]].append(l); corr.append(l in ("TP", "TN"))
                outcome[("Y" if said.get("buggy") else "N") + ("Y" if said.get("not_buggy") else "N")] += 1
            key = f"{mname}|{pid}"
            res["conditions"][key] = metrics(lab)
            res["by_cwe"][key] = {f"CWE-{c}": metrics(v) for c, v in sorted(lab_cwe.items())}
            res["pairs_outcome"][key] = {"separou": outcome["YN"], "duas_vulneraveis": outcome["YY"],
                                         "duas_seguras": outcome["NN"], "invertido": outcome["NY"]}
            res["unparsed"][key] = un
            correct[key] = corr
    res["context_overflow"] = overflow
    res["missing"] = missing

    comps = [("Gemma 7B|P0", "CodeGemma 7B|P0"), ("Gemma 7B|P3", "CodeGemma 7B|P3"),
             ("Gemma 7B|P0", "Gemma 7B|P3"), ("CodeGemma 7B|P0", "CodeGemma 7B|P3")]
    raw = [mcnemar_exact(correct[x], correct[y]) for x, y in comps]
    adj = holm([p for _, _, p in raw])
    for (x, y), (b, c, p), pa in zip(comps, raw, adj):
        res["mcnemar"].append({"A": x, "B": y, "A_certo_B_errado": b, "A_errado_B_certo": c, "p": p, "p_holm": pa})

    out = os.path.join(R, "results/analysis242.json")
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
