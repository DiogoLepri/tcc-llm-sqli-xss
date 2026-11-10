#!/usr/bin/env python3
"""
metrics.py — métricas do TCC (Seção 3.7) e modo de compatibilidade com Sovrano et al. (2025).

Dois modos de classificação:
  sovrano : porta fiel de classify() do analyse_results.ipynb do artefato.
            TP = arquivo vulnerável + "BUG FOUND: YES" (ou sem NO) + linha BL contida no diff.
            Detectar sem localizar conta como FN. Usado só na reprodução (Tabela 2).
  tcc     : definição da Seção 3.7. TP/FN dependem só do veredito; a localização (LH)
            é medida à parte, nos arquivos vulneráveis.
Nada aqui altera respostas brutas.
"""
import argparse, csv, json, re, sys
from collections import defaultdict
csv.field_size_limit(10**9)

# ------------------------------------------------------------------ porta do notebook
bug_line_pattern = re.compile(r'(Bugged\s*)?[ -]*(Line|BL)\s*[:#]\s*(.*?)(?=BUG FOUND:)', re.IGNORECASE | re.DOTALL)
bug_line_pattern_simple = re.compile(r'(Bugged)?[ -]*(Line|BL) *[:#]', re.IGNORECASE)


def extract_code_or_return_original(text):
    matches = list(re.finditer(r"```([a-zA-Z]+)\n(.*?)```", text, re.DOTALL))
    if not matches:
        return text
    return "\n".join(m.group(2).strip() for m in matches)


def clean_whitespace(text):
    text = text.replace('\n', ' ')
    text = re.sub(r'\s+', ' ', text)
    return text.strip().strip('`.')


def remove_spaces(text):
    return text.replace(' ', '')


def extract_bug_line(model_output):
    if len(re.split(bug_line_pattern, model_output)) < 3:
        bug_line = re.split(bug_line_pattern_simple, model_output)[-1].strip()
    else:
        bug_line = re.split(bug_line_pattern, model_output)[-2].strip()
    bug_line = extract_code_or_return_original(bug_line).strip()
    m = re.search(r'`([^`]+)`', bug_line)
    if m:
        bug_line = m.group(0)
    return clean_whitespace(bug_line)


def has_bug_line(model_output):
    code = extract_code_or_return_original(model_output)
    _has = bool(bug_line_pattern.search(model_output))
    if not _has:
        return False
    bl = remove_spaces(clean_whitespace(extract_bug_line(model_output))).strip()
    if len(bl) == 0:
        return False
    if _has and ('BL: None'.lower() not in model_output.lower() or "BUG FOUND: NO".lower() not in model_output.lower()):
        return True
    if code and code != model_output:
        return True
    return None


def clean_patch(patch):
    return re.sub(r'^[+-]', '', patch, flags=re.MULTILINE)


def classify_sovrano(ftype, patch, out):
    yes = bool(re.search(r"bug\s*found\s*:\s*yes", out, re.IGNORECASE))
    no = bool(re.search(r"bug\s*found\s*:\s*no", out, re.IGNORECASE))
    if ftype == 'not_buggy':
        return 'FP' if yes else 'TN'
    if ftype == 'buggy' and no:
        return 'FN'
    if not has_bug_line(out):
        return 'FN'
    bl = remove_spaces(extract_bug_line(out))
    cp = remove_spaces(clean_whitespace(clean_patch(patch)))
    return 'TP' if (len(bl) > 0 and bl in cp) else 'FN'


# ------------------------------------------------------------------ métricas
def stats(labels):
    c = defaultdict(int)
    for l in labels:
        c[l] += 1
    tp, fp, tn, fn = c['TP'], c['FP'], c['TN'], c['FN']
    n = tp + fp + tn + fn
    div = lambda a, b: a / b if b else float('nan')
    p, r = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * p * r, p + r) if (p == p and r == r) else float('nan')
    return {"n": n, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "accuracy": div(tp + tn, n), "precision": p, "recall": r, "f1": f1,
            "fpr": div(fp, fp + tn), "specificity": div(tn, fp + tn)}


def load_files(path):
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        return {r['file_id']: r for r in csv.DictReader(f)}


def reproduce(args):
    """Fase 2: métricas no modo Sovrano sobre as respostas publicadas."""
    files = {"79": load_files(args.cwe79), "89": load_files(args.cwe89)}
    reported = {}
    with open(args.reported, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            reported[(r['model'], r['CWE'])] = r
    out_rows = []
    for (model, cwe), rep in sorted(reported.items()):
        c = cwe.split('-')[1]
        if c not in files:
            continue
        p = f"{args.outputs}/data_{cwe}_{model}.csv"
        with open(p, newline='', encoding='utf-8', errors='replace') as f:
            data = list(csv.DictReader(f))
        labels = []
        for d in data:
            fr = files[c].get(d['file_id'])
            labels.append(classify_sovrano(d['type'], fr['patch'] if fr else '', d['model_output'] or ''))
        s = stats(labels)
        for metric, key in (("F1", "f1"), ("Accuracy", "accuracy"), ("Precision", "precision"), ("Recall", "recall")):
            out_rows.append({"CWE": cwe, "model": model, "metric": metric,
                             "reported": float(rep[metric]), "reproduced": s[key],
                             "diff": s[key] - float(rep[metric]),
                             "n_reported": rep["Number of Samples"], "n_reproduced": s["n"],
                             "TP": s["TP"], "FP": s["FP"], "TN": s["TN"], "FN": s["FN"]})
    with open(args.out, "w", newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    worst = max(out_rows, key=lambda r: abs(r["diff"]))
    print(f"linhas: {len(out_rows)} | maior |diferença|: {abs(worst['diff']):.6f} "
          f"({worst['model']} {worst['CWE']} {worst['metric']})")
    for r in out_rows:
        if r["metric"] == "F1":
            print(f"  {r['CWE']} {r['model']:<22} F1 rep={r['reported']:.4f} repr={r['reproduced']:.4f} "
                  f"n={r['n_reported']}/{r['n_reproduced']}  TP={r['TP']} FP={r['FP']} TN={r['TN']} FN={r['FN']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reproduce")
    r.add_argument("--outputs", required=True)
    r.add_argument("--reported", required=True)
    r.add_argument("--cwe79", required=True)
    r.add_argument("--cwe89", required=True)
    r.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "reproduce":
        reproduce(a)
