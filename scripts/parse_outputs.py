#!/usr/bin/env python3
"""
parse_outputs.py — extrai veredito e linha reportada das respostas BRUTAS.

Lê o JSONL de run_inference.py, NÃO altera raw_response, e escreve um JSONL novo
com parsed_verdict (vulnerable/safe/None) e reported_bug_line. Também reporta a
taxa de respostas não parseáveis (sem veredito extraível) — usada no piloto.

Regras de parsing (tolerantes, baseadas no formato SE/BL/BUG FOUND do P0):
- Veredito: procura "BUG FOUND: YES/NO" (ignora caixa/espacos). YES->vulnerable, NO->safe.
  Fallbacks: linhas "verdict: vulnerable|safe"; senão None (não parseável).
- Linha: "BL:" (regex do Sovrano) até antes de "BUG FOUND"; remove crases.
"""
import argparse, json, re, sys

RE_BUGFOUND = re.compile(r"BUG\s*FOUND\s*[:#]?\s*(YES|NO)", re.IGNORECASE)
RE_VERDICT = re.compile(r"verdict\s*[\"']?\s*[:=]\s*[\"']?\s*(vulnerable|safe)", re.IGNORECASE)
RE_BL = re.compile(r"(?:Bugged)?[ \-]*(?:Line|BL)\s*[:#]\s*(.*?)(?=BUG\s*FOUND:|$)",
                   re.IGNORECASE | re.DOTALL)


def clean_md(raw):
    """Remove ênfase markdown (**, __) que os modelos colocam nos rótulos SE/BL/BUG FOUND.
    Só para leitura: raw_response continua intacto no log."""
    return re.sub(r"\*\*|__", "", raw or "")


def parse(raw):
    verdict = None
    raw = clean_md(raw)
    m = RE_BUGFOUND.search(raw or "")
    if m:
        verdict = "vulnerable" if m.group(1).upper() == "YES" else "safe"
    else:
        m2 = RE_VERDICT.search(raw or "")
        if m2:
            verdict = m2.group(1).lower()
    bl = None
    mb = RE_BL.search(raw or "")
    if mb:
        lines = [l for l in mb.group(1).splitlines() if not l.strip().startswith("```")]
        lines = [l.strip().strip("`").strip() for l in lines if l.strip()]
        bl = lines[0] if lines else None
        if bl is not None and bl.lower().rstrip(".") in ("none", "null", ""):
            bl = None
    return verdict, bl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    n = unparsed = 0
    by_prompt = {}
    with open(args.inp, encoding="utf-8") as f, open(args.out, "w", encoding="utf-8") as g:
        for line in f:
            if not line.strip():
                continue
            d = json.loads(line)
            v, bl = parse(d.get("raw_response", ""))
            d["parsed_verdict"] = v
            d["reported_bug_line"] = bl
            g.write(json.dumps(d, ensure_ascii=False) + "\n")
            n += 1
            p = d.get("prompt_id", "?")
            by_prompt.setdefault(p, [0, 0])
            by_prompt[p][0] += 1
            if v is None:
                unparsed += 1
                by_prompt[p][1] += 1
    print(f"total={n} nao_parseaveis={unparsed} taxa={unparsed/max(1,n):.1%}")
    for p in sorted(by_prompt):
        tot, un = by_prompt[p]
        print(f"  {p}: {un}/{tot} nao parseavel ({un/max(1,tot):.1%})")


if __name__ == "__main__":
    main()
