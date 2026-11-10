#!/usr/bin/env python3
"""
build_stability.py — sorteia a subamostra do estudo de estabilidade (Seção 3.6).

24 pares = 3 por quartil de tamanho em cada CWE (4 quartis x 2 CWEs x 3).
Os quartis são calculados DENTRO da amostra principal de cada CWE (tok_max),
e o sorteio usa seed 2026. Cada par roda 10 vezes no total por condição:
a execução 1 é a da bateria principal; este manifesto alimenta as execuções 2 a 10.
"""
import argparse, csv, random, statistics as st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-quartile", type=int, default=3)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.manifest, newline="", encoding="utf-8")))
    rng = random.Random(a.seed)
    chosen = []
    for cwe in ("89", "79"):
        sub = sorted([r for r in rows if r["cwe"] == cwe], key=lambda r: int(r["file_id"]))
        q = st.quantiles([int(r["tok_max"]) for r in sub], n=4)
        quart = lambda t: 0 if t <= q[0] else 1 if t <= q[1] else 2 if t <= q[2] else 3
        for k in range(4):
            pool = [r for r in sub if quart(int(r["tok_max"])) == k]
            pick = rng.sample(pool, a.per_quartile)
            for r in pick:
                chosen.append({**r, "stability_quartile": k})
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(chosen[0].keys()))
        w.writeheader()
        w.writerows(chosen)
    print(f"estabilidade: {len(chosen)} pares -> {a.out}")


if __name__ == "__main__":
    main()
