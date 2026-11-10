#!/usr/bin/env python3
"""
build_prompts.py — gera prompts/prompt_config.json + prévias (reproduzível).

Spec = Apêndice A + Seção 3.5 do TCC, com as decisões aprovadas no checkpoint da Fase 1:
- P0: verbatim do Sovrano run_prompts.py (mensagem única, sem system, temperature 0).
- P1 (S1 task), P2 (S3 role), P3 (D2 definition): estrutura do Apêndice A.
  USER idêntico em P1–P3 (ordem do Apêndice A):
      <pergunta da tarefa>
      <bloco de saída SE/BL/BUG FOUND, idêntico ao P0>
      Code:
      {code}
  SYSTEM varia:
      P1 = ""                                    (task-oriented)
      P2 = "You are a code security expert."      (role-oriented)
      P3 = "You are a code security expert who analyzes the given code for
            {CWE_ID} ({CWE_NAME}). Definition: {CWE_DEFINITION}."  (definition-based)
- CWE referida como "CWE-79 (cross-site scripting)" / "CWE-89 (SQL injection)".
- OVERRIDE do rascunho: a instrução de saída JSON (verdict/bug_line/explanation) do
  Apêndice A/3.5 é substituída pelo bloco SE/BL/BUG FOUND do P0, idêntico nas 4 condições
  (decisão do orientador; 3.5 e Apêndice A serão atualizados no artigo).
- Sem chain-of-thought; justificativa curta.
"""
import json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "prompts")
os.makedirs(OUT, exist_ok=True)

CWE_NAME = {"79": "cross-site scripting", "89": "SQL injection"}   # nomes do SecLLMHolmes
CWE_REF = {c: f"CWE-{c} ({CWE_NAME[c]})" for c in CWE_NAME}        # {CWE_ID} ({CWE_NAME})
CWE_LABEL_SOVRANO = {
    "79": "Improper Neutralization of Input During Web Page Generation: Cross-site Scripting",
    "89": "Improper Neutralization of Special Elements used in an SQL Command: SQL Injection"}
CWE_DEF_MITRE = {
    "79": "Cross-Site Scripting: The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users. Cross-site scripting (XSS) vulnerabilities occur when:\n1. Untrusted data enters a web application, typically from a web request.\n2. The web application dynamically generates a web page that contains this untrusted data.\n3. During page generation, the application does not prevent the data from containing content that is executable by a web browser, such as JavaScript, HTML tags, HTML attributes, mouse events, Flash, ActiveX, etc.\n4. A victim visits the generated web page through a web browser, which contains malicious script that was injected using the untrusted data.\n5. Since the script comes from a web page that was sent by the web server, the victim's web browser executes the malicious script in the context of the web server's domain.\n6. This effectively violates the intention of the web browser's same-origin policy, which states that scripts in one domain should not be able to access resources or run code in a different domain.",
    "89": "SQL Injection: The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data. This can be used to alter query logic to bypass security checks, or to insert additional statements that modify the back-end database, possibly including execution of system commands."}

# --- Bloco de saída idêntico ao P0: extraído do próprio P0 verbatim ---
P0 = open(os.path.join(OUT, "P0_original.txt"), encoding="utf-8").read()
# fatia de "Your output must adhere" até imediatamente antes de "\n\nFile Content:"
m = re.search(r"(Your output must adhere.*?BUG FOUND: YES)\n\nFile Content:", P0, re.DOTALL)
OUTPUT_BLOCK = m.group(1)

def question(c):
    return f"Does this code contain instances of the security vulnerability known as {CWE_REF[c]}?"

def user_msg(c):
    return question(c) + "\n" + OUTPUT_BLOCK + "\nCode:\n{code}"

def build(c):
    u = user_msg(c)
    return {
        "P1_S1": {"system": "", "user": u},
        "P2_S3": {"system": "You are a code security expert.", "user": u},
        "P3_D2": {"system": f"You are a code security expert who analyzes the given code for {CWE_REF[c]}. Definition: {CWE_DEF_MITRE[c]}", "user": u},
    }

cfg = {
    "temperature": 0, "seed": 2026,
    "output_schema_native": "SE / BL / BUG FOUND (idêntico ao P0, nas 4 condições)",
    "parsed_mapping": {"BUG FOUND YES->verdict": "vulnerable", "BUG FOUND NO->verdict": "safe",
                       "BL->reported_bug_line": "linha ou null", "SE->explanation": "curta"},
    "cwe_ref_P0": CWE_LABEL_SOVRANO, "cwe_ref_P1P2P3": CWE_REF,
    "sources": {
        "P0": "Sovrano run_prompts.py (verbatim; single user msg; no system)",
        "P1": "Apêndice A.2 (S1, task-oriented; system vazio)",
        "P2": "Apêndice A.3 (S3, role-oriented)",
        "P3": "Apêndice A.4 (D2, definition-based; role+definição MITRE no system)"},
    "adaptation_notes": [
        "USER idêntico em P1/P2/P3 (ordem do Apêndice A: pergunta -> saída -> Code).",
        "Condições variam SOMENTE o system (none/role/role+definição).",
        "Instrução de saída JSON do rascunho substituída pelo bloco SE/BL/BUG FOUND do P0.",
        "Sem chain-of-thought."],
    "output_block": OUTPUT_BLOCK,
    "prompts": {c: build(c) for c in ["79", "89"]},
}
json.dump(cfg, open(os.path.join(OUT, "prompt_config.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)

PH = "<<FILE CONTENT HERE>>"
def render(spec):
    s = ""
    if spec["system"]:
        s += "[SYSTEM]\n" + spec["system"] + "\n\n"
    return s + "[USER]\n" + spec["user"].replace("{code}", PH)

for c in ["79", "89"]:
    for name, spec in cfg["prompts"][c].items():
        open(os.path.join(OUT, f"{name}_CWE-{c}.preview.txt"), "w", encoding="utf-8").write(render(spec))

print("OK. output_block idêntico ao P0:", OUTPUT_BLOCK is not None, "| len:", len(OUTPUT_BLOCK))
for c in ["89"]:
    for name in ["P1_S1", "P2_S3", "P3_D2"]:
        print(f"\n================ {name} — CWE-{c} ================\n")
        print(render(cfg["prompts"][c][name]))
