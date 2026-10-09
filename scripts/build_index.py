#!/usr/bin/env python3
"""Genera il catalogo delle liste pubblicate e le attribuzioni delle fonti.

Output:
  dist/index.json       ogni feed/lista con URL, formato, voci, descrizione e fonti (per automazioni)
  dist/THIRD_PARTY.md   fonti di terze parti con licenza e link (attribuzioni richieste da CC BY, MIT, ecc.)

Va eseguito dopo i build. Uso: python scripts/build_index.py
"""
from __future__ import annotations

import json
import sys
import tomllib
from datetime import datetime, timezone

from build_ip import RAW_BASE, ROOT
from ct_phishing_it import promuovi

DIST = ROOT / "dist"
IP_CFG = tomllib.loads((ROOT / "ip/sources.toml").read_text(encoding="utf-8"))
DOM_CFG = tomllib.loads((ROOT / "domains/domains.toml").read_text(encoding="utf-8"))
promuovi(DOM_CFG)  # block-phishing-it a osservazione chiusa (domains/ct_marchi.toml)


def count(path) -> int | None:
    if not path.exists():
        return None
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))


def source_info(src: dict) -> dict:
    return {"id": src["id"], "licenza": src.get("license", ""), "homepage": src.get("homepage", src.get("url", ""))}


def ip_feeds() -> list[dict]:
    feeds = []
    sources = [s for s in IP_CFG.get("sources", []) if s.get("enabled", True)]
    groups = [(n, a.get("description", ""), a["categories"], "aggregato") for n, a in IP_CFG.get("aggregates", {}).items()]
    groups += [(c, m.get("description", ""), [c], "categoria") for c, m in IP_CFG["categories"].items()]
    for name, desc, cats, kind in groups:
        for v in (4, 6):
            rel = f"dist/ip/{name}-v{v}.txt"
            n = count(ROOT / rel)
            if n is None:
                continue
            feeds.append({
                "id": f"ip/{name}-v{v}", "tipo": "ip", "versione_ip": v, "aggregato": kind == "aggregato",
                "categorie": cats, "formato": "un IP o CIDR per riga", "url": f"{RAW_BASE}/{rel}", "voci": n,
                "descrizione": desc,
                "fonti": [source_info(s) for s in sources if s["category"] in cats]
                + ([{"id": "manuale", "licenza": "GPL-3.0 (Clanto)", "homepage": f"ip/custom/{c}.txt"}
                    for c in cats if (ROOT / f"ip/custom/{c}.txt").exists()]),
            })
    return feeds


def domain_feeds() -> list[dict]:
    feeds = []
    sources = DOM_CFG.get("sources", [])
    formats = [("adguard", "dist/adguard/{k}-{c}.txt", "regole AdGuard"),
               ("domini", "dist/domains/{k}-{c}.txt", "un dominio per riga"),
               ("unbound", "dist/unbound/{k}-{c}.conf", "local-zone Unbound"),
               ("opnsense", "dist/opnsense/{c}.txt", "FQDN per alias OPNsense URL Table (IPs)")]
    for kind in ("allow", "block"):
        for cat, opts in DOM_CFG.get(kind, {}).items():
            manual = (ROOT / f"domains/{'allowlist' if kind == 'allow' else 'blocklist'}/{cat}.txt").exists()
            fonti = [source_info(s) for s in sources if s.get("category") == cat]
            if manual:
                fonti.append({"id": "manuale", "licenza": "GPL-3.0 (Clanto)",
                              "homepage": f"domains/{'allowlist' if kind == 'allow' else 'blocklist'}/{cat}.txt"})
            for fmt, pattern, label in formats:
                if fmt == "opnsense" and (kind != "block" or not opts.get("opnsense")):
                    continue
                rel = pattern.format(k=kind, c=cat)
                n = count(ROOT / rel)
                if n is None:
                    continue
                feeds.append({"id": f"{fmt}/{kind}-{cat}", "tipo": "dominio", "azione": "sblocco" if kind == "allow" else "blocco",
                              "categoria": cat, "formato": label, "url": f"{RAW_BASE}/{rel}", "voci": n,
                              "descrizione": opts.get("description", ""), "fonti": fonti})
    extra = [("adguard/allow-base", "dist/adguard/allow-base.txt", "regole AdGuard", "sblocco",
              "Aggregato delle allowlist da applicare a tutti"),
             ("unbound/safesearch", "dist/unbound/safesearch.conf", "local-data Unbound", "safesearch",
              "SafeSearch forzato (Google, YouTube, Bing, DuckDuckGo, Yandex, Pixabay)")]
    for fid, rel, label, action, desc in extra:
        n = count(ROOT / rel)
        if n is not None:
            feeds.append({"id": fid, "tipo": "dominio", "azione": action, "formato": label,
                          "url": f"{RAW_BASE}/{rel}", "voci": n, "descrizione": desc, "fonti": []})
    return feeds


def third_party() -> str:
    lines = ["# Fonti di terze parti", "",
             "> Generato da `scripts/build_index.py`: **non modificare a mano**. Le liste pubblicate in `dist/` sono",
             "> distribuite sotto GPL-3.0 e derivano anche dalle fonti seguenti, ciascuna con la propria licenza.", "",
             "## Fonti ripubblicate nelle liste", "",
             "| Fonte | Usata in | Licenza | Sito |", "|---|---|---|---|"]
    rows = [(s["id"], f"feed IP `{s['category']}`", s.get("license", ""), s.get("homepage", ""))
            for s in IP_CFG.get("sources", []) if s.get("enabled", True)]
    rows += [(s["id"], f"lista domini `{s['category']}`", s.get("license", ""), s.get("homepage", s.get("url", "")))
             for s in DOM_CFG.get("sources", [])]
    for sid, used, lic, home in sorted(rows):
        lines.append(f"| {sid} | {used} | {lic} | {home} |")
    lines += ["", "## Dati usati solo per filtrare (non ripubblicati)", "",
              "| Fonte | Uso | Sito |", "|---|---|---|"]
    for s in IP_CFG.get("shared_sources", []):
        url = s.get("url", "https://iptoasn.com/ (licenza PDDL)")
        lines.append(f"| {s['id']} | esclusione di infrastrutture condivise dai feed | {url} |")
    if DOM_CFG.get("psl_url"):
        lines.append(f"| Public Suffix List (sezione privata) | domini di piattaforme mai bloccati per intero "
                     f"nelle liste di sicurezza | {DOM_CFG['psl_url']} (MPL-2.0) |")
    lines += ["| iptoasn.com | reti per AS (esclusioni, feed social, controlli) | https://iptoasn.com/ (PDDL 1.0) |",
              "", "## Liste upstream consigliate per AdGuard", "",
              "Non ripubblicate: AdGuard le scarica direttamente. Catalogo con licenze in "
              "[adguard/README.md](adguard/README.md#catalogo-liste-upstream-abbonamento-diretto-su-adguard).", ""]
    return "\n".join(lines)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    feeds = ip_feeds() + domain_feeds()
    index = {
        "repository": "https://github.com/clanto/DNS",
        "licenza": "GPL-3.0",
        "generato": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "attribuzioni": f"{RAW_BASE}/dist/THIRD_PARTY.md",
        "registro_variazioni": f"{RAW_BASE}/dist/CHANGELOG.md",
        "feed": feeds,
    }
    (DIST / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (DIST / "THIRD_PARTY.md").write_text(third_party(), encoding="utf-8", newline="\n")
    print(f"- index.json: {len(feeds)} feed; THIRD_PARTY.md aggiornato")
    return 0


if __name__ == "__main__":
    sys.exit(main())
