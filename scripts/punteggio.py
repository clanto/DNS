#!/usr/bin/env python3
"""Precisione delle fonti, persistenza, punteggio per voce e livello strict delle blocklist di sicurezza.

Richiamato da scripts/build_domains.py (configurazione: [punteggio] in domains/domains.toml).

1. Precisione per fonte, misurata a ogni build: quota di voci della fonte che colpiscono un segnale di falso
   positivo noto (esclusioni di cura, piattaforme della sezione privata PSL, servizi protetti o allowlist
   coperti dalla voce, domini propri). Peso = peso_max × (1 − penalita_fp × quota), almeno peso_min.
   Tranco non è usato: la lista combina Cloudflare Radar (CC BY-NC 4.0), non utilizzabile da un'azienda.
2. Persistenza: ora del primo avvistamento continuativo di ogni voce delle fonti esterne, in
   domains/cache/persistenza/<categoria>.txt (testo ordinato per ora, versionato con le cache).
3. Punteggio 0-100 = 100 × (1 − Π(1 − peso fonte) × (1 − peso_persistenza × persistenza)), con
   persistenza = min(1, ore di presenza continuativa / persistenza_ore): la persistenza conta come una prova in più,
   accanto alle fonti. Le voci manuali valgono sempre 100.
4. Livello strict: voci con punteggio ≥ soglia in dist/adguard/block-<cat>-strict.txt e dist/domains/;
   gli URL delle liste complete non cambiano (restano l'unione delle fonti).
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import perche
from build_ip import ROOT, warn

STATE_DIR = ROOT / "domains" / "cache" / "persistenza"
ADGUARD_DIR = ROOT / "dist" / "adguard"
PLAIN_DIR = ROOT / "dist" / "domains"
DEFAULTS = {"penalita_fp": 100.0, "peso_max": 0.8, "peso_min": 0.1, "persistenza_ore": 24, "peso_persistenza": 0.5,
            "max_calo_strict": 0.2, "min_voci_calo": 100, "bootstrap_commit": 30, "partizioni_indice": 256}


@dataclass
class Contesto:
    """Insiemi già calcolati dal build delle liste, usati per i segnali di falso positivo e i motivi."""
    curated: set[str]
    platforms: set[str]
    protected: set[str]
    allow_sets: dict[str, set[str]]  # categoria allow (non protect) → voci
    own: list[str]
    covers: Callable[[str, str], bool]
    drop_covered: Callable[[set[str]], list[str]]


@dataclass
class Risultato:
    adguard: dict[str, str] = field(default_factory=dict)
    plain: dict[str, str] = field(default_factory=dict)
    meta: dict[str, tuple[str, str, int]] = field(default_factory=dict)
    anomalie: list[str] = field(default_factory=list)
    errori: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    misure: dict[str, dict] = field(default_factory=dict)
    strict: dict[str, set[str]] = field(default_factory=dict)
    soglie: dict[str, int] = field(default_factory=dict)
    conf: dict = field(default_factory=dict)

    def readme(self, complete: dict[str, int]) -> list[str]:
        """Sezioni per dist/adguard/README.md; complete = voci AdGuard delle liste complete per categoria."""
        conf = self.conf
        righe = ["## Precisione delle fonti", "",
                 "Misurata a ogni build: quota di voci della fonte che colpiscono un falso positivo noto (esclusioni di "
                 "cura, piattaforme PSL, servizi protetti o allowlist coperti, domini propri). Il peso entra nel "
                 f"punteggio delle voci: peso = {conf['peso_max']} × (1 − {conf['penalita_fp']} × quota), "
                 f"minimo {conf['peso_min']}.", "",
                 "| Fonte | Lista | Voci | Falsi positivi | Precisione | Peso | Esempi |", "|---|---|---|---|---|---|---|"]
        for sid, m in sorted(self.misure.items(), key=lambda x: (x[1]["categoria"], x[0])):
            righe.append(f"| {sid} | block-{m['categoria']} | {m['voci']} | {m['falsi_positivi']} | "
                         f"{100 * m['precisione']:.3f}% | {m['peso']:.2f} | {', '.join(m['esempi'][:3])} |")
        righe += ["", "## Livello strict", "",
                  "Stesse liste con le sole voci a punteggio alto: meno voci, meno falsi positivi. Punteggio = "
                  f"100 × (1 − Π(1 − peso fonte) × (1 − {conf['peso_persistenza']} × persistenza)), persistenza piena "
                  f"dopo {conf['persistenza_ore']} ore di presenza continuativa; voci manuali sempre 100.", "",
                  "| Lista | Soglia | Voci complete | Voci strict | Quota |", "|---|---|---|---|---|"]
        for cat in self.strict:
            full, n = complete.get(cat, 0), self.meta[f"block-{cat}-strict.txt"][2]
            righe.append(f"| block-{cat} | {self.soglie[cat]} | {full} | {n} | {100 * n / full if full else 0:.1f}% |")
        return righe + [""]


def ora_attuale() -> int:
    return int(datetime.now(timezone.utc).timestamp()) // 3600


def ora_di(giorno: str) -> int:
    try:
        return int(datetime.combine(date.fromisoformat(giorno), datetime.min.time(), timezone.utc).timestamp()) // 3600
    except ValueError:
        return 0


def leggi_campi(path: Path, normalize: Callable[[str], str]) -> dict[str, tuple[str, str]]:
    """dominio → (data, motivo) da un file 'voce | data | motivo | ...' (la validazione la fa build_domains)."""
    out: dict[str, tuple[str, str]] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        campi = [c.strip() for c in raw.split("|")]
        if len(campi) >= 3:
            try:
                out[normalize(campi[0])] = (campi[1], campi[2])
            except UnicodeError:
                continue
    return out


def padri(nomi: set[str] | list[str]) -> set[str]:
    """Ogni nome e i suoi domini padre (almeno due etichette); per i pattern con '*' solo la parte fissa."""
    out: set[str] = set()
    for n in nomi:
        parti = n.split(".")
        if "*" in n:
            parti = parti[next(i for i, p in enumerate(parti) if "*" in p) + 1:]
        out.update(".".join(parti[i:]) for i in range(len(parti) - 1))
    return out


# ---------------------------------------------------------------------------------------------------------
# Precisione delle fonti
# ---------------------------------------------------------------------------------------------------------

def misura_fonti(per_source: dict[str, dict[str, set[str]]], ctx: Contesto, conf: dict) -> dict[str, dict]:
    segnali = {
        "cura": ctx.curated,
        "piattaforma": ctx.platforms,
        "protetto": padri(ctx.protected),
        "allowlist": padri(set().union(*ctx.allow_sets.values()) if ctx.allow_sets else set()),
        "proprio": padri(ctx.own),
    }
    misure: dict[str, dict] = {}
    for cat, sources in per_source.items():
        for sid, names in sources.items():
            colpite = {k: names & v for k, v in segnali.items()}
            colpite["proprio"] |= {n for n in names if any(n.endswith(f".{o}") for o in ctx.own)}
            errate = set().union(*colpite.values())
            quota = len(errate) / len(names) if names else 0.0
            peso = conf["peso_max"] * max(0.0, 1 - conf["penalita_fp"] * quota)
            peso = max(conf["peso_min"], round(peso * 20) / 20)  # passi di 0,05: pesi stabili tra un build e l'altro
            misure[sid] = {"categoria": cat, "voci": len(names), "falsi_positivi": len(errate),
                           "segnali": {k: len(v) for k, v in colpite.items() if v},
                           "esempi": sorted(errate)[:5], "precisione": round(1 - quota, 5), "peso": peso}
    return misure


# ---------------------------------------------------------------------------------------------------------
# Persistenza: primo avvistamento continuativo per voce
# ---------------------------------------------------------------------------------------------------------

def stato_path(cat: str) -> Path:
    return STATE_DIR / f"{cat}.txt"


def carica_stato(cat: str) -> dict[str, int] | None:
    path = stato_path(cat)
    if not path.exists():
        return None
    stato: dict[str, int] = {}
    ora = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("@"):
            ora = int(line[1:])
        elif line and not line.startswith("#"):
            stato[line] = ora
    return stato


def salva_stato(cat: str, stato: dict[str, int]) -> int:
    per_ora: dict[int, list[str]] = {}
    for nome, ora in stato.items():
        per_ora.setdefault(ora, []).append(nome)
    righe = [f"# Primo avvistamento continuativo delle voci delle fonti esterne di block-{cat}.",
             "# Generato da scripts/punteggio.py: non modificare a mano. '@N' = ora UTC N dall'epoca Unix (N × 3600 s);",
             "# seguono le voci comparse in quell'ora e presenti in ogni build successivo."]
    for ora in sorted(per_ora):
        righe.append(f"@{ora}")
        righe += sorted(per_ora[ora])
    testo = "\n".join(righe) + "\n"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    stato_path(cat).write_text(testo, encoding="utf-8", newline="\n")
    return len(testo)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")


def ricostruisci(sids: list[str], max_commit: int) -> dict[str, int]:
    """Stato iniziale dalla storia git delle cache delle fonti: per ogni voce, l'ora del commit più vecchio da cui
    è presente senza interruzioni (sulle versioni lette). Senza storia (checkout superficiale) resta vuoto."""
    primo: dict[str, int] = {}
    for sid in sids:
        rel = f"domains/cache/{sid}.txt"
        log = _git("log", f"-n{max_commit}", "--format=%H %ct", "--", rel)
        if log.returncode != 0:
            continue
        continua: set[str] | None = None
        visti: dict[str, int] = {}
        for riga in log.stdout.split("\n"):
            if not riga.strip():
                continue
            sha, ct = riga.split()
            testo = _git("show", f"{sha}:{rel}")
            if testo.returncode != 0:
                break
            nomi = {n for n in testo.stdout.split("\n") if n and not n.startswith("#")}
            continua = nomi if continua is None else continua & nomi
            if not continua:
                break
            ora = int(ct) // 3600
            for n in continua:
                visti[n] = ora
        for n, ora in visti.items():
            primo[n] = min(primo.get(n, ora), ora)
    return primo


def aggiorna_stato(precedente: dict[str, int], attuali: set[str], ora: int) -> dict[str, int]:
    """Le voci ancora presenti mantengono il primo avvistamento, le nuove prendono l'ora attuale, le sparite escono."""
    return {n: min(precedente.get(n, ora), ora) for n in attuali}


# ---------------------------------------------------------------------------------------------------------
# Punteggio e livello strict
# ---------------------------------------------------------------------------------------------------------

def punteggio(pesi: list[float], ore: int, manuale: bool, conf: dict) -> int:
    if manuale:
        return 100
    resto = 1.0
    for p in pesi:
        resto *= 1 - p
    persistenza = min(1.0, max(0, ore) / conf["persistenza_ore"]) if conf["persistenza_ore"] else 1.0
    resto *= 1 - conf["peso_persistenza"] * persistenza
    return round(100 * round(1 - resto, 6))


def controlla_calo(precedenti: dict[str, int], nuovi: dict[str, int], quota: float, minimo: int) -> list[str]:
    """Liste strict che perdono più della quota rispetto al build precedente (→ percorso di anomalia del build)."""
    return [f"`{nome}`: {prima} → {nuovi[nome]} voci (calo oltre {quota:.0%})"
            for nome, prima in precedenti.items()
            if nome in nuovi and prima >= minimo and nuovi[nome] < prima * (1 - quota)]


def conta(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()) if path.exists() else 0


def motivo_esclusione(nome: str, cat: str, opts: dict, raw: dict[str, set[str]], manual: set[str],
                      ctx: Contesto, motivi_cura: dict[str, tuple[str, str]]) -> str:
    """Perché una voce arrivata in block-<cat> non è pubblicata (stesso ordine dei filtri di build_domains)."""
    if opts.get("exclude_platforms") and nome in ctx.platforms and nome not in manual:
        return "piattaforma della Public Suffix List: si bloccano solo i sottodomini"
    if nome in ctx.curated and nome not in manual:
        return f"esclusione di cura (domains/escludi.txt): {motivi_cura.get(nome, ('', ''))[1]}"
    for other in opts.get("exclude", []):
        if nome in raw.get(other, set()):
            return f"già in block-{other}"
    if any(ctx.covers(o, nome) for o in ctx.own):
        return "dominio proprio (own_domains)"
    if nome in ctx.protected:
        return "servizio protetto (allow-protetti)"
    for acat, voci in ctx.allow_sets.items():
        for a in voci:
            if ctx.covers(a, nome):
                return f"in allow-{acat} ({a})"
    return "esclusa dal build"


def applica(cfg: dict, raw: dict[str, set[str]], final: dict[str, set[str]], per_source: dict[str, dict[str, set[str]]],
            manual: dict[str, set[str]], ctx: Contesto, normalize: Callable[[str], str], *, scrivi: bool,
            ora: int | None = None) -> Risultato:
    conf = {**DEFAULTS, **{k: v for k, v in cfg.get("punteggio", {}).items() if not isinstance(v, dict)}}
    soglie: dict[str, int] = cfg.get("punteggio", {}).get("strict", {})
    ora = ora_attuale() if ora is None else ora
    res = Risultato()
    blocks = cfg.get("block", {})
    for cat in soglie:
        if cat not in blocks:
            res.errori.append(f"domains.toml: [punteggio.strict] con categoria block inesistente '{cat}'")
    res.misure = misura_fonti(per_source, ctx, conf)

    # Persistenza (solo categorie con livello strict), punteggio e strict
    primi: dict[str, dict[str, int]] = {}
    punteggi: dict[str, dict[str, int]] = {}
    date_manuali: dict[str, dict[str, tuple[str, str]]] = {}
    for cat in soglie:
        if cat not in blocks:
            continue
        sources = per_source.get(cat, {})
        esterne = set().union(*sources.values()) if sources else set()
        stato = carica_stato(cat)
        if stato is None:
            stato = ricostruisci(list(sources), conf["bootstrap_commit"]) if scrivi else {}
            res.log.append(f"- persistenza block/{cat}: stato iniziale da git ({len(stato)} voci con storia)")
        stato = aggiorna_stato(stato, esterne, ora)
        primi[cat] = stato
        if scrivi:
            size = salva_stato(cat, stato)
            res.log.append(f"- persistenza block/{cat}: {len(stato)} voci, {size / 1e6:.1f} MB")
        date_manuali[cat] = leggi_campi(ROOT / "domains" / "blocklist" / f"{cat}.txt", normalize)
        fonti_di: dict[str, list[float]] = {}
        for sid, names in sources.items():
            peso = res.misure[sid]["peso"]
            for n in names:
                fonti_di.setdefault(n, []).append(peso)
        punteggi[cat] = {n: punteggio(fonti_di.get(n, []), ora - stato.get(n, ora), n in manual[cat], conf)
                         for n in final[cat]}
        res.strict[cat] = {n for n, p in punteggi[cat].items() if p >= soglie[cat]}

    # Uscite strict, confronto con il build precedente
    precedenti, nuovi = {}, {}
    for cat, nomi in res.strict.items():
        fname = f"block-{cat}-strict.txt"
        precedenti[fname] = conta(PLAIN_DIR / fname)
        voci = ctx.drop_covered(nomi)
        res.adguard[fname] = "".join(f"||{d}^\n" for d in voci)
        semplici = sorted(d for d in nomi if "*" not in d)
        res.plain[fname] = "".join(f"{d}\n" for d in semplici)
        nuovi[fname] = len(semplici)
        desc = (f"Livello strict di block-{cat}: solo voci con punteggio ≥ {soglie[cat]} "
                f"(fonti affidabili e persistenti, voci manuali), per aziende e scuole")
        res.meta[fname] = (desc, fname, len(voci))
        res.log.append(f"- strict block/{cat}: {len(voci)} voci AdGuard (soglia {soglie[cat]})")
    res.anomalie += controlla_calo({k: v for k, v in precedenti.items() if v}, nuovi, conf["max_calo_strict"],
                                   conf["min_voci_calo"])
    res.soglie, res.conf = soglie, conf
    if scrivi:
        indice(cfg, raw, final, per_source, manual, ctx, normalize, primi, punteggi, res, conf, soglie, date_manuali)
    return res


def indice(cfg, raw, final, per_source, manual, ctx, normalize, primi, punteggi, res, conf, soglie, date_manuali) -> None:
    """Indice «Perché è bloccato?»: per ogni dominio le liste che lo bloccano, quelle da cui è stato tolto e perché,
    le allowlist che lo sbloccano (vedi scripts/perche.py per il formato)."""
    blocks, allows = cfg.get("block", {}), cfg.get("allow", {})
    liste = [{"nome": f"block-{c}", "tipo": "block", "descrizione": o.get("description", ""),
              "punteggio": c in punteggi, "strict": f"block-{c}-strict" if c in res.strict else None}
             for c, o in blocks.items()]
    liste += [{"nome": f"allow-{c}", "tipo": "allow", "descrizione": o.get("description", "")} for c, o in allows.items()]
    pos = {item["nome"]: i for i, item in enumerate(liste)}
    sorgenti = [s for s in cfg.get("sources", []) if s.get("id") in res.misure]
    fonti = [s["id"] for s in sorgenti] + ["manuale"]
    fpos = {f: i for i, f in enumerate(fonti)}
    motivi_cura = leggi_campi(ROOT / "domains" / "escludi.txt", normalize)
    voci: dict[str, list] = {}
    tuple_fonti: dict[tuple, tuple] = {}  # tuple condivise: meno memoria con centinaia di migliaia di voci

    for cat, opts in blocks.items():
        li = pos[f"block-{cat}"]
        di: dict[str, list[int]] = {}
        for sid, names in per_source.get(cat, {}).items():
            for n in names:
                di.setdefault(n, []).append(fpos[sid])
        for n in manual[cat]:
            di.setdefault(n, []).append(fpos["manuale"])

        def fonti_di(n: str) -> tuple:
            t = tuple(di.get(n, ()))
            return tuple_fonti.setdefault(t, t)

        strict = res.strict.get(cat, set())
        for n in final[cat]:
            if "*" in n:
                continue
            if cat in punteggi:
                primo = primi[cat].get(n) or ora_di(date_manuali[cat].get(n, ("", ""))[0])
                rec = (li, fonti_di(n), primo, punteggi[cat][n], int(n in strict))
            else:
                rec = (li, fonti_di(n))
            voci.setdefault(n, []).append(rec)
        for n in raw[cat] - final[cat]:
            if "*" not in n:
                motivo = motivo_esclusione(n, cat, opts, raw, manual[cat], ctx, motivi_cura)
                voci.setdefault(n, []).append((li, fonti_di(n), motivo))
    for cat in allows:
        motivi = leggi_campi(ROOT / "domains" / "allowlist" / f"{cat}.txt", normalize)
        for n in ctx.allow_sets.get(cat, set()) | (ctx.protected if allows[cat].get("protect") else set()):
            if "*" not in n and n in motivi:
                voci.setdefault(n, []).append((pos[f"allow-{cat}"], motivi[n][1]))

    meta = {
        "versione": perche.VERSIONE,
        "generato": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "partizioni": conf["partizioni_indice"],
        "hash": "CRC-32 (IEEE) del dominio in ASCII/punycode, modulo partizioni, in esadecimale",
        "liste": liste,
        "fonti": fonti,
        "precisione": {sid: {k: m[k] for k in ("categoria", "voci", "falsi_positivi", "precisione", "peso")}
                       for sid, m in res.misure.items()},
        "soglie_strict": soglie,
        "punteggio": {k: conf[k] for k in ("penalita_fp", "peso_max", "peso_min", "persistenza_ore", "peso_persistenza")},
    }
    files, size = perche.scrivi_indice(meta, voci, conf["partizioni_indice"])
    res.log.append(f"- indice «Perché è bloccato?»: {len(voci)} domini, {files} file, {size / 1e6:.1f} MB")
    if not voci:
        warn("indice «Perché è bloccato?» vuoto")
