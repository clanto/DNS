#!/usr/bin/env python3
"""Precisione delle fonti, persistenza, errore stimato per voce e livello strict delle blocklist di sicurezza.

Richiamato da scripts/build_domains.py (configurazione: [punteggio] in domains/domains.toml).

1. Precisione per fonte, misurata a ogni build: quota di voci della fonte che colpiscono un segnale di falso
   positivo noto (esclusioni di cura, piattaforme della sezione privata PSL, servizi protetti o allowlist
   coperti dalla voce, domini propri). Errore stimato della fonte, smussato perché una fonte piccola non crolli
   per un solo falso positivo: q = (falsi positivi + prior_voci × prior_errore) / (voci + prior_voci).
   Tranco non è usato: la lista combina Cloudflare Radar (CC BY-NC 4.0), non utilizzabile da un'azienda.
   Popolarità: Chrome UX Report (CrUX, Google, CC BY 4.0) dalla top list mensile di zakird/crux-top-lists.
   Solo nelle categorie crux_categorie (phishing, redirect): una voce che copre un sito tra i più visitati
   (rank ≤ crux_rank_misura) conta come falso positivo nella misura e, se il sito ha rank ≤ crux_rank_strict, resta
   fuori dallo strict (la lista completa non cambia). Malware, pubblicità, spyware e policy no: lì un sito popolare è
   spesso il bersaglio (pubblicità malevola, PUP, app spia molto diffuse).
2. Persistenza: ora del primo avvistamento continuativo di ogni voce delle fonti esterne, in
   domains/cache/persistenza/<categoria>.txt (testo ordinato per ora, versionato con le cache).
3. Errore stimato per voce = Π q delle fonti che la contengono × (1 − peso_persistenza × persistenza), con
   persistenza = min(1, ore di presenza continuativa / persistenza_ore). Le voci manuali valgono 0.
4. Livello strict: voci con errore stimato ≤ soglia della lista, dove soglia = max(errore_max della categoria,
   errore di una voce della fonte migliore della lista a persistenza piena). Nelle liste con una sola fonte lo
   strict non può distinguere tra le voci e coincide con la lista completa (meno popolari e voci nuove); con più
   fonti esclude le voci che arrivano solo da fonti deboli. Una voce già nello strict esce solo oltre
   soglia × isteresi: nessuna oscillazione tra un build e l'altro. Valori continui, senza gradini.
   Gli URL delle liste complete non cambiano (restano l'unione delle fonti).
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
CRUX_CACHE = ROOT / "domains" / "cache" / "crux-top.txt"  # host popolari per rank (Chrome UX Report, CC BY 4.0)
ADGUARD_DIR = ROOT / "dist" / "adguard"
PLAIN_DIR = ROOT / "dist" / "domains"
DEFAULTS = {"prior_voci": 1000, "prior_errore": 0.0005, "isteresi": 1.5, "persistenza_ore": 24, "peso_persistenza": 0.5,
            "max_calo_strict": 0.2, "min_voci_calo": 100, "bootstrap_commit": 30, "partizioni_indice": 256,
            "crux_url": "", "crux_rank_misura": 1000, "crux_rank_strict": 10000, "crux_rank_cache": 100000,
            "crux_categorie": ["phishing", "redirect"]}


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
    popolari: dict[str, int] = field(default_factory=dict)  # host → rank CrUX (vuoto se non disponibile)


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
    soglie: dict[str, float] = field(default_factory=dict)  # soglia effettiva di errore stimato per categoria
    conf: dict = field(default_factory=dict)

    def readme(self, complete: dict[str, int]) -> list[str]:
        """Sezioni per dist/adguard/README.md; complete = voci AdGuard delle liste complete per categoria."""
        conf = self.conf
        righe = ["## Precisione delle fonti", "",
                 "Misurata a ogni build: quota di voci della fonte che colpiscono un falso positivo noto (esclusioni di "
                 "cura, piattaforme PSL, servizi protetti o allowlist coperti, domini propri; per phishing e redirect "
                 "anche siti molto visitati). Errore stimato smussato: (falsi positivi + "
                 f"{conf['prior_voci'] * conf['prior_errore']:g}) / (voci + {conf['prior_voci']}).", "",
                 "| Fonte | Lista | Voci | Falsi positivi | Precisione | Errore stimato | Esempi |",
                 "|---|---|---|---|---|---|---|"]
        for sid, m in sorted(self.misure.items(), key=lambda x: (x[1]["categoria"], x[0])):
            righe.append(f"| {sid} | block-{m['categoria']} | {m['voci']} | {m['falsi_positivi']} | "
                         f"{100 * m['precisione']:.3f}% | {100 * m['errore']:.4f}% | {', '.join(m['esempi'][:3])} |")
        righe += ["", "## Livello strict", "",
                  "Stesse liste con le sole voci a errore stimato basso. Errore di una voce = prodotto degli errori "
                  f"delle fonti che la contengono × (1 − {conf['peso_persistenza']} × persistenza), persistenza piena "
                  f"dopo {conf['persistenza_ore']} ore; voci manuali 0. Soglia = la maggiore tra errore massimo della "
                  "categoria ed errore della fonte migliore della lista (con una sola fonte lo strict coincide con la "
                  f"lista completa, meno siti popolari e voci nuove). Una voce già nello strict esce oltre "
                  f"{conf['isteresi']} × soglia.", "",
                  "| Lista | Soglia | Voci complete | Voci strict | Quota |", "|---|---|---|---|---|"]
        for cat in self.strict:
            full, n = complete.get(cat, 0), self.meta[f"block-{cat}-strict.txt"][2]
            righe.append(f"| block-{cat} | {100 * self.soglie[cat]:.4f}% | {full} | {n} | "
                         f"{100 * n / full if full else 0:.1f}% |")
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


def parse_crux(text: str, max_rank: int) -> dict[str, int]:
    """CSV 'origin,rank' di CrUX → host con rank ≤ max_rank (rank = fascia: 1000, 5000, 10000...)."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        origin, _, rank = line.rpartition(",")
        if not rank.isdigit() or int(rank) > max_rank:
            continue
        host = origin.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0].lower().rstrip(".")
        if host and "." in host:
            out[host] = min(int(rank), out.get(host, int(rank)))
    return out


def carica_popolari(cfg: dict, offline: bool, persist: bool, fetch: Callable[[str], bytes],
                    gunzip: Callable[[bytes], bytes]) -> tuple[dict[str, int], str]:
    """Top list CrUX con cache in domains/cache/crux-top.txt ('host,rank') e guardrail di calo come le fonti."""
    conf = {**DEFAULTS, **{k: v for k, v in cfg.get("punteggio", {}).items() if not isinstance(v, dict)}}
    cached = parse_crux(CRUX_CACHE.read_text(encoding="utf-8"), 10**9) if CRUX_CACHE.exists() else {}
    url = conf["crux_url"]
    if offline or not url:
        return cached, f"cache, {len(cached)} host"
    try:
        nuovi = parse_crux(gunzip(fetch(url)).decode("utf-8", "replace"), conf["crux_rank_cache"])
        if not nuovi or (cached and len(nuovi) < len(cached) * 0.5):
            raise ValueError(f"calo sospetto {len(cached)} → {len(nuovi)} host")
    except Exception as exc:  # errore di rete/parsing: si ripiega sulla cache
        warn(f"CrUX: {exc}; uso la cache ({len(cached)} host)")
        return cached, f"cache ({exc}), {len(cached)} host"
    if persist:
        CRUX_CACHE.parent.mkdir(parents=True, exist_ok=True)
        CRUX_CACHE.write_text(f"# Chrome UX Report top list (Google, CC BY 4.0) via {url}\n"
                              + "".join(f"{h},{r}\n" for h, r in sorted(nuovi.items(), key=lambda x: (x[1], x[0]))),
                              encoding="utf-8", newline="\n")
    return nuovi, f"ok, {len(nuovi)} host"


def popolari_fino(ctx: "Contesto", rank: int) -> set[str]:
    """Host popolari con rank ≤ rank e i loro domini padre: una voce in questo insieme blocca un sito popolare."""
    return padri({h for h, r in ctx.popolari.items() if r <= rank})


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
    popolari = popolari_fino(ctx, conf["crux_rank_misura"])
    misure: dict[str, dict] = {}
    for cat, sources in per_source.items():
        for sid, names in sources.items():
            colpite = {k: names & v for k, v in segnali.items()}
            # popolarità solo dove un sito molto visitato non è un bersaglio voluto (non pubblicità, spyware, policy)
            colpite["popolare"] = names & popolari if cat in conf["crux_categorie"] else set()
            colpite["proprio"] |= {n for n in names if any(n.endswith(f".{o}") for o in ctx.own)}
            errate = set().union(*colpite.values())
            quota = len(errate) / len(names) if names else 0.0
            errore = errore_fonte(len(errate), len(names), conf)
            misure[sid] = {"categoria": cat, "voci": len(names), "falsi_positivi": len(errate),
                           "segnali": {k: len(v) for k, v in colpite.items() if v},
                           "esempi": sorted(errate)[:5], "precisione": round(1 - quota, 5),
                           "errore": round(errore, 8)}
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

def errore_fonte(falsi: int, voci: int, conf: dict) -> float:
    """Errore stimato di una fonte, smussato verso prior_errore: pesa poco su fonti grandi, molto su quelle piccole."""
    return (falsi + conf["prior_voci"] * conf["prior_errore"]) / (voci + conf["prior_voci"])


def errore_voce(errori: list[float], ore: int, manuale: bool, conf: dict) -> float:
    """Errore stimato di una voce: prodotto degli errori delle fonti, ridotto dalla persistenza. Manuale = 0."""
    if manuale:
        return 0.0
    if not errori:
        return 1.0
    err = 1.0
    for e in errori:
        err *= e
    persistenza = min(1.0, max(0, ore) / conf["persistenza_ore"]) if conf["persistenza_ore"] else 1.0
    return err * (1 - conf["peso_persistenza"] * persistenza)


def soglia_lista(errore_max: float, errori_fonti: list[float], conf: dict) -> float:
    """Soglia di una lista: errore_max, o l'errore della fonte migliore a persistenza piena se è più alto
    (con una sola fonte lo strict coincide con la lista completa: non c'è consenso con cui distinguere le voci)."""
    migliore = min(errori_fonti) * (1 - conf["peso_persistenza"]) if errori_fonti else 0.0
    return max(errore_max, migliore)


def in_strict(err: float, soglia: float, era_dentro: bool, conf: dict) -> bool:
    return err <= soglia or (era_dentro and err <= soglia * conf["isteresi"])


def controlla_calo(precedenti: dict[str, int], nuovi: dict[str, int], quota: float, minimo: int) -> list[str]:
    """Liste strict che perdono più della quota rispetto al build precedente (→ percorso di anomalia del build)."""
    return [f"`{nome}`: {prima} → {nuovi[nome]} voci (calo oltre {quota:.0%})"
            for nome, prima in precedenti.items()
            if nome in nuovi and prima >= minimo and nuovi[nome] < prima * (1 - quota)]


def leggi_lista(path: Path) -> set[str]:
    return set(path.read_text(encoding="utf-8").split()) if path.exists() else set()


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
    errori_max: dict[str, float] = cfg.get("punteggio", {}).get("strict", {})
    soglie: dict[str, float] = {}
    ora = ora_attuale() if ora is None else ora
    res = Risultato()
    blocks = cfg.get("block", {})
    for cat in errori_max:
        if cat not in blocks:
            res.errori.append(f"domains.toml: [punteggio.strict] con categoria block inesistente '{cat}'")
        elif not 0 < float(errori_max[cat]) < 1:
            res.errori.append(f"domains.toml: [punteggio.strict] {cat}: errore massimo fuori da (0, 1)")
    res.misure = misura_fonti(per_source, ctx, conf)

    # Persistenza (solo categorie con livello strict), punteggio e strict
    primi: dict[str, dict[str, int]] = {}
    punteggi: dict[str, dict[str, float]] = {}  # categoria → voce → errore stimato
    popolari_strict = popolari_fino(ctx, conf["crux_rank_strict"])
    date_manuali: dict[str, dict[str, tuple[str, str]]] = {}
    for cat in errori_max:
        if cat not in blocks or not 0 < float(errori_max[cat]) < 1:
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
            err = res.misure[sid]["errore"]
            for n in names:
                fonti_di.setdefault(n, []).append(err)
        soglie[cat] = soglia_lista(float(errori_max[cat]), [res.misure[sid]["errore"] for sid in sources], conf)
        prima = leggi_lista(PLAIN_DIR / f"block-{cat}-strict.txt")
        punteggi[cat] = {n: errore_voce(fonti_di.get(n, []), ora - stato.get(n, ora), n in manual[cat], conf)
                         for n in final[cat]}
        res.strict[cat] = {n for n, e in punteggi[cat].items()
                           if in_strict(e, soglie[cat], n in prima, conf)
                           and (n in manual[cat] or cat not in conf["crux_categorie"] or n not in popolari_strict)}

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
        desc = (f"Livello strict di block-{cat}: solo voci con errore stimato ≤ {100 * soglie[cat]:.4f}% "
                f"(fonti affidabili e persistenti, voci manuali), per aziende e scuole")
        res.meta[fname] = (desc, fname, len(voci))
        res.log.append(f"- strict block/{cat}: {len(voci)} voci AdGuard (soglia {100 * soglie[cat]:.4f}%)")
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
                rec = (li, fonti_di(n), primo, round(punteggi[cat][n] * 1e6), int(n in strict))
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
        "precisione": {sid: {k: m[k] for k in ("categoria", "voci", "falsi_positivi", "precisione", "errore")}
                       for sid, m in res.misure.items()},
        "soglie_strict_ppm": {c: round(s * 1e6, 2) for c, s in soglie.items()},
        "punteggio": {k: conf[k] for k in ("prior_voci", "prior_errore", "isteresi", "persistenza_ore",
                                           "peso_persistenza")},
    }
    files, size = perche.scrivi_indice(meta, voci, conf["partizioni_indice"])
    res.log.append(f"- indice «Perché è bloccato?»: {len(voci)} domini, {files} file, {size / 1e6:.1f} MB")
    if not voci:
        warn("indice «Perché è bloccato?» vuoto")
