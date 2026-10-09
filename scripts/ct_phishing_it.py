#!/usr/bin/env python3
"""Candidati phishing che imitano marchi e servizi italiani, dai log di Certificate Transparency.

Interroga crt.sh per i certificati emessi di recente con nomi che iniziano con i prefissi dei marchi
(domains/ct_marchi.toml), riconosce marchio, typo e omoglifi, assegna un punteggio e scarta domini
ufficiali, voci già nelle nostre blocklist, piattaforme della PSL privata, servizi protetti, allowlist
ed esclusioni di cura. In CI verifica che i candidati risolvano; chi non risolve da scadenza_giorni esce.

Output (fase di osservazione, mai in una blocklist pubblicata finché osservazione = true):
  dist/osservazione/phishing-it-candidati.txt   candidati sopra soglia e vivi, un dominio per riga
  dist/osservazione/phishing-it-report.md       motivo e punteggio per candidato, statistiche del giro
  dist/osservazione/phishing-it-stato.json      stato con primo avvistamento e ultima risposta DNS

Uso: python scripts/ct_phishing_it.py [--senza-dns] [--dati FILE.json] [--oggi AAAA-MM-GG]
  --senza-dns  salta la verifica di vita (rete con DNS filtrato): nessuna voce scade, tutte valgono vive
  --dati       legge i certificati da un file JSON in formato crt.sh invece di interrogare crt.sh
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import http.client
import ipaddress
import json
import re
import socket
import sys
import time
import tomllib
import unicodedata
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

import asn
from build_domains import DOMAIN_RE
from build_ip import ROOT, md_cell, warn

CONFIG_PATH = ROOT / "domains" / "ct_marchi.toml"
OUT_DIR = ROOT / "dist" / "osservazione"
CANDIDATI_PATH = OUT_DIR / "phishing-it-candidati.txt"
REPORT_PATH = OUT_DIR / "phishing-it-report.md"
STATO_PATH = OUT_DIR / "phishing-it-stato.json"
MAX_RISPOSTA = 30 * 1024 * 1024
CATEGORIA = "phishing-it"
PREFISSO_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

# Caratteri simili alle lettere latine (Cirillico, Greco, varianti) → lettera latina
OMOGLIFI = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ρ": "p",
    "τ": "t", "κ": "k", "ι": "i", "ε": "e", "ӧ": "o", "ı": "i", "ℓ": "l", "ß": "ss",
})
CIFRE_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
CIFRE_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
DV_GRATUITI = ("let's encrypt", "zerossl", "google trust services", "cpanel", "buypass", "ssl.com rsa ssl subca")


# ---------------------------------------------------------------------------
# Configurazione e liste locali
# ---------------------------------------------------------------------------

def carica_config(path: Path = CONFIG_PATH) -> dict:
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    errori = []
    for m in cfg.get("marchi", []):
        if not m.get("nome") or not m.get("parole") or not m.get("ufficiali"):
            errori.append(f"marchio senza nome, parole o ufficiali: {m.get('nome', '?')}")
        for p in m.get("cerca", m.get("parole", [])):
            if not PREFISSO_RE.match(p):
                errori.append(f"{m.get('nome')}: prefisso non valido '{p}' (solo lettere, cifre e '-')")
    for p in cfg.get("fonte", {}).get("prefissi_esca", []):
        if not PREFISSO_RE.match(p):
            errori.append(f"prefisso_esca non valido '{p}'")
    if errori:
        raise ValueError("; ".join(errori))
    return cfg


def leggi_voci(path: Path) -> set[str]:
    """Primo campo delle righe non commentate (formato 'dominio | data | motivo...' o un dominio per riga)."""
    if not path.exists():
        return set()
    voci = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")):
            voci.add(line.split("|")[0].split()[0].strip().lower().removeprefix("*."))
    return voci


@dataclass
class Contesto:
    """Insiemi locali usati dai filtri (caricati dal repository, sostituibili nei test)."""
    piattaforme: set[str] = field(default_factory=set)   # sezione privata PSL
    bloccati: set[str] = field(default_factory=set)      # voci delle nostre blocklist pubblicate
    allow: set[str] = field(default_factory=set)         # allowlist (compresi i protetti)
    protetti: set[str] = field(default_factory=set)
    escludi: set[str] = field(default_factory=set)       # esclusioni di cura (nome esatto)
    propri: set[str] = field(default_factory=set)


def carica_contesto() -> Contesto:
    dom = ROOT / "domains"
    ctx = Contesto()
    ctx.piattaforme = leggi_voci(dom / "cache" / "psl-private.txt")
    for p in (ROOT / "dist" / "domains").glob("block-*.txt"):
        ctx.bloccati |= leggi_voci(p)
    for p in (dom / "blocklist").glob("*.txt"):
        ctx.bloccati |= leggi_voci(p)
    for p in (dom / "allowlist").glob("*.txt"):
        ctx.allow |= leggi_voci(p)
    ctx.protetti = leggi_voci(dom / "allowlist" / "protetti.txt")
    ctx.escludi = leggi_voci(dom / "escludi.txt")
    ctx.propri = set(tomllib.loads((dom / "domains.toml").read_text(encoding="utf-8")).get("own_domains", []))
    return ctx


# ---------------------------------------------------------------------------
# Analisi dei nomi
# ---------------------------------------------------------------------------

def suffissi(nome: str) -> list[str]:
    parti = nome.split(".")
    return [".".join(parti[i:]) for i in range(len(parti))]


def coperto(nome: str, insieme: set[str]) -> bool:
    """True se nome o un suo dominio padre è nell'insieme."""
    return any(s in insieme for s in suffissi(nome))


def registrabile(nome: str, piattaforme: set[str], icann: set[str]) -> str:
    """Dominio registrabile: un'etichetta sotto la piattaforma PSL più lunga, o sotto il suffisso pubblico."""
    parti = nome.split(".")
    for i in range(1, len(parti)):
        if ".".join(parti[i:]) in piattaforme:
            return ".".join(parti[i - 1:])
    if len(parti) >= 3 and ".".join(parti[-2:]) in icann:
        return ".".join(parti[-3:])
    return ".".join(parti[-2:])


def unicode_etichetta(etichetta: str) -> str:
    if etichetta.startswith("xn--"):
        try:
            return etichetta.encode("ascii").decode("idna")
        except UnicodeError:
            return etichetta
    return etichetta


def scheletri(testo: str) -> set[str]:
    """Forme normalizzate: omoglifi Unicode → latino, accenti tolti, cifre → lettere, rn → m, vv → w."""
    base = unicodedata.normalize("NFKD", testo.lower().translate(OMOGLIFI))
    base = "".join(c for c in base if not unicodedata.combining(c)).translate(OMOGLIFI)
    forme = {base.translate(CIFRE_I), base.translate(CIFRE_L)}
    return forme | {f.replace("rn", "m").replace("vv", "w") for f in forme}


def entro_uno(a: str, b: str) -> bool:
    """Distanza di Damerau-Levenshtein al massimo 1 (sostituzione, inserimento, cancellazione, scambio)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def typo_in(token: str, parola: str) -> bool:
    """Typo del marchio all'inizio del token (unicredltt-login, finecobahk): le finestre in mezzo a parole
    lunghe producono solo coincidenze (axisbank ~ isybank)."""
    n = len(parola)
    return any(token[:lung] != parola and len(token) >= lung and entro_uno(token[:lung], parola)
               for lung in (n - 1, n, n + 1))


def unito_a_esca(parola: str, compatto: str, esca: set[str], segnali: set[str]) -> bool:
    """Parola del marchio unita a una parola esca o a 'it'/'italia': inpsrimborso, rimborsoinps."""
    for resto in (compatto[len(parola):] if compatto.startswith(parola) else "",
                  compatto[:-len(parola)] if compatto.endswith(parola) else ""):
        if resto and (resto in esca | segnali or any(e in resto for e in esca if len(e) >= 5)):
            return True
    return False


def corrispondenza(etichetta: str, marchio: dict, esca: set[str], segnali: set[str]) -> str | None:
    """Tipo di corrispondenza del marchio in un'etichetta: 'marchio', 'variante' o None.

    Le parole da 5 caratteri si cercano dentro l'etichetta; quelle più corte e quelle in 'token' (parole
    comuni come poste, fineco, aruba) solo come token separato da '-' o unite a una parola esca."""
    testo = unicode_etichetta(etichetta).lower()
    token = [t for t in testo.split("-") if t]
    compatto = "".join(token)
    for parola in marchio.get("non_marchio", []):
        compatto = compatto.replace(parola, "")
    solo_token = {p for p in marchio["parole"] if len(p) < 5 or p in marchio.get("token", [])}
    esatte = []
    if testo.isascii():
        for parola in marchio["parole"]:
            if parola in solo_token:
                if parola in token or unito_a_esca(parola, compatto, esca, segnali):
                    esatte.append(parola)
            elif parola in compatto:
                esatte.append(parola)
    # una variante di una parola più lunga di quelle trovate esatte vince (intesasanpoalo contiene intesa)
    lungo = max((len(p) for p in esatte), default=0)
    lunghe = [p for p in marchio["parole"] if p not in solo_token and len(p) > lungo]
    corte = [p for p in solo_token if len(p) >= 4 and len(p) > lungo]
    forme = scheletri(compatto)
    if any(p in f for f in forme for p in lunghe):
        return "variante"  # cifre, Unicode o rn→m al posto delle lettere del marchio
    if any(p in scheletri(t) and p != t for t in token for p in corte):
        return "variante"
    if any(v in compatto for v in marchio.get("varianti", []) if len(v) > lungo):
        return "variante"
    if compatto.isascii() and any(typo_in(t, p) for t in token for p in lunghe if len(p) >= 7):
        return "variante"
    return "marchio" if esatte else None


@dataclass
class Valutazione:
    dominio: str          # voce da pubblicare: dominio registrabile o nome esatto
    nome: str             # nome del certificato
    marchio: str
    punteggio: int
    motivi: list[str]


def valuta(nome: str, cert: dict, cfg: dict, ctx: Contesto, oggi: date) -> tuple[Valutazione | None, str]:
    """Valuta un nome di certificato. Restituisce (valutazione, esito); esito spiega uno scarto."""
    nome = nome.strip().lower().rstrip(".")
    wildcard = nome.startswith("*.")
    nome = nome.removeprefix("*.")
    if not DOMAIN_RE.match(nome):
        return None, "non è un nome a dominio"
    icann = set(cfg.get("suffissi_icann", []))
    reg = registrabile(nome, ctx.piattaforme, icann)
    etichette = nome.split(".")
    n_reg = len(reg.split("."))
    tld = etichette[-1]
    # etichette del dominio registrabile senza suffisso (per una piattaforma: l'etichetta del cliente)
    reg_label = reg.split(".")[0]
    sotto = etichette[:len(etichette) - n_reg]
    esca_cfg = set(cfg.get("esca", []))
    segnali = set(cfg.get("segnali_it", []))
    w = cfg.get("punteggio", {})

    trovato = None
    for marchio in cfg.get("marchi", []):
        tipo = corrispondenza(reg_label, marchio, esca_cfg, segnali)
        dove = "dominio"
        if tipo is None:
            for lab in sotto:
                tipo = corrispondenza(lab, marchio, esca_cfg, segnali)
                if tipo:
                    dove = "sottodominio"
                    break
        if tipo:
            trovato = (marchio, tipo, dove)
            break
    if trovato is None:
        return None, "nessun marchio"
    marchio, tipo, dove = trovato

    ufficiali = {u for m in cfg.get("marchi", []) for u in m.get("ufficiali", [])}
    if coperto(nome, ufficiali) or coperto(nome, ctx.propri):
        return None, "dominio ufficiale"
    voce = reg if dove == "dominio" else nome
    if voce in ctx.piattaforme or nome in ctx.piattaforme:
        return None, "piattaforma PSL"
    if voce in ctx.escludi or nome in ctx.escludi:
        return None, "esclusione di cura"
    if any(coperto(voce, {a}) or coperto(a, {voce}) for a in ctx.allow | ctx.protetti if a):
        return None, "allowlist o servizio protetto"
    if coperto(voce, ctx.bloccati):
        return None, "già nelle nostre liste"

    token = set()
    for lab in etichette[:-1]:
        token |= {t for t in unicode_etichetta(lab).split("-") if t}
    compatto = "".join(etichette[:-1]).replace("-", "")
    esche = sorted({e for e in esca_cfg if e in token or (len(e) >= 6 and e in compatto)}
                   - set(marchio["parole"]))
    if marchio.get("richiede_segnale_it") and not (token & segnali or tld == "it"
                                                   or any(s in compatto for s in segnali if len(s) >= 6)):
        return None, "marchio globale senza segnale italiano"

    punti = 0
    motivi = []
    if tipo == "variante":
        punti += w.get("variante", 50)
        motivi.append(f"variante di {marchio['nome']}")
    elif dove == "dominio":
        punti += w.get("marchio_dominio", 45)
        motivi.append(f"marchio {marchio['nome']} nel dominio")
    else:
        punti += w.get("marchio_sottodominio", 20)
        motivi.append(f"marchio {marchio['nome']} nel sottodominio")
    if esche:
        n = min(len(esche), w.get("esca_max", 2))
        punti += n * w.get("esca", 15)
        motivi.append("esca: " + ", ".join(esche[:4]))
    italia = sorted(i for i in cfg.get("italia", []) if i in token or (len(i) >= 6 and i in compatto))
    if italia and tld != "it":
        punti += w.get("italia", 10)
        motivi.append("richiamo all'Italia: " + ", ".join(italia[:2]))
    if tld in set(cfg.get("tld_rischio", [])):
        punti += w.get("tld_rischio", 15)
        motivi.append(f"TLD .{tld}")
    try:
        emesso = datetime.fromisoformat(cert.get("not_before", "")).date()
    except ValueError:
        emesso = None
    if emesso and (oggi - emesso).days <= 2:
        punti += w.get("cert_recente", 5)
        motivi.append("certificato recente")
    if wildcard:
        punti += w.get("wildcard", 5)
        motivi.append("wildcard")
    legittimo = sorted(c for c in cfg.get("contesto_legittimo", []) if c in token or (len(c) >= 5 and c in compatto))
    if legittimo:
        punti += w.get("contesto_legittimo", -20)
        motivi.append("contesto non da phishing: " + ", ".join(legittimo[:3]))
    emittente = cert.get("issuer_name", "").lower()
    righe = [r.strip() for r in cert.get("name_value", "").split("\n") if r.strip()]
    if any("." not in r or " " in r for r in righe):
        punti += w.get("organizzazione", -40)
        motivi.append("certificato con organizzazione (OV/EV)")
    elif any(d in emittente for d in DV_GRATUITI):
        punti += w.get("dv_gratuito", 5)
        motivi.append("certificato DV gratuito")
    return Valutazione(voce, nome, marchio["nome"], punti, motivi), "valutato"


# ---------------------------------------------------------------------------
# Fonte CT (crt.sh) e verifica di vita
# ---------------------------------------------------------------------------

def scarica(url: str, timeout: int) -> bytes:
    """Solo HTTPS (anche nei redirect), con limite di dimensione."""
    return asn.read_https(url, timeout=timeout, limit=MAX_RISPOSTA)


def prefissi_del_giro(tutti: list[str], per_giro: int, oggi: date) -> list[str]:
    """Rotazione giornaliera: per_giro prefissi a partire da un indice che avanza ogni giorno, così tutti
    vengono interrogati ogni len(tutti)/per_giro giorni restando nel limite di frequenza di crt.sh."""
    if per_giro >= len(tutti):
        return list(tutti)
    inizio = (oggi.toordinal() * per_giro) % len(tutti)
    return [tutti[(inizio + i) % len(tutti)] for i in range(per_giro)]


def interroga_crtsh(prefissi: list[str], fonte: dict, scarica_fn=scarica, attendi=time.sleep) -> tuple[list[dict], list[str]]:
    """Una richiesta per prefisso, in serie, con pausa e backoff. Restituisce (certificati, errori)."""
    certificati: dict[int, dict] = {}
    errori: list[str] = []
    pausa = fonte.get("pausa_secondi", 15)
    tentativi = fonte.get("tentativi", 4)
    limite = time.monotonic() + fonte.get("budget_minuti", 45) * 60
    for n, prefisso in enumerate(prefissi):
        if time.monotonic() > limite:
            errori.append(f"budget di tempo esaurito: saltati {len(prefissi) - n} prefissi")
            break
        url = fonte["url"].format(q=urllib.parse.quote(f"{prefisso}%"))
        for tentativo in range(tentativi):
            if n or tentativo:
                attendi(pausa if tentativo == 0 else 30 * 2 ** (tentativo - 1))
            try:
                dati = json.loads(scarica_fn(url, fonte.get("timeout_secondi", 120)) or b"[]")
                if not isinstance(dati, list):
                    raise ValueError("risposta non è una lista JSON")
                for c in dati:
                    if isinstance(c, dict) and "id" in c:
                        certificati.setdefault(c["id"], c)
                break
            except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ValueError, OSError) as exc:
                if tentativo == tentativi - 1:
                    errori.append(f"{prefisso}%: {exc}")
    return list(certificati.values()), errori


def risolve(nome: str) -> bool:
    """True se il nome risolve ad almeno un indirizzo pubblico (sinkhole 0.0.0.0 e reti private = non vivo)."""
    try:
        infos = socket.getaddrinfo(nome, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
                return True
        except ValueError:
            continue
    return False


def verifica_vita(nomi: list[str], risolvi=risolve, timeout: float = 10) -> dict[str, bool]:
    vivi: dict[str, bool] = {}
    with cf.ThreadPoolExecutor(32) as ex:
        futuri = {ex.submit(risolvi, n): n for n in nomi}
        for fut, n in futuri.items():
            try:
                vivi[n] = bool(fut.result(timeout=timeout))
            except (cf.TimeoutError, OSError):
                vivi[n] = False
    return vivi


# ---------------------------------------------------------------------------
# Stato, scadenza, output
# ---------------------------------------------------------------------------

def aggiorna_stato(stato: dict, valutazioni: list[Valutazione], vivi: dict[str, bool] | None, oggi: date,
                   scadenza: int) -> tuple[dict, list[str]]:
    """Aggiunge i nuovi avvistamenti, registra l'ultima risposta DNS e toglie le voci morte da più di
    scadenza giorni. vivi None = verifica di vita non eseguita (nessuna scadenza)."""
    iso = oggi.isoformat()
    for v in valutazioni:
        voce = stato.setdefault(v.dominio, {"primo": iso, "ultimo_vivo": None})
        if v.punteggio >= voce.get("punteggio", -999):
            voce.update(marchio=v.marchio, punteggio=v.punteggio, motivi=v.motivi, nome=v.nome)
        voce["ultimo_cert"] = iso
    usciti = []
    for dominio in sorted(stato):
        voce = stato[dominio]
        if vivi is None:
            continue
        if vivi.get(dominio):
            voce["ultimo_vivo"] = iso
        rif = date.fromisoformat(voce["ultimo_vivo"] or voce["primo"])
        if (oggi - rif).days >= scadenza:
            usciti.append(dominio)
            del stato[dominio]
    return stato, usciti


def candidati(stato: dict, soglia: int, senza_dns: bool) -> list[str]:
    return sorted((d for d, v in stato.items() if v["punteggio"] >= soglia and (senza_dns or v["ultimo_vivo"])),
                  key=lambda d: d.split(".")[::-1])


def scrivi_report(stato: dict, cfg: dict, stat: dict, lista: list[str], usciti: list[str], oggi: date,
                  senza_dns: bool, errori: list[str] | None = None) -> str:
    soglia = cfg.get("soglia", 60)
    oss = cfg.get("osservazione", True)
    righe = [
        "# Phishing di marchi italiani da Certificate Transparency",
        "",
        "> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.",
        "",
        ("**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare "
         "i falsi positivi prima di promuovere la lista a `block-phishing-it`." if oss else
         "**Lista pubblicata** come `block-phishing-it` (osservazione = false)."),
        "",
        f"Giro del {oggi.isoformat()}: fonte {cfg.get('fonte', {}).get('nome', 'crt.sh')}, "
        f"soglia {soglia}, finestra {cfg.get('finestra_giorni', 3)} giorni, scadenza {cfg.get('scadenza_giorni', 7)} giorni"
        + (", **verifica di vita disattivata**" if senza_dns else "") + ".",
        "",
        "## Statistiche del giro",
        "",
        "| Voce | Valore |",
        "|---|---|",
    ]
    righe += [f"| {k} | {v} |" for k, v in stat.items()]
    righe += [f"| candidati pubblicabili (sopra soglia e vivi) | {len(lista)} |",
              f"| voci nello stato | {len(stato)} |", f"| uscite per scadenza | {len(usciti)} |", ""]
    righe += ["## Candidati sopra soglia", "",
              "| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |",
              "|---|---|---|---|---|---|"]
    for d in sorted(lista, key=lambda d: (-stato[d]["punteggio"], d)):
        v = stato[d]
        righe.append(f"| {md_cell(d)} | {md_cell(v['marchio'])} | {v['punteggio']} | {md_cell('; '.join(v['motivi']))} "
                     f"| {v['primo']} | {v['ultimo_vivo'] or '—'} |")
    if not lista:
        righe.append("| — | | | | | |")
    sotto = sum(1 for v in stato.values() if v["punteggio"] < soglia)
    righe += ["", f"Voci sotto soglia nello stato: {sotto} (non elencate: servono solo a misurare la soglia).", ""]
    if errori:
        righe += ["## Errori della fonte", ""] + [f"- {md_cell(e)}" for e in errori[:30]] + [""]
    return "\n".join(righe)


def promuovi(cfg: dict) -> None:
    """Con osservazione = false aggiunge a una config di build_domains la categoria block.phishing-it,
    alimentata dai candidati sopra soglia. In osservazione non fa nulla."""
    if not CONFIG_PATH.exists():
        return
    ct = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if ct.get("osservazione", True):
        return
    if not CANDIDATI_PATH.exists():
        warn(f"osservazione = false ma {CANDIDATI_PATH.relative_to(ROOT).as_posix()} manca: block-{CATEGORIA} non generata")
        return
    cfg.setdefault("block", {}).setdefault(CATEGORIA, {
        "description": "Phishing che imita marchi e servizi italiani (Certificate Transparency, punteggio sopra soglia)",
        "exclude_platforms": True,
    })
    if not any(s.get("id") == "ct-phishing-it" for s in cfg.setdefault("sources", [])):
        cfg["sources"].append({
            "id": "ct-phishing-it", "category": CATEGORIA, "path": CANDIDATI_PATH.relative_to(ROOT).as_posix(),
            "format": "domains", "license": "GPL-3.0 (Clanto)", "homepage": "https://crt.sh/",
            "note": "Nomi da Certificate Transparency (crt.sh) filtrati e verificati da scripts/ct_phishing_it.py",
        })


def esegui(cfg: dict, ctx: Contesto, certificati: list[dict], stato: dict, oggi: date, vivi_fn,
           errori: list[str], prefissi: int | str) -> tuple[dict, list[str], list[str], dict]:
    """Analizza i certificati e aggiorna lo stato. vivi_fn None = senza verifica di vita."""
    finestra = oggi - timedelta(days=cfg.get("finestra_giorni", 3))
    soglia = cfg.get("soglia", 60)
    esiti: dict[str, int] = {}
    migliori: dict[str, Valutazione] = {}
    recenti = 0
    visti: set[str] = set()
    for cert in certificati:
        try:
            emesso = datetime.fromisoformat(cert.get("not_before", "")).date()
        except ValueError:
            continue
        if emesso < finestra:
            continue
        recenti += 1
        for nome in cert.get("name_value", "").split("\n"):
            chiave = nome.strip().lower()
            if not chiave or chiave in visti:
                continue
            visti.add(chiave)
            v, esito = valuta(chiave, cert, cfg, ctx, oggi)
            if v is None:
                esiti[esito] = esiti.get(esito, 0) + 1
                continue
            if v.punteggio < soglia:
                esiti["sotto soglia"] = esiti.get("sotto soglia", 0) + 1
            if v.dominio not in migliori or v.punteggio > migliori[v.dominio].punteggio:
                migliori[v.dominio] = v
    valutazioni = list(migliori.values())
    # nello stato entrano i candidati sopra soglia e i quasi-candidati (per misurare la soglia)
    tracciati = [v for v in valutazioni if v.punteggio >= soglia - 15]
    nomi = sorted({v.dominio for v in tracciati} | set(stato))
    vivi = vivi_fn(nomi) if vivi_fn else None
    stato, usciti = aggiorna_stato(stato, tracciati, vivi, oggi, cfg.get("scadenza_giorni", 7))
    lista = candidati(stato, soglia, vivi_fn is None)
    stat = {"prefissi interrogati": prefissi, "errori della fonte": len(errori),
            "certificati letti": len(certificati), "certificati nella finestra": recenti,
            "nomi distinti analizzati": len(visti)}
    for k in ("nessun marchio", "dominio ufficiale", "già nelle nostre liste", "piattaforma PSL",
              "allowlist o servizio protetto", "esclusione di cura", "marchio globale senza segnale italiano",
              "sotto soglia", "non è un nome a dominio"):
        stat[f"scartati: {k}"] = esiti.get(k, 0)
    if vivi is not None:
        stat["non risolvono (in questo giro)"] = sum(1 for n in nomi if not vivi.get(n))
    return stato, lista, usciti, stat


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--senza-dns", action="store_true", help="salta la verifica di vita (DNS filtrato)")
    parser.add_argument("--dati", type=Path, help="certificati da file JSON in formato crt.sh")
    parser.add_argument("--oggi", type=date.fromisoformat, default=date.today(), help=argparse.SUPPRESS)
    parser.add_argument("--uscita", type=Path, default=OUT_DIR, help="cartella di output")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    cfg = carica_config()
    ctx = carica_contesto()
    if not ctx.piattaforme:
        warn("cache PSL privata assente: le piattaforme non vengono riconosciute (eseguire build_domains.py)")
    tutti = list(dict.fromkeys([p for m in cfg["marchi"] for p in m.get("cerca", m["parole"])]
                               + cfg.get("fonte", {}).get("prefissi_esca", [])))
    prefissi = prefissi_del_giro(tutti, cfg.get("fonte", {}).get("prefissi_per_giro", len(tutti)), args.oggi)
    inizio = time.monotonic()
    if args.dati:
        certificati, errori = json.loads(args.dati.read_text(encoding="utf-8")), []
    else:
        certificati, errori = interroga_crtsh(prefissi, cfg.get("fonte", {}))
    for e in errori:
        warn(f"crt.sh: {e}")
    stato_path = args.uscita / STATO_PATH.name
    stato = json.loads(stato_path.read_text(encoding="utf-8")) if stato_path.exists() else {}
    stato, lista, usciti, stat = esegui(cfg, ctx, certificati, stato, args.oggi,
                                        None if args.senza_dns else verifica_vita, errori, f"{len(prefissi)} di {len(tutti)}")
    stat["durata (secondi)"] = round(time.monotonic() - inizio)
    args.uscita.mkdir(parents=True, exist_ok=True)
    intest = ("# Candidati phishing-it da Certificate Transparency: IN OSSERVAZIONE, non è una blocklist pubblicata\n"
              if cfg.get("osservazione", True) else
              "# block-phishing-it: phishing di marchi italiani da Certificate Transparency\n")
    (args.uscita / CANDIDATI_PATH.name).write_text(intest + "".join(f"{d}\n" for d in lista),
                                                    encoding="utf-8", newline="\n")
    stato_path.write_text(json.dumps(dict(sorted(stato.items())), indent=1, ensure_ascii=False) + "\n",
                          encoding="utf-8", newline="\n")
    report = scrivi_report(stato, cfg, stat, lista, usciti, args.oggi, args.senza_dns, errori)
    (args.uscita / REPORT_PATH.name).write_text(report, encoding="utf-8", newline="\n")
    print(report)
    if errori and len(errori) == len(prefissi):
        warn("crt.sh non ha risposto a nessuna ricerca: stato aggiornato solo con la verifica di vita")
    return 0


if __name__ == "__main__":
    sys.exit(main())
