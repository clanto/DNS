#!/usr/bin/env python3
"""«Perché è bloccato?»: indice di spiegazione delle liste domini e ricerca da terminale.

L'indice è generato da scripts/build_domains.py (tramite scripts/punteggio.py) e non è versionato in git:
il workflow di build lo pubblica su GitHub Pages insieme a docs/ (https://clanto.github.io/DNS/perche/).
  dist/perche/meta.json   liste, fonti, pesi e precisione delle fonti, soglie, data del build
  dist/perche/<xx>.json   partizioni {"v":1,"d":{dominio: [record, ...]}}; xx = CRC-32 del dominio modulo
                          il numero di partizioni, in esadecimale (stesso calcolo in docs/perche-bloccato.html)

Record di un dominio (lista e fonti sono indici di meta.json "liste" e "fonti"):
  [lista, [fonti], primo, punteggio, strict]  bloccato da una lista con punteggio (primo = ore UTC dall'epoca Unix)
  [lista, [fonti]]                            bloccato da una lista senza punteggio
  [lista, [fonti], "motivo"]                  tolto da una blocklist (esclusione di cura, PSL, protetto, allowlist)
  [lista, "motivo"]                           presente in un'allowlist

Uso: python scripts/perche.py dominio|URL [--remoto] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import zlib
from datetime import datetime, timezone

from build_ip import ROOT, fetch

INDEX_DIR = ROOT / "dist" / "perche"
INDEX_URL = "https://clanto.github.io/DNS/perche"  # GitHub Pages (workflow di build), non versionato in git
VERSIONE = 1


def partizione(dominio: str, partizioni: int = 256) -> str:
    """Nome della partizione del dominio: hash modulo numero di partizioni, in esadecimale."""
    return f"{zlib.crc32(dominio.encode()) % partizioni:0{len(f'{partizioni - 1:x}')}x}"


def scrivi_indice(meta: dict, voci: dict[str, list], partizioni: int) -> tuple[int, int]:
    """Scrive meta.json e le partizioni; restituisce (file, byte totali)."""
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    larghezza = len(f"{partizioni - 1:x}")
    numerati: list[dict[str, list]] = [{} for _ in range(partizioni)]
    for nome, record in voci.items():
        numerati[zlib.crc32(nome.encode()) % partizioni][nome] = record  # come partizione(), senza formattare
    gruppi = {f"{i:0{larghezza}x}": g for i, g in enumerate(numerati)}
    for vecchio in INDEX_DIR.glob("*.json"):
        if vecchio.stem not in gruppi and vecchio.name != "meta.json":
            vecchio.unlink()
    totale = 0
    for nome, contenuto in gruppi.items():
        testo = json.dumps({"v": VERSIONE, "d": contenuto}, separators=(",", ":"), sort_keys=True) + "\n"
        (INDEX_DIR / f"{nome}.json").write_text(testo, encoding="utf-8", newline="\n")
        totale += len(testo)
    testo = json.dumps(meta, ensure_ascii=False, indent=1) + "\n"
    (INDEX_DIR / "meta.json").write_text(testo, encoding="utf-8", newline="\n")
    return partizioni + 1, totale + len(testo.encode("utf-8"))


def estrai_host(testo: str) -> str:
    """Host da un dominio, un URL o una regola AdGuard (||dominio^): minuscolo, IDN in punycode."""
    t = testo.strip().lower()
    t = t.removeprefix("@@").removeprefix("||").split("^")[0].split("$")[0]
    if "://" not in t:
        t = "http://" + t
    try:
        host = urllib.parse.urlsplit(t).hostname or ""
    except ValueError:
        return ""
    host = host.strip(".")
    try:
        return host.encode("idna").decode("ascii") if host else ""
    except UnicodeError:
        return host


def suffissi(host: str) -> list[str]:
    """host e tutti i domini padre, fino al TLD (block-tld blocca TLD interi)."""
    parti = host.split(".")
    return [".".join(parti[i:]) for i in range(len(parti))]


class Indice:
    """Indice locale (dist/perche) o remoto (raw URL del repository), letto per partizione."""

    def __init__(self, remoto: bool = False):
        self.remoto = remoto or not (INDEX_DIR / "meta.json").exists()
        self.meta = json.loads(self._leggi("meta.json"))
        self._cache: dict[str, dict] = {}

    def _leggi(self, nome: str) -> str:
        if self.remoto:
            return fetch(f"{INDEX_URL}/{nome}")
        return (INDEX_DIR / nome).read_text(encoding="utf-8")

    def record(self, dominio: str) -> list:
        nome = partizione(dominio, self.meta["partizioni"])
        if nome not in self._cache:
            self._cache[nome] = json.loads(self._leggi(f"{nome}.json"))["d"]
        return self._cache[nome].get(dominio, [])


def data_ora(ore: int) -> str:
    if not ore:
        return "non noto"
    return datetime.fromtimestamp(ore * 3600, tz=timezone.utc).strftime("%Y-%m-%d %H:00 UTC")


def spiega(host: str, indice: Indice) -> dict:
    """Risultato strutturato: blocchi, voci tolte, allowlist, azioni consigliate."""
    meta = indice.meta
    liste, fonti = meta["liste"], meta["fonti"]
    out = {"host": host, "bloccato": False, "blocchi": [], "tolte": [], "consentite": [], "azioni": []}
    for s in suffissi(host):
        for rec in indice.record(s):
            lista = liste[rec[0]]
            base = {"lista": lista["nome"], "regola": s, "padre": s != host}
            if lista["tipo"] == "allow":
                out["consentite"].append({**base, "motivo": rec[1]})
                continue
            nomi_fonti = [fonti[i] for i in rec[1]]
            if len(rec) == 3:
                out["tolte"].append({**base, "fonti": nomi_fonti, "motivo": rec[2]})
                continue
            voce = {**base, "fonti": nomi_fonti}
            if len(rec) == 5:
                voce.update(primo=data_ora(rec[2]), punteggio=rec[3], strict=bool(rec[4]))
            out["blocchi"].append(voce)
    out["bloccato"] = bool(out["blocchi"])
    out["sbloccato_adguard"] = bool(out["blocchi"] and out["consentite"])
    oggi = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if out["sbloccato_adguard"]:
        out["azioni"].append("un'allowlist lo sblocca già su AdGuard ($important): verificare che l'istanza sia abbonata "
                             "ad allow-base (le liste in formato semplice per firewall e Unbound lo bloccano comunque)")
    for b in out["blocchi"]:
        categoria = b["lista"].removeprefix("block-")
        esterne = [f for f in b["fonti"] if f != "manuale"]
        if b["padre"]:
            locale = f"per sbloccare solo {host}: eccezione locale nell'istanza AdGuard '@@||{host}^$important'"
            if esterne and "manuale" not in b["fonti"]:
                locale += ", o per tutti i clienti una voce in domains/allowlist/varie.txt"
            out["azioni"].append(locale)
        if "manuale" in b["fonti"]:
            out["azioni"].append(f"{b['regola']} è una voce nostra: toglierla da domains/blocklist/{categoria}.txt con una PR")
        if esterne:
            out["azioni"].append(f"falso positivo di {', '.join(esterne)}: aggiungere a domains/escludi.txt la riga "
                                 f"'{b['regola']} | {oggi} | motivo | ticket' (solo nome esatto, i sottodomini restano)")
    if not out["blocchi"]:
        out["azioni"].append("nessuna nostra lista lo blocca: controllare il Registro query di AdGuard (liste upstream "
                             "abbonate direttamente, domains/upstream.toml, o regole personalizzate dell'istanza)")
    out["azioni"] = list(dict.fromkeys(out["azioni"]))
    return out


def formatta(r: dict, meta: dict) -> str:
    esito = "non bloccato dalle nostre liste"
    if r["bloccato"]:
        esito = "BLOCCATO" + (" dalle liste, ma SBLOCCATO su AdGuard da un'allowlist" if r["sbloccato_adguard"] else "")
    righe = [f"{r['host']}: {esito} (indice del {meta.get('generato', '?')})"]
    for b in r["blocchi"]:
        regola = f"regola ||{b['regola']}^" + (" (dominio padre)" if b["padre"] else "")
        extra = ""
        if "punteggio" in b:
            extra = f", punteggio {b['punteggio']}, primo avvistamento {b['primo']}, strict: {'sì' if b['strict'] else 'no'}"
        righe.append(f"  - {b['lista']}: {regola}, fonti {', '.join(b['fonti'])}{extra}")
    for t in r["tolte"]:
        righe.append(f"  - non in {t['lista']} per {t['regola']}: {t['motivo']} (fonti {', '.join(t['fonti'])})")
    for c in r["consentite"]:
        righe.append(f"  - sbloccato da {c['lista']} con @@||{c['regola']}^: {c['motivo']}")
    righe.append("Cosa fare:")
    righe += [f"  - {a}" for a in r["azioni"]]
    return "\n".join(righe)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("voce", help="dominio, URL o regola AdGuard")
    parser.add_argument("--remoto", action="store_true", help="legge l'indice pubblicato su GitHub Pages invece di dist/perche")
    parser.add_argument("--json", action="store_true", help="risultato in JSON")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    host = estrai_host(args.voce)
    if not host or "." not in host and len(host) < 2:
        print(f"ERRORE: '{args.voce}' non contiene un dominio valido", file=sys.stderr)
        return 2
    indice = Indice(args.remoto)
    r = spiega(host, indice)
    print(json.dumps(r, ensure_ascii=False, indent=1) if args.json else formatta(r, indice.meta))
    return 0


if __name__ == "__main__":
    sys.exit(main())
