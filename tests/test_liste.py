#!/usr/bin/env python3
"""Test di integrazione delle liste: build IP e domini, file generati, validazioni, guardrail, documentazione.

Richiede rete (scarica fonti e intervalli condivisi) e riscrive i file generati nella copia di lavoro.
Uso: python tests/test_liste.py
"""
import hashlib
import io
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_domains as BD  # noqa: E402
import build_ip as B  # noqa: E402

FAILS: list[str] = []
PASSES = 0


def check(cond, msg):
    global PASSES
    if cond:
        PASSES += 1
    else:
        FAILS.append(msg)


def quiet(fn, *a, **k):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*a, **k)


def run_main(mod, *args):
    old = sys.argv
    sys.argv = ["x", *args]
    try:
        return quiet(mod.main)
    finally:
        sys.argv = old


def digest(paths):
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode() + p.read_bytes())
    return h.hexdigest()


def section_ip_build():
    check(run_main(B, "--check") == 0, "build_ip --check fallisce")
    check(run_main(B) == 0, "build_ip build fallisce")
    d1 = digest(list((ROOT / "dist/ip").glob("*.txt")) + list((ROOT / "ip/cache").glob("*")))
    check(run_main(B, "--offline") == 0, "build_ip --offline fallisce")
    d2 = digest(list((ROOT / "dist/ip").glob("*.txt")) + list((ROOT / "ip/cache").glob("*")))
    check(d1 == d2, "build offline dalla cache non riproduce gli stessi feed (non deterministico)")


def section_ip_outputs():
    cfg = tomllib.loads((ROOT / "ip/sources.toml").read_text(encoding="utf-8"))
    cats, aggs = cfg["categories"], cfg["aggregates"]
    feeds = {}
    for p in sorted((ROOT / "dist/ip").glob("*.txt")):
        raw = p.read_bytes()
        check(b"\r" not in raw, f"{p.name}: contiene CRLF")
        nets = []
        for ln in raw.decode().splitlines():
            try:
                nets.append(ipaddress.ip_network(ln, strict=True))
            except ValueError:
                FAILS.append(f"{p.name}: riga non valida '{ln}'")
        feeds[p.name] = nets
        check(len(nets) == len(set(nets)), f"{p.name}: duplicati")
        check(nets == sorted(nets, key=B.sort_key), f"{p.name}: non ordinato")
        ver = 4 if "-v4" in p.name else 6
        check(all(n.version == ver for n in nets), f"{p.name}: famiglia IP mista")
        check(len(list(ipaddress.collapse_addresses(nets))) == len(nets), f"{p.name}: reti sovrapposte non accorpate")
        if not p.name.startswith("bogon"):
            bad = [str(n) for n in nets if B.reject_reason(n, {4: 8, 6: 16}) == "non instradabile"]
            check(not bad, f"{p.name}: reti private/riservate {bad[:3]}")

    expected = {f"{c}-v{v}.txt" for c in list(cats) + list(aggs) for v in (4, 6)}
    check(set(feeds) == expected, f"feed attesi/presenti diversi: {set(feeds) ^ expected}")
    for name, agg in aggs.items():
        for v in (4, 6):
            union = sorted(ipaddress.collapse_addresses(n for c in agg["categories"] for n in feeds[f"{c}-v{v}.txt"]),
                           key=B.sort_key)
            check(union == feeds[f"{name}-v{v}.txt"], f"{name}-v{v} non coincide con l'unione delle categorie")
        for excluded in ("inbound", "bogon", "hacking", "warez", "social"):
            check(excluded not in agg["categories"], f"{excluded} non dovrebbe essere nell'aggregato {name}")
    check(set(aggs["all"]["categories"]) < set(aggs["all-scuole"]["categories"]), "all-scuole non estende all")
    check(len(feeds["tor-v4.txt"]) > 3000 and len(feeds["tor-v6.txt"]) > 1000, "relay Tor mancanti nel feed tor")
    check(len(feeds["social-v4.txt"]) > 50 and len(feeds["social-v6.txt"]) > 20, "feed social vuoto o incompleto")
    check((ROOT / "DNSoverHTTPS/ipv4.txt").read_bytes() == (ROOT / "dist/ip/doh-v4.txt").read_bytes(),
          "DNSoverHTTPS/ipv4.txt diverso da doh-v4.txt")

    # resolver pubblici: devono restare bloccati anche dentro reti condivise (keep)
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "45.90.28.55",
               "2001:4860:4860::8888", "2606:4700:4700::1111", "2a07:a8c0::46:485e"):
        a = ipaddress.ip_address(ip)
        for feed in ("doh", "all", "all-scuole"):
            name = f"{feed}-v{a.version}.txt"
            check(any(a in n for n in feeds[name]), f"{ip} manca nel feed {name}")
    # infrastrutture condivise e servizi che hanno già dato falsi positivi: mai nei feed
    for ip in ("13.248.169.48", "76.223.54.146", "76.76.21.22", "17.248.195.56", "142.251.127.109",
               "199.36.158.100", "172.253.114.101"):
        a = ipaddress.ip_address(ip)
        check(not any(a in n for n in feeds[f"all-scuole-v{a.version}.txt"]), f"{ip} (condiviso) in all-scuole")

    stats = json.loads((ROOT / "dist/ip/stats.json").read_text(encoding="utf-8"))
    check(all(stats["feed"][k] == len(v) for k, v in feeds.items()), "stats.json non coincide con i feed")
    check({"condivisi", "protetti", "allowlist"} <= stats.keys(), "stats.json senza sezioni condivisi/protetti")
    cache_ids = {p.stem for p in (ROOT / "ip/cache").glob("*.txt")}
    enabled = {s["id"] for s in cfg["sources"] if s.get("enabled", True)}
    check(cache_ids == enabled, f"cache non allineata alle fonti attive: {cache_ids ^ enabled}")

    shared = B.NetIndex(B.load_shared(cfg, []))
    for cat in [c for c, m in cats.items() if m.get("exclude_shared")]:
        bad = [str(n) for v in (4, 6) for n in feeds[f"{cat}-v{v}.txt"] if shared.overlaps(n)]
        check(not bad, f"{cat}: IP su infrastruttura condivisa {bad[:5]}")


def section_parsers():
    nets, rej = B.parse_source_text("0.0.0.0/8\n10.1.1.1\n8.0.0.0/8\n1.2.3.4 # c\n5.5.5.1-5.5.5.2\n"
                                    '{"cidr":"2a00:1450::/32"}\n{"type":"metadata"}\n2001:db8::1\nxx\n'
                                    "0.0.0.0 ads.example\n64.227.191.20\t7\n", {4: 16, 6: 32})
    check({str(n) for n in nets} == {"1.2.3.4/32", "5.5.5.1/32", "5.5.5.2/32", "2a00:1450::/32", "64.227.191.20/32"},
          f"parser: risultato inatteso {sorted(map(str, nets))}")
    check(rej["troppo ampia"] == 1 and rej["non valida"] == 1 and rej["non instradabile"] == 4, f"parser: scarti {dict(rej)}")
    raw_nets, _ = B.parse_source_text("10.0.0.0/8\n224.0.0.0/4\n", None)
    check(len(raw_nets) == 2, "parser raw (bogon) scarta reti riservate")
    onion = B.onionoo_to_text('{"relays":[{"or_addresses":["1.2.3.4:9001","[2a01:4f8::1]:443"]},'
                              '{"or_addresses":["5.6.7.8:443"]}]}')
    check(onion.split("\n") == ["1.2.3.4", "2a01:4f8::1", "5.6.7.8"], f"parser Onionoo: {onion}")

    out, touched = B.subtract([ipaddress.ip_network("1.10.16.0/20")], [ipaddress.ip_network("1.10.16.5/32")])
    check(touched == 1 and not any(ipaddress.ip_address("1.10.16.5") in n for n in out)
          and sum(n.num_addresses for n in out) == 4095, "subtract: esclusione parziale errata")
    out, _ = B.subtract([ipaddress.ip_network("1.2.3.4/32")], [ipaddress.ip_network("1.2.0.0/16")])
    check(out == [], "subtract: rete interamente coperta non rimossa")
    idx = B.NetIndex(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "2001:db8::/32"))  # generatore
    check(idx.overlaps(ipaddress.ip_network("2001:db8::1")), "NetIndex: IPv6 perso con un generatore in ingresso")
    check(idx.overlaps(ipaddress.ip_network("10.1.0.0/16")) and not idx.overlaps(ipaddress.ip_network("11.0.0.0/8")),
          "NetIndex: sovrapposizioni IPv4 errate")

    tmp = B.CUSTOM_DIR / "_test.txt"
    tmp.write_text("\n".join([
        "8.8.8.8 | 2026-01-01 | ok | TCK-1",
        "8.8.8.8 | 2026-01-01 | dup | -",
        "9.9.9.1 | 2026-01-01 | chiamare +39 333 1234567 | -",
        "9.9.9.2 | 2026-01-01 | scrivere a nome@example.com | -",
        "9.9.9.3 | 2026-01-01 | scaduta | - | 2020-01-01",
        "192.168.1.1 | 2026-01-01 | privata | -",
        "9.9.9.4 | 2026-02-30 | data | -",
        "9.9.9.5 | 2026-01-01 | visto il 2024-10-25 su 1.2.3.4 | TCK-9",
        "9.9.9.6",
        "9.0.0.0/8 | 2026-01-01 | troppo ampia | -",
        "9.9.9.7 | 2026-01-01 | ticket strano | TCK 1",
        "9.9.9.8 | 2026-01-01 | futura | - | 2099-01-01",
    ]) + "\n", encoding="utf-8", newline="\n")
    errs = []
    try:
        ents, exp = B.load_annotated(tmp, min_prefix={4: 16, 6: 32}, today=date.today(), errors=errs)
    finally:
        tmp.unlink()
    check([str(e.net) for e in ents] == ["8.8.8.8/32", "9.9.9.5/32", "9.9.9.8/32"],
          f"voci manuali attive: {[str(e.net) for e in ents]}")
    check(exp == 1, "voci manuali scadute")
    check(len(errs) == 8, f"voci manuali: attesi 8 errori, trovati {len(errs)}: {errs}")


def section_guardrails():
    src = {"id": "_t", "category": "threat", "url": "https://example.invalid/x", "license": "x"}
    cache = B.CACHE_DIR / "_t.txt"
    cache.write_text("".join(f"1.2.3.{i}\n" for i in range(1, 101)), encoding="utf-8", newline="\n")
    orig_fetch = B.fetch

    def down(_url):
        raise OSError("rete giù")

    try:
        B.fetch = down
        n, r = quiet(B.load_source, src, {}, False, False)
        check(r.status == "cache" and len(n) == 100, "guardrail: errore di rete non usa la cache")
        B.fetch = lambda u: "1.2.3.1\n"
        n, r = quiet(B.load_source, src, {"max_drop_ratio": 0.5}, False, False)
        check(r.status == "cache" and len(n) == 100, "guardrail: calo >50% non usa la cache")
        B.fetch = lambda u: "# vuoto\n"
        n, r = quiet(B.load_source, src, {}, False, False)
        check(r.status == "cache", "guardrail: lista vuota non usa la cache")
        B.fetch = lambda u: "".join(f"1.2.4.{i}\n" for i in range(1, 91))
        n, r = quiet(B.load_source, src, {"max_drop_ratio": 0.5}, False, False)
        check(r.status == "ok" and len(n) == 90, "guardrail: variazione normale rifiutata")
        cache.unlink()
        B.fetch = down
        n, r = quiet(B.load_source, src, {}, False, False)
        check(r.status == "fallita" and not n, "guardrail: senza cache non segnala 'fallita'")
    finally:
        B.fetch = orig_fetch
        cache.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for p in (ROOT / "dist/ip").glob("*.txt"):
            (tdp / p.name).write_bytes(p.read_bytes())
        (tdp / "threat-v4.txt").write_text("".join(f"1.1.{i // 256}.{i % 256}\n" for i in range(200)), encoding="utf-8")
        gh_out = tdp / "gh_out"
        orig_dist = B.DIST_DIR
        B.DIST_DIR = tdp
        os.environ["GITHUB_OUTPUT"] = str(gh_out)
        try:
            run_main(B, "--check")
        finally:
            B.DIST_DIR = orig_dist
            del os.environ["GITHUB_OUTPUT"]
        check("anomaly=true" in gh_out.read_text(), "anomalia su variazione >25% non rilevata")


def section_domains():
    check(run_main(BD, "--check") == 0, "build_domains --check fallisce")
    check(run_main(BD) == 0, "build_domains build fallisce")
    adg_allow = re.compile(r"^@@\|\|[a-z0-9*._-]+\^\$important$")
    adg_block = re.compile(r"^\|\|[a-z0-9*._-]+\^(\$important)?$")
    blocked: set[str] = set()
    for p in (ROOT / "dist/adguard").glob("*.txt"):
        lines = p.read_text(encoding="utf-8").splitlines()
        rx = adg_allow if p.name.startswith("allow-") else adg_block
        bad = [line for line in lines if not rx.match(line)]
        check(not bad, f"{p.name}: righe AdGuard non valide {bad[:3]}")
        check(len(lines) == len(set(lines)), f"{p.name}: duplicati")
        check(b"\r" not in p.read_bytes(), f"{p.name}: CRLF")
        if p.name.startswith("block-"):
            blocked |= {line[2:].split("^")[0] for line in lines}
    minimi = {"block-doh.txt": 1000, "block-vpn.txt": 1000, "block-malware.txt": 50000, "block-phishing.txt": 50000,
              "block-redirect.txt": 20000, "block-pirateria.txt": 10000, "block-spyware.txt": 300,
              "block-cryptojacking.txt": 100, "block-porno.txt": 20000, "block-social.txt": 100,
              "block-pubblicita.txt": 30000, "block-traccianti.txt": 30000, "block-ddns.txt": 1000}
    for name, minimo in minimi.items():
        check(len((ROOT / "dist/adguard" / name).read_text().splitlines()) > minimo, f"{name}: troppo poche voci")
    check(not list((ROOT / "dist/unbound").glob("block-*.conf")),
          "regole Unbound delle blocklist: OPNsense usa i link di dist/domains/")
    for legacy in ("appspia", "criptojacking", "malware", "pishing", "redirect", "warez", "lista_streaming_illegale",
                   "pornoextra", "roblox", "test"):
        check(not (ROOT / f"liste/{legacy}.txt").exists(), f"liste/{legacy}.txt sostituita ma ancora presente")
    check(not (ROOT / "safe_search").exists(), "safe_search/ sostituita ma ancora presente")
    ss = (ROOT / "dist/unbound/safesearch.conf").read_text(encoding="utf-8")
    for needle in ('"www.google.it A ', '"www.youtube.com A ', '"www.bing.com A ', '"pixabay.com A '):
        check(needle in ss, f"safesearch.conf senza {needle}")
    vpn = set((ROOT / "dist/domains/block-vpn.txt").read_text().split())
    doh = set((ROOT / "dist/domains/block-doh.txt").read_text().split())
    for excluded in ("fortinet.com", "checkpoint.com", "wellpoint.com", "opendns.com", "adguard.io"):
        check(excluded not in vpn and excluded not in doh, f"esclusione di cura non applicata: {excluded}")
    ddns = set((ROOT / "dist/domains/block-ddns.txt").read_text().split())
    trk = set((ROOT / "dist/domains/block-traccianti.txt").read_text().split())
    ads = set((ROOT / "dist/domains/block-pubblicita.txt").read_text().split())
    check({"duckdns.org", "ddns.net", "hopto.org"} <= ddns, "block-ddns senza i provider DDNS principali")
    for gestione in ("noip.com", "dyn.com", "dyndns.com", "dynu.com", "afraid.org"):
        check(gestione in ddns, f"block-ddns: sito del provider non bloccato: {gestione}")
    for critico in ("data.microsoft.com", "geotrust.com", "urldefense.com", "safebrowsing.apple"):
        check(critico not in trk and critico not in ads, f"traccianti/pubblicita: servizio critico bloccato: {critico}")
    for protetto in ("push.apple.com", "wns.windows.com", "www.google.com", "teams.microsoft.com"):
        check(protetto not in trk | ads | ddns, f"servizio protetto in blocklist: {protetto}")
    check("doh.opendns.com" in doh, "le esclusioni non devono toccare i sottodomini (doh.opendns.com)")
    gaming = (ROOT / "dist/domains/block-gaming.txt").read_text().split()
    check("roblox.com" in gaming, "roblox.com non in block-gaming")
    check(not list((ROOT / "dist/domains").glob("allow-*")), "allowlist in formato semplice presenti")
    base = set((ROOT / "dist/adguard/allow-base.txt").read_text().splitlines())
    check(not any("spotify" in line or "netflix" in line for line in base), "streaming finito in allow-base")

    protected = [line.split("|")[0].strip() for line in
                 (ROOT / "domains/allowlist/protetti.txt").read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.startswith("#")]
    check(len(protected) >= 30, "lista protetti troppo corta")
    for host in protected:
        check(host not in blocked, f"servizio protetto {host} presente in una blocklist")
        check(f"@@||{host}^$important" in base or any(host.endswith("." + b[4:].split("^")[0]) for b in base),
              f"servizio protetto {host} non in allow-base")

    allow_names = [line.split("|")[0].strip() for f in (ROOT / "domains/allowlist").glob("*.txt")
                   for line in f.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    for forbidden in ("icloud.com", "apple-dns.net", "nordvpn.com", "cisco.com", "eset.com", "support.anydesk.com",
                      "*-pa.googleapis.com", "elasticbeanstalk.com", "ahcdn.com", "samsungads.com", "paypal.com"):
        check(forbidden not in allow_names, f"voce vietata in allowlist: {forbidden}")

    # un'allowlist non deve mai contraddire una blocklist (anche i TLD bloccati)
    for extra in ("support.anydesk.com", "sito.world"):
        f = ROOT / "domains/allowlist/varie.txt"
        bak = f.read_text(encoding="utf-8")
        f.write_text(bak + f"{extra} | 2026-09-24 | test | -\n", encoding="utf-8", newline="\n")
        try:
            err = io.StringIO()
            old = sys.argv
            sys.argv = ["x", "--check"]
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                rc = BD.main()
            sys.argv = old
            check(rc == 1 and "conflitto" in err.getvalue(), f"conflitto con '{extra}' non rilevato")
        finally:
            f.write_text(bak, encoding="utf-8", newline="\n")
    check(BD.covers("*-pa.googleapis.com", "phosphor-pa.googleapis.com"), "covers: wildcard")
    check(not BD.covers("spotify.com", "notspotify.com"), "covers: falso positivo su suffisso")
    check(BD.normalize("*.Esempio.IT.") == "esempio.it", "normalize")
    check(BD.normalize("città.it") == "xn--citt-3na.it", "normalize IDN")


def section_punteggio():
    import perche
    import punteggio as P
    cfg = tomllib.loads((ROOT / "domains/domains.toml").read_text(encoding="utf-8"))
    soglie = cfg["punteggio"]["strict"]
    conf = {**P.DEFAULTS, **{k: v for k, v in cfg["punteggio"].items() if not isinstance(v, dict)}}
    check(set(soglie) == {"malware", "phishing", "spyware", "cryptojacking", "redirect", "pubblicita", "traccianti"},
          "livello strict: categorie diverse da quelle di sicurezza")

    # formula: voce manuale sempre 100; due fonti valgono più di una; la persistenza alza il punteggio
    check(P.punteggio([], 0, True, conf) == 100, "punteggio: voce manuale non a 100")
    nuova, vecchia = P.punteggio([0.8], 0, False, conf), P.punteggio([0.8], 1000, False, conf)
    check(nuova < vecchia, "punteggio: la persistenza non conta")
    check(P.punteggio([0.8, 0.8], 0, False, conf) > nuova, "punteggio: due fonti non valgono più di una")
    check(P.punteggio([0.7], 10 ** 6, False, conf) < soglie["malware"],
          "soglia strict: una sola fonte con peso 0,7 non deve bastare")
    check(P.punteggio([0.8], 10 ** 6, False, conf) >= soglie["malware"],
          "soglia strict: una fonte affidabile e persistente deve bastare")
    stato = P.aggiorna_stato({"a.com": 10, "b.com": 12}, {"a.com", "c.com"}, 20)
    check(stato == {"a.com": 10, "c.com": 20}, f"persistenza: aggiornamento errato {stato}")
    check(P.controlla_calo({"x.txt": 1000}, {"x.txt": 700}, 0.2, 100) != [], "guardrail strict: calo del 30% non segnalato")
    check(P.controlla_calo({"x.txt": 1000}, {"x.txt": 900}, 0.2, 100) == [], "guardrail strict: calo del 10% segnalato")
    check(P.controlla_calo({"x.txt": 50}, {"x.txt": 0}, 0.2, 100) == [], "guardrail strict: liste piccole controllate")

    # CrUX: parsing per fascia, padri coperti, mai su malware/pubblicità/spyware (lì il sito popolare è il bersaglio)
    crux = P.parse_crux("origin,rank\nhttps://www.example.com,1000\nhttps://shop.example.org:8443,5000\n"
                        "http://lontano.example.net,100000\n", 10000)
    check(crux == {"www.example.com": 1000, "shop.example.org": 5000}, f"CrUX: parsing errato {crux}")
    check({"example.com", "www.example.com"} <= P.padri(set(crux)), "CrUX: dominio padre di un sito popolare non coperto")
    check(not {"malware", "pubblicita", "traccianti", "spyware"} & set(conf["crux_categorie"]),
          "CrUX: categorie dove un sito popolare è il bersaglio")
    ctx = P.Contesto(set(), set(), set(), {}, [], lambda a, b: False, sorted, {"www.example.com": 1000})
    m = P.misura_fonti({"phishing": {"f": {"example.com", "phish.example.net"}},
                        "malware": {"g": {"example.com", "bad.example.net"}}}, ctx, conf)
    check(m["f"]["falsi_positivi"] == 1 and m["g"]["falsi_positivi"] == 0,
          "CrUX: segnale di popolarità applicato alla categoria sbagliata")
    crux_cache = ROOT / "domains/cache/crux-top.txt"
    if crux_cache.exists():
        check("sites.google.com" not in set((ROOT / "dist/domains/block-phishing.txt").read_text().split()),
              "block-phishing: sites.google.com (Google Sites delle scuole) bloccato")

    # strict sottoinsieme della lista completa (stessi host bloccati o meno), voci manuali sempre presenti
    for cat in soglie:
        full_plain = set((ROOT / f"dist/domains/block-{cat}.txt").read_text().split())
        strict_plain = set((ROOT / f"dist/domains/block-{cat}-strict.txt").read_text().split())
        check(strict_plain <= full_plain, f"block-{cat}-strict (domini) non è sottoinsieme della lista completa")
        full_adg = {line[2:-1] for line in (ROOT / f"dist/adguard/block-{cat}.txt").read_text().splitlines()}
        strict_adg = [line[2:-1] for line in (ROOT / f"dist/adguard/block-{cat}-strict.txt").read_text().splitlines()]
        scoperte = [d for d in strict_adg if not any(s in full_adg for s in perche.suffissi(d))]
        check(not scoperte, f"block-{cat}-strict (AdGuard) blocca host fuori dalla lista completa: {scoperte[:3]}")
        manuale = ROOT / f"domains/blocklist/{cat}.txt"
        if manuale.exists():
            voci = {line.split("|")[0].strip() for line in manuale.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")}
            mancanti = [v for v in voci if "*" not in v and v not in strict_plain and v in full_plain]
            check(not mancanti, f"block-{cat}-strict senza voci manuali {mancanti[:3]}")

    # il percorso di anomalia scatta se una lista strict perde più della quota configurata
    target = ROOT / "dist/domains/block-spyware-strict.txt"
    bak = target.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        gh_out = Path(td) / "gh_out"
        target.write_text("".join(f"finto{i}.example\n" for i in range(5000)), encoding="utf-8", newline="\n")
        os.environ["GITHUB_OUTPUT"] = str(gh_out)
        try:
            run_main(BD, "--check")
        finally:
            del os.environ["GITHUB_OUTPUT"]
            target.write_bytes(bak)
        check("anomaly=true" in gh_out.read_text(), "calo della lista strict non segnalato come anomalia")

    # indice «Perché è bloccato?»: partizioni coerenti, voci tolte con motivo, allowlist
    meta = json.loads((ROOT / "dist/perche/meta.json").read_text(encoding="utf-8"))
    parts = sorted(p.stem for p in (ROOT / "dist/perche").glob("*.json") if p.stem != "meta")
    check(len(parts) == meta["partizioni"], "indice: numero di partizioni errato")
    check(perche.partizione("esempio.it", 256) == f"{__import__('zlib').crc32(b'esempio.it') % 256:02x}", "indice: hash")
    idx = perche.Indice()
    for nome in ("duckdns.org", "fortinet.com", "push.apple.com"):
        check(nome in json.loads((ROOT / f"dist/perche/{perche.partizione(nome)}.json").read_text())["d"],
              f"indice: {nome} nella partizione sbagliata o assente")
    r = perche.spiega("app.qualcosa.duckdns.org", idx)
    check(r["bloccato"] and any(b["lista"] == "block-ddns" and b["padre"] for b in r["blocchi"]),
          "perche: sottodominio DDNS non spiegato con la regola sul padre")
    r = perche.spiega("fortinet.com", idx)
    check(not r["bloccato"] and any("esclusione di cura" in t["motivo"] for t in r["tolte"]),
          "perche: esclusione di cura di fortinet.com non spiegata")
    r = perche.spiega("push.apple.com", idx)
    check(not r["bloccato"] and any(c["lista"] == "allow-protetti" for c in r["consentite"]),
          "perche: servizio protetto non spiegato")
    check(any("protetto" in t["motivo"] for t in r["tolte"]), "perche: voce tolta perché protetta non spiegata")
    spy = next(line.split("|")[0].strip() for line in (ROOT / "domains/blocklist/spyware.txt").read_text(encoding="utf-8")
               .splitlines() if line.strip() and not line.startswith("#"))
    r = perche.spiega(spy, idx)
    check(any(b["lista"] == "block-spyware" and b["punteggio"] == 100 and b["strict"] for b in r["blocchi"]),
          f"perche: voce manuale {spy} senza punteggio 100 o fuori dallo strict")
    for testo, atteso in (("https://Login.Esempio.IT:8443/a?b=c", "login.esempio.it"), ("||ads.esempio.it^", "ads.esempio.it"),
                          ("città.it", "xn--citt-3na.it"), ("esempio.it.", "esempio.it")):
        check(perche.estrai_host(testo) == atteso, f"perche: estrai_host('{testo}') = {perche.estrai_host(testo)}")

    # la pagina statica usa lo stesso hash e la stessa estrazione dell'host (verifica con Node se disponibile)
    page = (ROOT / "docs/perche-bloccato.html").read_text(encoding="utf-8")
    check("<script src" not in page and "<link" not in page and "googletagmanager" not in page,
          "perche-bloccato.html: dipendenze o tracker esterni")
    check(re.findall(r"https://[a-z0-9.-]+", page) and all(
        u in ("https://raw.githubusercontent.com", "https://github.com", "https://app.esempio.it") for u in re.findall(r"https://[a-z0-9.-]+", page)),
        "perche-bloccato.html: domini esterni diversi da GitHub")
    check(".innerHTML" not in page, "perche-bloccato.html: innerHTML (i dati dell'indice vanno inseriti come testo)")
    check('"./perche/"' in page and "raw.githubusercontent.com" not in page,
          "perche-bloccato.html: l'indice va letto dallo stesso sito Pages, non dai raw URL")
    # l'indice cambia a ogni build: mai nella storia git (pubblicato solo su GitHub Pages)
    ignorato = subprocess.run(["git", "check-ignore", "-q", "dist/perche/meta.json"], cwd=ROOT).returncode == 0
    check(ignorato, "dist/perche non è in .gitignore")
    build_wf = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    check("upload-pages-artifact" in build_wf and "deploy-pages" in build_wf, "build.yml: pubblicazione Pages assente")
    node = __import__("shutil").which("node")
    if node:
        core = page.split("  var TABLE = ")[1].split("var cache = {}")[0]
        casi = ["esempio.it", "login.esempio.it", "xn--citt-3na.it", "duckdns.org"]
        url_casi = ["https://Login.Esempio.IT:8443/a?b=c", "||ads.esempio.it^", "città.it", "esempio.it."]
        js = ("var TABLE = " + core + "\nconsole.log(JSON.stringify({p: "
              + json.dumps(casi) + ".map(function(d){return partizione(d, 256)}), h: " + json.dumps(url_casi)
              + ".map(estraiHost)}));")
        out = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8")
        try:
            res = json.loads(out.stdout)
        except ValueError:
            res = {}
            FAILS.append(f"perche-bloccato.html: errore JavaScript {out.stderr[:200]}")
        if res:
            check(res["p"] == [perche.partizione(d) for d in casi], f"pagina: hash diverso da Python {res['p']}")
            check(res["h"] == [perche.estrai_host(u) for u in url_casi], f"pagina: host diversi da Python {res['h']}")


def section_security():
    import gzip
    import urllib.error
    import urllib.request

    import asn
    import check_opnsense_ips as coi
    import inspect

    # dominio registrabile con la PSL completa: a.co.uk e b.co.uk sono domini diversi
    coi.PSL.__init__("// ===BEGIN ICANN DOMAINS===\nuk\nco.uk\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n")
    check(coi.registrable("www.a.co.uk") == "a.co.uk" and coi.registrable("b.co.uk") == "b.co.uk",
          "PSL: dominio registrabile errato per co.uk")
    check(coi.registrable("x.y.github.io") == "y.github.io", "PSL: piattaforma privata non riconosciuta")
    check(coi.registrable("a.b.ck") == "a.b.ck" and coi.registrable("www.ck") == "www.ck", "PSL: wildcard/eccezioni")
    check(coi.registrable("host.example.com") == "example.com", "PSL: regola implicita '*' non applicata")
    coi.PSL.__init__()
    check("total" in inspect.signature(asn.read_https).parameters, "download senza limite di tempo totale")
    check(not hasattr(asn, "names"), "asn.names() inutilizzata ancora presente")
    try:
        asn.read_https("http://example.invalid/x", timeout=1, limit=10)
        FAILS.append("read_https: URL http accettato")
    except ValueError:
        check(True, "")
    handler = asn._HttpsOnlyRedirect()
    req = urllib.request.Request("https://example.invalid/a")
    try:
        handler.redirect_request(req, None, 302, "Found", {}, "http://example.invalid/b")
        FAILS.append("redirect verso http seguito")
    except urllib.error.URLError:
        check(True, "")
    check(handler.redirect_request(req, None, 302, "Found", {}, "https://example.invalid/b") is not None,
          "redirect verso https rifiutato")

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()

    class FakeOpener:
        def open(self, req, timeout):
            return FakeResp(b"x" * 4096)

    orig = asn._OPENER
    asn._OPENER = FakeOpener()
    try:
        try:
            asn.read_https("https://example.invalid/x", timeout=1, limit=1024)
            FAILS.append("read_https: risposta oltre il limite accettata")
        except ValueError:
            check(True, "")
        check(asn.read_https("https://example.invalid/x", timeout=1, limit=8192) == b"x" * 4096,
              "read_https: risposta entro il limite rifiutata")
        check(len(B.fetch("https://example.invalid/x")) == 4096, "fetch non usa read_https")
    finally:
        asn._OPENER = orig
    bomb = gzip.compress(b"\0" * (4 * 1024 * 1024))
    try:
        asn.gunzip(bomb, limit=1024 * 1024)
        FAILS.append("gunzip: limite di decompressione ignorato")
    except ValueError:
        check(True, "")
    check(asn.gunzip(gzip.compress(b"abc")) == b"abc", "gunzip: contenuto valido rifiutato")

    cell = B.md_cell("HTTP Error 500: x | [clic](http://evil.example) <img src=x>\n`y`")
    check(not any(c in cell for c in "|[]<>`\n"), f"md_cell non sanifica: {cell}")
    src = {"id": "_sec", "category": "threat", "url": "https://example.invalid/x", "license": "x"}
    orig_fetch = B.fetch

    def evil(_url):
        raise OSError("errore | [link](http://evil.example)")

    try:
        B.fetch = evil
        _, r = quiet(B.load_source, src, {}, False, False)
        check("|" not in r.detail and "[" not in r.detail, f"dettaglio errore non sanificato nel README: {r.detail}")
    finally:
        B.fetch = orig_fetch
    for bad in ("../x", "a/b", "..", "A", "x\\y", ""):
        check(not B.SOURCE_ID_RE.match(bad), f"id di fonte non valido accettato: {bad!r}")
    check(B.SOURCE_ID_RE.match("hagezi-tif-mini"), "id di fonte valido rifiutato")
    try:
        BD.normalize("faß.de")
        FAILS.append("normalize: 'faß.de' convertito con IDNA 2003 in fass.de")
    except UnicodeError:
        check(True, "")
    check(BD.normalize("Sub.Example.COM") == "sub.example.com", "normalize ASCII")
    check(BD.drop_covered({"a.b.c", "b.c", "x.y"}) == ["b.c", "x.y"], "drop_covered")
    check(BD.covered_by("a.b.c", {"c"}) and not BD.covered_by("b.c", {"b.c"}), "covered_by")


def section_catalog():
    import build_index
    check(quiet(build_index.main) == 0, "build_index fallisce")
    index = json.loads((ROOT / "dist/index.json").read_text(encoding="utf-8"))
    check(len(index["feed"]) > 50, "index.json: troppo pochi feed")
    for f in index["feed"]:
        rel = f["url"].removeprefix(B.RAW_BASE + "/")
        check((ROOT / rel).exists(), f"index.json: {f['id']} punta a un file inesistente")
        check(f["voci"] == sum(1 for line in (ROOT / rel).read_text(encoding="utf-8").splitlines()
                               if line.strip() and not line.startswith("#")), f"index.json: voci errate per {f['id']}")
    third = (ROOT / "dist/THIRD_PARTY.md").read_text(encoding="utf-8")
    for cfg_path in ("ip/sources.toml", "domains/domains.toml"):
        cfg = tomllib.loads((ROOT / cfg_path).read_text(encoding="utf-8"))
        for s in cfg.get("sources", []):
            if s.get("enabled", True):
                check(f"| {s['id']} |" in third, f"THIRD_PARTY.md senza la fonte {s['id']}")


def section_repository():
    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        text = wf.read_text(encoding="utf-8")
        check("jobs:" in text and "\t" not in text, f"{wf.name}: struttura o tabulazioni")
        for repo, sha, tag in re.findall(r"uses: ([\w/-]+)@([0-9a-f]{40}) # (v[\d.]+)", text):
            out = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}", f"refs/tags/{tag}"],
                                 capture_output=True, text=True).stdout
            check(out.startswith(sha), f"{wf.name}: SHA {repo}@{tag} non corrisponde al tag")
    for md in [ROOT / "README.md", ROOT / "ip/README.md", ROOT / "dist/ip/README.md", ROOT / "dist/adguard/README.md"]:
        for link in re.findall(r"\]\(([^)]+)\)", md.read_text(encoding="utf-8")):
            if link.startswith(B.RAW_BASE + "/"):
                target = ROOT / link[len(B.RAW_BASE) + 1:]
            elif link.startswith(("http", "#")):
                continue
            else:
                target = (md.parent / link.split("#")[0]).resolve()
            check(target.exists(), f"{md.relative_to(ROOT)}: link rotto {link}")

    tracked = subprocess.run(["git", "ls-files", "--others", "--cached", "--exclude-standard"], cwd=ROOT,
                             capture_output=True, text=True).stdout.split()
    files = [ROOT / f for f in tracked if (f.split("/")[0] in ("ip", "domains", "scripts", ".github", "dist", "tests")
                                           or f in ("README.md", ".gitattributes")) and "__pycache__" not in f]
    for f in files:
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if f.suffix != ".md" and f.name != "test_liste.py":
            # regole AdGuard per singolo cliente: contengono nomi e IP dei clienti, mai nel repository pubblico
            check("$client" not in text, f"{f.relative_to(ROOT)}: regola \\$client nel repository pubblico")
        if f.suffix in (".md", ".toml", ".py", ".yml", ".txt"):
            bad = re.findall(r"(?<![\w'\"])(?:perch|poich|cio|pi|gi|pu|cos|citt|qualit|novit|attivit|sar|funzionalit|e)'"
                             r"(?=[\s.,;:)]|$)", text)
            check(not bad, f"{f.relative_to(ROOT)}: accenti scritti con apostrofo {bad[:3]}")
        check(b"\r\n" not in f.read_bytes(), f"{f.relative_to(ROOT)}: CRLF")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    for section in (section_ip_build, section_ip_outputs, section_parsers, section_guardrails, section_security,
                    section_domains, section_punteggio, section_catalog, section_repository):
        section()
    print(f"PASS: {PASSES}  FAIL: {len(FAILS)}")
    for f in FAILS:
        print(" -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
