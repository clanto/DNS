#!/usr/bin/env python3
"""Test offline di scripts/pivot_infra.py con dati sintetici (nessuna rete, nessun dato reale).

Domini .example e IP delle reti di documentazione (RFC 5737, RFC 3849), trattate come instradabili solo qui.
Uso: python tests/test_pivot.py
"""
import ipaddress
import struct
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_domains as BD  # noqa: E402
import build_ip as B  # noqa: E402
import pivot_infra as P  # noqa: E402

FAILS: list[str] = []
PASSES = 0
TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
P.routable = lambda ip: ip.version in (4, 6) and any(ip in n for n in TEST_NETS)  # reti di documentazione


def check(cond, msg):
    global PASSES
    if cond:
        PASSES += 1
    else:
        FAILS.append(msg)


def ip(x):
    return ipaddress.ip_address(x)


def cfg(**over):
    c = dict(P.DEFAULTS)
    c.update({"sinkhole_ns": ["sinkhole", "microsoftinternetsafety.net"], "sinkhole_ptr": ["sinkhole", "blackhole"],
              "parking_ns": ["park", "bodis.com"], "shared_ptr": ["webhosting"], "shared_hosting_as": ["SHAREDHOST"],
              "sinkhole_nets": [ipaddress.ip_network("192.0.2.128/25")]})
    c.update(over)
    return c


# --- costruzione di risposte DNS sintetiche --------------------------------------------------------------

def rr(owner_ptr: int, rtype: int, rdata: bytes) -> bytes:
    return struct.pack(">HHHIH", 0xC000 | owner_ptr, rtype, 1, 300, len(rdata)) + rdata


def response(qid, name, qtype, answers=b"", n_an=0, authority=b"", n_ns=0, rcode=0):
    head = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, n_an, n_ns, 0)
    return head + P.encode_name(name) + struct.pack(">HH", qtype, 1) + answers + authority


def section_dns():
    q = P.build_query(0x1234, "www.evil.example", 1)
    check(q[:2] == b"\x12\x34" and q.endswith(b"\x03www\x04evil\x07example\x00\x00\x01\x00\x01"), "build_query")
    # www.evil.example CNAME tds.evil2.example (compresso), tds A 203.0.113.10
    cname_rdata = b"\x03tds\x05evil2" + b"\xc0" + bytes([12 + 1 + 3 + 1 + 4])  # punta a "example"
    data = response(7, "www.evil.example", 1,
                    rr(12, 5, cname_rdata) + rr(12, 1, bytes([203, 0, 113, 10])), 2)
    r = P.parse_response(data, 7, "www.evil.example", 1)
    check(r.rcode == "NOERROR" and r.answers[0] == ("www.evil.example", 5, "tds.evil2.example")
          and r.answers[1][2] == ip("203.0.113.10"), f"parse_response A/CNAME: {r}")
    # SOA in authority (NODATA su NS di un sottodominio): conta il proprietario
    soa = response(8, "a.evil.example", 2, authority=struct.pack(">HHHIH", 0xC000 | 14, 6, 1, 60, 2) + b"\xc0\x0e",
                   n_ns=1)
    r = P.parse_response(soa, 8, "a.evil.example", 2)
    check(r.authority and r.authority[0][0] == "evil.example" and r.authority[0][1] == 6, f"SOA in authority: {r}")
    nx = response(9, "dead.example", 1, rcode=3)
    check(P.parse_response(nx, 9).rcode == "NXDOMAIN", "rcode NXDOMAIN")
    aaaa = response(10, "v6.example", 28, rr(12, 28, ip("2001:db8::5").packed), 1)
    check(P.parse_response(aaaa, 10).answers[0][2] == ip("2001:db8::5"), "AAAA")
    for bad, why in ((data, "id"), (data[:20], "troncata"), (b"\x00" * 5, "corta")):
        try:
            P.parse_response(bad, 99 if why == "id" else None)
            FAILS.append(f"parse_response accetta una risposta non valida ({why})")
        except ValueError:
            check(True, "")
    try:
        P.parse_response(data, 7, "altro.example", 1)
        FAILS.append("parse_response accetta una domanda diversa (spoofing)")
    except ValueError:
        check(True, "")
    loop = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    try:
        P.parse_response(loop)
        FAILS.append("puntatori ciclici non rilevati")
    except ValueError:
        check(True, "")
    try:
        P.encode_name("a" * 64 + ".example")
        FAILS.append("etichetta oltre 63 caratteri accettata")
    except ValueError:
        check(True, "")


def section_resolver():
    calls = []

    def transport(packet):
        calls.append(packet)
        qid = struct.unpack(">H", packet[:2])[0]
        return response(qid, "ok.example", 1, rr(12, 1, bytes([203, 0, 113, 1])), 1)

    res = P.Resolver("192.0.2.53", qps=1000, max_queries=3, timeout=1, deadline=float("inf"), transport=transport)
    check(res.query("ok.example", "A").answers[0][2] == ip("203.0.113.1"), "resolver: risposta")
    res.query("ok.example", "A")
    check(len(calls) == 1, "resolver: la cache non evita la seconda query")
    try:
        res.query("altro.example", "A")  # domanda diversa: due tentativi, entrambi scartati
        res.query("terzo.example", "A")
        FAILS.append("resolver: limite di query non rispettato")
    except P.BudgetExceeded:
        check(res.sent == 3 and res.failed == 1, f"resolver: conteggi sent={res.sent} failed={res.failed}")

    def down(_packet):
        raise OSError("timeout")

    res = P.Resolver("192.0.2.53", qps=1000, max_queries=10, timeout=1, deadline=float("inf"), transport=down)
    check(res.query("x.example", "A") is None and res.failed == 1 and res.sent == 2, "resolver: errore di rete")
    res = P.Resolver("192.0.2.53", qps=1000, max_queries=10, timeout=1, deadline=0, transport=down)
    try:
        res.query("x.example", "A")
        FAILS.append("resolver: limite di tempo non rispettato")
    except P.BudgetExceeded:
        check(True, "")


class FakeResolver:
    """Risposte da tabella: (nome, tipo) → Response."""

    def __init__(self, table):
        self.table = table

    def query(self, name, qtype):
        return self.table.get((name, qtype), P.Response("NOERROR", [], []))


def a(name, *addrs, cname=None):
    recs = []
    if cname:
        recs.append((name, 5, cname))
    recs += [(cname or name, 28 if ":" in x else 1, ip(x)) for x in addrs]
    return P.Response("NOERROR", recs, [])


def section_observe():
    table = {
        ("www.evil.example", "A"): a("www.evil.example", "203.0.113.10", cname="tds.evil2.example"),
        ("www.evil.example", "NS"): P.Response("NOERROR", [], [("evil.example", 6, "ns1.evil.example")]),
        ("evil.example", "NS"): P.Response("NOERROR", [("evil.example", 2, "ns1.badns.example")], []),
        ("dead.example", "A"): P.Response("NXDOMAIN", [], []),
        ("err.example", "A"): None,
    }
    fr = FakeResolver(table)
    o = P.observe(fr, "www.evil.example")
    check(o.status == "ok" and o.ips == {ip("203.0.113.10")} and o.cnames == ["tds.evil2.example"]
          and o.zone == "evil.example" and o.ns == {"ns1.badns.example"}, f"observe: {o}")
    check(P.observe(fr, "dead.example").status == "morto", "observe: NXDOMAIN")
    check(P.observe(fr, "err.example").status == "errore", "observe: nessuna risposta")
    check(P.observe(fr, "vuoto.example").status == "morto", "observe: NOERROR senza IP")
    check(P.registrable_guess("a.b.evil.co.uk") == "evil.co.uk" and P.registrable_guess("x.evil.example") == "evil.example",
          "registrable_guess")
    check(P.matches("ns1.sinkhole.example", ["sinkhole"]) and P.matches("ns2.bodis.com", ["bodis.com"])
          and not P.matches("ns1.notbodis.com", ["bodis.com"]), "matches: parole e suffissi")


def section_seeds():
    per_source = {
        "a": {"multi.example", "solo-a.example", "x1.zona.example", "x2.zona.example", "x3.zona.example"},
        "b": {"multi.example", "sub.parent.example", "allow.example"},
        "c": {"parent.example"},
    }
    seeds = P.select_seeds(per_source, lambda n: n == "allow.example", 10, 2, "2026-W41")
    check(list(seeds)[0] in ("multi.example", "sub.parent.example") and seeds["multi.example"] == {"a", "b"},
          f"semi: le voci in più fonti vanno prima {list(seeds)[:3]}")
    check(seeds["sub.parent.example"] == {"b", "c"}, "semi: fonte del dominio padre non conteggiata")
    check("allow.example" not in seeds, "semi: allowlist non esclusa")
    check(sum(1 for n in seeds if n.endswith(".zona.example")) == 2, "semi: limite per zona non applicato")
    check(len(P.select_seeds(per_source, lambda n: False, 2, 2, "s")) == 2, "semi: max_seeds non applicato")
    s1 = list(P.select_seeds(per_source, lambda n: False, 10, 5, "2026-W41"))
    check(s1 == list(P.select_seeds(per_source, lambda n: False, 10, 5, "2026-W41")), "semi: ordine non deterministico")


def obs(name, *addrs, zone="", ns=(), cnames=(), status="ok"):
    o = P.Obs(name, status, {ip(x) for x in addrs}, list(cnames), zone or P.registrable_guess(name), set(ns))
    return o


def filters(**over):
    empty = B.NetIndex([])
    base = dict(shared=B.NetIndex([ipaddress.ip_network("198.51.100.0/25")]), keep=empty, protected=empty,
                allow=B.NetIndex([ipaddress.ip_network("203.0.113.99/32")]),
                sinkhole=B.NetIndex([ipaddress.ip_network("192.0.2.128/25")]),
                covered=B.NetIndex([ipaddress.ip_network("203.0.113.77/32")]),
                asn_of=lambda a: (64500, "SHAREDHOST-AS") if str(a) == "203.0.113.66" else (64501, "EXAMPLE-VPS"),
                ptr_of=lambda a: {"203.0.113.55": "host.webhosting.example",
                                  "203.0.113.44": "blackhole.example"}.get(str(a), ""),
                shared_asn=set(), shared_as_keywords=[])
    base.update(over)
    return P.Filters(**base)


def section_ips():
    c = cfg(min_domains=3, min_confirmed=1, max_domains=5)
    seeds, o = {}, {}

    def put(ipaddr, names, confirmed=1, **kw):
        for i, n in enumerate(names):
            seeds[n] = {"a", "b"} if i < confirmed else {"a"}
            o[n] = obs(n, ipaddr, **kw)

    put("203.0.113.10", ["d1.example", "d2.example", "d3.example", "www.d3.example"])  # dedicato: 3 domini
    put("198.51.100.5", ["s1.example", "s2.example", "s3.example"])                    # CDN condivisa
    put("2001:db8::10", ["v1.example", "v2.example", "v3.example"])                    # dedicato IPv6
    put("203.0.113.20", ["k1.example", "k2.example", "k3.example"], ns=["ns1.sinkhole.example"])
    put("192.0.2.200", ["n1.example", "n2.example", "n3.example"])                     # sinkhole_nets
    put("203.0.113.30", ["p1.example", "p2.example", "p3.example"], ns=["ns1.parkingcrew.example"])
    put("203.0.113.40", ["t1.example", "t2.example"])                                 # sotto soglia
    put("203.0.113.41", ["u1.example", "u2.example", "u3.example"], confirmed=0)      # nessuna conferma
    put("203.0.113.42", ["l1.example", "l2.example", "l3.example"])                    # anche un sito legittimo
    put("203.0.113.43", [f"h{i}.example" for i in range(8)])                          # densità oltre soglia
    put("203.0.113.66", ["as1.example", "as2.example", "as3.example"])                 # AS hosting condiviso
    put("203.0.113.55", ["w1.example", "w2.example", "w3.example"])                    # PTR hosting condiviso
    put("203.0.113.44", ["b1.example", "b2.example", "b3.example"])                    # PTR blackhole
    put("203.0.113.77", ["c1.example", "c2.example", "c3.example"])                    # già nei feed
    put("203.0.113.99", ["al1.example", "al2.example", "al3.example"])                 # ip/allowlist.txt
    put("203.0.113.88", ["m1.example", "m2.example", "m3.example"], status="morto")
    sink = B.NetIndex(c["sinkhole_nets"])
    for x in o.values():
        P.classify(x, c, sink)
    check(o["k1.example"].status == "sinkhole" and o["n1.example"].status == "sinkhole", "sinkhole non riconosciuto")
    check(o["p1.example"].status == "parcheggio", "parcheggio non riconosciuto")
    accepted, rejected, review = P.evaluate_ips(seeds, o, {ip("203.0.113.42")}, filters(), c)
    got = {str(x.ip) for x in accepted}
    check(got == {"203.0.113.10", "2001:db8::10"}, f"IP accettati: {sorted(got)} scarti {dict(rejected)}")
    d = next(x for x in accepted if str(x.ip) == "203.0.113.10")
    check(d.domains == ["d1.example", "d2.example", "d3.example"] and d.confirmed == 1 and d.sources == ["a", "b"]
          and d.asn == 64501, f"prove dell'IP dedicato: {d}")
    expected = {"infrastruttura condivisa": 1, "sinkhole": 2, "parcheggio": 1, "sotto la soglia di domini": 1,
                "conferme insufficienti": 1, "ospita domini delle allowlist": 1, "AS di hosting condiviso": 1,
                "PTR di hosting condiviso": 1, "sinkhole (PTR)": 1, "già nei feed c2/threat": 1,
                "ip/allowlist.txt": 1, "densità oltre max_domains (da verificare)": 1}
    check(dict(rejected) == expected, f"scarti per motivo: {dict(rejected)}")
    check(review and review[0]["ip"] == "203.0.113.43" and review[0]["domini"] == 8, f"densità: {review}")
    # soglie configurabili
    acc2, _, _ = P.evaluate_ips(seeds, o, set(), filters(), cfg(min_domains=2, min_confirmed=1, max_domains=50))
    check("203.0.113.40" in {str(x.ip) for x in acc2} and "203.0.113.43" in {str(x.ip) for x in acc2},
          "soglie min_domains/max_domains non configurabili")
    acc3, _, _ = P.evaluate_ips(seeds, o, set(), filters(), cfg(min_domains=4, min_confirmed=1, max_domains=50))
    check("203.0.113.10" not in {str(x.ip) for x in acc3}, "stesso dominio registrato contato due volte")
    acc4, rej4, _ = P.evaluate_ips(seeds, o, set(), filters(), cfg(min_domains=3, max_ip_candidates=1, max_domains=50))
    check(len(acc4) == 1 and rej4["oltre max_ip_candidates (prossima esecuzione)"] >= 1, "max_ip_candidates")
    acc5, rej5, _ = P.evaluate_ips(seeds, o, set(), filters(keep=B.NetIndex([ipaddress.ip_network("203.0.113.10/32")])),
                                   c)
    check("203.0.113.10" not in {str(x.ip) for x in acc5} and rej5["resolver pubblico (keep)"] == 1, "keep")
    acc6, rej6, _ = P.evaluate_ips(seeds, o, {ip("203.0.113.42")}, filters(
        protected=B.NetIndex([ipaddress.ip_network("2001:db8::10/128")])), c)
    check(rej6["servizio protetto"] == 1 and len(acc6) == 1, "servizi protetti non esclusi")
    return accepted


def section_domains(accepted):
    c = cfg(min_domains=3)
    accepted_ips = {x.ip for x in accepted}
    o = {}
    for i in range(3):  # tre domini malevoli con nameserver su un IP dedicato malevolo e CNAME comune
        n = f"www.m{i}.example"
        o[n] = obs(n, "203.0.113.10", zone=f"m{i}.example", ns=["ns1.badns.example", "ns2.badns.example"],
                   cnames=["go.tds.example"])
    for i in range(3):  # nameserver condiviso con domini legittimi
        n = f"q{i}.example"
        o[n] = obs(n, "203.0.113.10", ns=["ns1.popular-dns.example"])
    for i in range(3):  # nameserver su IP non malevolo
        n = f"r{i}.example"
        o[n] = obs(n, "203.0.113.10", ns=["ns1.other-dns.example"])
    legit = {"legit.example": obs("legit.example", "203.0.113.200", ns=["ns9.popular-dns.example"])}
    hosts = {"ns1.badns.example": {ip("203.0.113.10")}, "ns1.other-dns.example": {ip("203.0.113.150")}}

    def resolve_hosts(names):
        return set().union(*(hosts.get(h, set()) for h in names))

    found, rejected = P.evaluate_domains(o, legit, accepted_ips, resolve_hosts,
                                         lambda n: "già bloccato" if n == "known.example" else None, c)
    got = {(f.name, f.kind) for f in found}
    check(got == {("badns.example", "nameserver"), ("tds.example", "cname")}, f"domini candidati: {got} {dict(rejected)}")
    check(rejected["nameserver usato da domini legittimi"] == 1 and rejected["nameserver non su IP malevolo dedicato"] == 1,
          f"scarti domini: {dict(rejected)}")
    found2, rej2 = P.evaluate_domains(o, legit, accepted_ips, resolve_hosts,
                                      lambda n: "già bloccato" if n == "badns.example" else None, c)
    check("badns.example" not in {f.name for f in found2} and rej2["nameserver: già bloccato"] == 1, "known")
    found3, _ = P.evaluate_domains(o, legit, set(), resolve_hosts, lambda n: None, c)
    check(not found3, "candidati senza IP malevoli dedicati")
    return found


def section_entries(accepted, found):
    today = date(2026, 10, 9)
    tmp = ROOT / "tests" / "_pivot_tmp.txt"
    try:
        lines = [P.ip_line(x, today, 30) for x in accepted]
        check(all("| pivot-20261009 | 2026-11-08" in ln for ln in lines), f"riga IP: {lines[:1]}")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        errs = []
        ents, _ = B.load_annotated(tmp, min_prefix=None, today=today, errors=errs)
        check(not errs and len(ents) == len(accepted), f"righe IP non valide per build_ip: {errs}")
        dlines = [P.domain_line(x, today, 30) for x in found]
        tmp.write_text("\n".join(dlines) + "\n", encoding="utf-8", newline="\n")
        errs = []
        names, _ = BD.load(tmp, tld=False, today=today, errors=errs)
        check(not errs and set(names) == {x.name for x in found}, f"righe domini non valide per build_domains: {errs}")
        # PII nel motivo: si ripiega sul motivo senza esempi
        pii = P.IpCandidate(ip("203.0.113.10"), ["a123456789.example"] * 3, 1, ["a"], 64501, "X", "")
        check("a123456789" not in P.ip_line(pii, today, 30), "dato simile a un telefono nel motivo")

        tmp.write_text("\n".join([
            "# intestazione",
            "203.0.113.1 | 2026-08-01 | pivot vecchio | pivot-20260801 | 2026-08-31",
            "203.0.113.2 | 2026-08-01 | manuale scaduto | TCK-1 | 2026-08-31",
            "203.0.113.10 | 2026-10-01 | già presente | pivot-20261001 | 2026-10-31",
        ]) + "\n", encoding="utf-8", newline="\n")
        added, pruned = P.apply_entries(tmp, [], lines, today)
        text = tmp.read_text(encoding="utf-8")
        check(pruned == 1 and "203.0.113.1 |" not in text, "voce derivata scaduta non tolta")
        check("203.0.113.2 |" in text, "voce manuale scaduta tolta (va lasciata a chi l'ha scritta)")
        check(added == len(lines) - 1 and text.count("203.0.113.10 |") == 1, "voce già presente duplicata")
        added, pruned = P.apply_entries(tmp, [], lines, today)
        check(added == 0 and pruned == 0, "apply_entries non idempotente")
    finally:
        tmp.unlink(missing_ok=True)


def section_config():
    c = P.load_config()
    check(c["min_domains"] >= 2 and 1 <= c["expiry_days"] <= 90, "ip/pivot.toml: soglie")
    check(c["max_seconds"] <= 600 and c["max_queries"] <= 20000 and c["qps"] <= 100, "ip/pivot.toml: limiti di carico")
    check(all(isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for n in c["sinkhole_nets"]), "sinkhole_nets")
    check(all(s["url"].startswith("https://") for s in c["shared_sources"] if "url" in s), "shared_sources HTTPS")
    wf = (ROOT / ".github/workflows/pivot.yml").read_text(encoding="utf-8")
    check("timeout-minutes: 15" in wf and "${{ github.event" not in wf, "pivot.yml: timeout o interpolazione insicura")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    section_dns()
    section_resolver()
    section_observe()
    section_seeds()
    accepted = section_ips()
    found = section_domains(accepted)
    section_entries(accepted, found)
    section_config()
    print(f"PASS: {PASSES}  FAIL: {len(FAILS)}")
    for f in FAILS:
        print(" -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
