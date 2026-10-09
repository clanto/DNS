#!/usr/bin/env python3
"""Test offline di scripts/ct_phishing_it.py con dati sintetici (nessuna rete, nessun dato reale di persone).

Uso: python tests/test_ct_phishing_it.py
"""
import io
import json
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ct_phishing_it as CT  # noqa: E402

FAILS: list[str] = []
PASSES = 0
OGGI = date(2026, 10, 9)


def check(cond, msg):
    global PASSES
    if cond:
        PASSES += 1
    else:
        FAILS.append(msg)


def cert(nomi, giorno="2026-10-08", emittente="C=US, O=Let's Encrypt, CN=E7", cid=None):
    return {"id": cid if cid is not None else abs(hash((nomi, giorno))), "issuer_name": emittente,
            "name_value": nomi, "not_before": f"{giorno}T10:00:00"}


CFG = CT.carica_config()
CTX = CT.Contesto(
    piattaforme={"pages.dev", "github.io", "workers.dev"},
    bloccati={"gia-bloccato-poste.top", "world"},
    allow={"servizio-poste-partner.it"},
    protetti={"login.esempio-protetto.it"},
    escludi={"poste-escluso.com"},
    propri={"clanto.cloud"},
)


def valuta(nome, **k):
    return CT.valuta(nome, cert(nome, **k), CFG, CTX, OGGI)


def section_config():
    check(CFG.get("osservazione") is True, "la fase di osservazione deve essere attiva")
    check(len(CFG["marchi"]) >= 30, "troppo pochi marchi in ct_marchi.toml")
    for m in CFG["marchi"]:
        for u in m["ufficiali"]:
            check(CT.DOMAIN_RE.match(u), f"{m['nome']}: dominio ufficiale non valido {u}")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.toml"
        p.write_text('[[marchi]]\nnome = "x"\nparole = ["xyz"]\nufficiali = ["x.it"]\ncerca = ["x%y"]\n',
                     encoding="utf-8")
        try:
            CT.carica_config(p)
            FAILS.append("prefisso con caratteri jolly accettato")
        except ValueError:
            check(True, "")


def section_corrispondenze():
    v, e = valuta("postepay-sblocco.top")
    check(v and v.dominio == "postepay-sblocco.top" and v.punteggio >= CFG["soglia"],
          f"marchio con esca e TLD a rischio non candidato: {e} {v}")
    check(v and any("esca" in m for m in v.motivi) and any("TLD" in m for m in v.motivi), f"motivi incompleti {v}")
    # typo e omoglifi
    for nome in ("p0stepay-verifica.com", "intesasanpoalo-accesso.com", "unicred1t-conferma.com",
                 "xn--pstepay-verifica-mkn.com"):  # Cirillico 'о' al posto di 'o'
        v, e = valuta(nome)
        check(v is not None and any("variante" in m for m in v.motivi), f"variante non riconosciuta: {nome} ({e})")
        check(v is not None and v.punteggio >= CFG["soglia"], f"variante sotto soglia: {nome} {v}")
    v, _ = valuta("vodafonne-italia-rimborso.com")
    check(v is not None and v.punteggio >= CFG["soglia"], f"typo esplicito di marchio globale: {v}")
    # marchi corti: solo come token o uniti a una parola esca
    check(valuta("inps-rimborso.com")[0] is not None, "inps-rimborso.com non riconosciuto")
    check(valuta("inpsrimborso.com")[0] is not None, "inpsrimborso.com non riconosciuto")
    check(valuta("inpsychology.com")[1] == "nessun marchio", "inpsychology.com riconosciuto come INPS")
    check(valuta("timetable.com")[1] == "nessun marchio", "timetable.com riconosciuto come TIM")
    check(valuta("vintageposters.com")[1] == "nessun marchio", "poster riconosciuto come Poste")
    for legit in ("finecoding.top", "arubanetworks-lab.com", "unipolar-design.shop", "iliadathletics.com"):
        check(valuta(legit)[1] == "nessun marchio", f"parola comune riconosciuta come marchio: {legit}")
    v, _ = valuta("p0ste-verifica.com")
    check(v is not None and any("variante" in m for m in v.motivi), f"omoglifo su parola token: {v}")
    check(valuta("postesicurezza.top")[0] is not None, "marchio token unito a parola esca non riconosciuto")
    # marchio globale senza contesto italiano
    check(valuta("vodafone-shop-berlin.de")[1] == "marchio globale senza segnale italiano",
          "marchio globale senza segnale italiano accettato")
    check(valuta("iliad-mobile-italia.com")[0] is not None, "marchio globale con segnale italiano scartato")
    # nome nel sottodominio di un dominio qualsiasi: si pubblica il nome esatto, sotto soglia senza altri segnali
    v, _ = valuta("inps.studio-esempio.com")
    check(v is not None and v.dominio == "inps.studio-esempio.com" and v.punteggio < CFG["soglia"],
          f"marchio nel sottodominio: {v}")
    # certificato OV/EV: titolare verificato
    nomi = "Esempio Banca S.p.A.\nunicredit-servizi.com"
    v, _ = CT.valuta("unicredit-servizi.com", cert(nomi, emittente="CN=Example OV CA"), CFG, CTX, OGGI)
    check(v is not None and v.punteggio < CFG["soglia"], f"certificato OV non penalizzato: {v}")
    check(valuta("not a domain")[1] == "non è un nome a dominio", "testo libero trattato come dominio")


def section_esclusioni():
    for nome in ("poste.it", "areaclienti.poste.it", "www.intesasanpaolo.com", "x.inps.it", "agenziaentrate.gov.it"):
        check(valuta(nome)[1] == "dominio ufficiale", f"dominio ufficiale segnalato: {nome}")
    # piattaforme PSL: mai il dominio della piattaforma, solo il sottodominio esatto
    v, _ = valuta("postepay-verifica.pages.dev")
    check(v is not None and v.dominio == "postepay-verifica.pages.dev", f"piattaforma: voce errata {v}")
    v, _ = valuta("a.postepay-verifica.pages.dev")
    check(v is not None and v.dominio == "postepay-verifica.pages.dev", f"piattaforma: registrabile errato {v}")
    v, _ = valuta("inps-rimborso.esempio.workers.dev")
    check(v is not None and v.dominio == "inps-rimborso.esempio.workers.dev", f"piattaforma, sottodominio: {v}")
    check(CT.registrabile("x.y.github.io", CTX.piattaforme, set()) == "y.github.io", "registrabile su piattaforma")
    check(CT.registrabile("a.b.co.uk", set(), {"co.uk"}) == "b.co.uk", "registrabile con suffisso a due livelli")
    check(valuta("gia-bloccato-poste.top")[1] == "già nelle nostre liste", "dominio già bloccato non scartato")
    check(valuta("poste-premio.world")[1] == "già nelle nostre liste", "TLD già bloccato non scartato")
    check(valuta("poste-escluso.com")[1] == "esclusione di cura", "esclusione di cura ignorata")
    check(valuta("servizio-poste-partner.it")[1] == "allowlist o servizio protetto", "allowlist ignorata")
    check(valuta("inps-login.clanto.cloud")[1] == "dominio ufficiale", "dominio proprio segnalato")


def section_scadenza():
    stato = {}
    v1 = CT.Valutazione("postepay-sblocco.top", "postepay-sblocco.top", "Poste", 80, ["x"])
    v2 = CT.Valutazione("inps-rimborso.top", "inps-rimborso.top", "INPS", 75, ["y"])
    stato, usciti = CT.aggiorna_stato(stato, [v1, v2], {"postepay-sblocco.top": True}, date(2026, 10, 1), 7)
    check(stato["postepay-sblocco.top"]["primo"] == "2026-10-01" and stato["postepay-sblocco.top"]["ultimo_vivo"],
          "primo avvistamento o ultima risposta DNS non registrati")
    check(CT.candidati(stato, 60, False) == ["postepay-sblocco.top"], "candidato non vivo pubblicato")
    check(CT.candidati(stato, 60, True) == ["postepay-sblocco.top", "inps-rimborso.top"] or
          set(CT.candidati(stato, 60, True)) == {"postepay-sblocco.top", "inps-rimborso.top"},
          "senza DNS tutti i candidati sopra soglia valgono vivi")
    stato, usciti = CT.aggiorna_stato(stato, [], {}, date(2026, 10, 5), 7)
    check(not usciti and len(stato) == 2, "voce uscita prima della scadenza")
    stato, usciti = CT.aggiorna_stato(stato, [], None, date(2026, 12, 1), 7)
    check(not usciti, "senza verifica di vita nessuna voce deve scadere")
    stato, usciti = CT.aggiorna_stato(stato, [], {}, date(2026, 10, 8), 7)
    check(set(usciti) == {"postepay-sblocco.top", "inps-rimborso.top"} and not stato,
          f"voci morte da 7 giorni non uscite: {usciti}")
    st = {}
    st, _ = CT.aggiorna_stato(st, [v1], {"postepay-sblocco.top": True}, date(2026, 10, 1), 7)
    st, u = CT.aggiorna_stato(st, [], {"postepay-sblocco.top": True}, date(2026, 10, 20), 7)
    check(not u and st["postepay-sblocco.top"]["ultimo_vivo"] == "2026-10-20", "voce viva fatta scadere")


def section_flusso():
    certs = [
        cert("postepay-sblocco.top\nwww.postepay-sblocco.top", cid=1),
        cert("*.inps-rimborso.cfd", cid=2),
        cert("poste.it", cid=3),
        cert("postepay-vecchio.top", giorno="2026-09-01", cid=4),     # fuori finestra
        cert("intesa-verifica.pages.dev", cid=5),
        cert("vintageposters.com", cid=6),
    ]
    vivi = {"postepay-sblocco.top": True, "inps-rimborso.cfd": False, "intesa-verifica.pages.dev": True}
    stato, lista, usciti, stat = CT.esegui(CFG, CTX, certs, {}, OGGI, lambda nomi: {n: vivi.get(n, False) for n in nomi},
                                           [], 3)
    check(lista == ["intesa-verifica.pages.dev", "postepay-sblocco.top"], f"candidati inattesi: {lista}")
    check("inps-rimborso.cfd" in stato and stato["inps-rimborso.cfd"]["ultimo_vivo"] is None,
          "candidato non vivo non tracciato nello stato")
    check("postepay-vecchio.top" not in stato, "certificato fuori finestra considerato")
    check(stat["scartati: dominio ufficiale"] == 1 and stat["certificati nella finestra"] == 5, f"statistiche {stat}")
    report = CT.scrivi_report(stato, CFG, stat, lista, usciti, OGGI, False, ["errore | [x](http://y)"])
    check("Fase di osservazione" in report and "postepay-sblocco.top" in report, "report incompleto")
    check("[x](http://y)" not in report, "errore della fonte non sanificato nel report")

    # esecuzione completa da file, in una cartella temporanea: niente rete, niente scrittura in dist/
    with tempfile.TemporaryDirectory() as td:
        dati = Path(td) / "certs.json"
        dati.write_text(json.dumps(certs), encoding="utf-8")
        old = sys.argv
        sys.argv = ["x", "--dati", str(dati), "--senza-dns", "--oggi", "2026-10-09", "--uscita", td]
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = CT.main()
        finally:
            sys.argv = old
        righe = (Path(td) / CT.CANDIDATI_PATH.name).read_text(encoding="utf-8").splitlines()
        check(rc == 0 and righe[0].startswith("#") and "IN OSSERVAZIONE" in righe[0], "intestazione candidati")
        check("postepay-sblocco.top" in righe and "inps-rimborso.cfd" in righe, f"candidati da file: {righe}")
        check(json.loads((Path(td) / CT.STATO_PATH.name).read_text(encoding="utf-8")), "stato vuoto")


def section_fonte():
    chiamate, attese = [], []

    def finta(url, timeout):
        chiamate.append(url)
        if len(chiamate) == 1:
            raise OSError("502 Bad Gateway")
        return json.dumps([cert("postepay-sblocco.top", cid=7)]).encode()

    certs, errori = CT.interroga_crtsh(["postepay", "inps"], {"url": CFG["fonte"]["url"], "tentativi": 3,
                                                               "pausa_secondi": 15}, finta, attese.append)
    check(len(certs) == 1 and not errori, f"retry dopo errore non riuscito: {errori}")
    check(chiamate[0].startswith("https://crt.sh/?identity=postepay%25&match=LIKE"), f"URL crt.sh errato: {chiamate[0]}")
    check(attese == [30, 15], f"pausa e backoff errati: {attese}")

    def giu(url, timeout):
        raise OSError("giù")

    certs, errori = CT.interroga_crtsh(["a"], {"url": CFG["fonte"]["url"], "tentativi": 2}, giu, lambda s: None)
    check(not certs and len(errori) == 1, "errore definitivo non segnalato")
    tutti = [f"p{i}" for i in range(10)]
    giri = [set(CT.prefissi_del_giro(tutti, 4, date(2026, 10, g))) for g in (1, 2, 3)]
    check(all(len(g) == 4 for g in giri) and set().union(*giri) == set(tutti), f"rotazione dei prefissi {giri}")
    check(CT.prefissi_del_giro(tutti, 50, OGGI) == tutti, "con per_giro >= totale vanno interrogati tutti")
    vivi = CT.verifica_vita(["a.example", "b.example"], lambda n: n.startswith("a"))
    check(vivi == {"a.example": True, "b.example": False}, f"verifica di vita {vivi}")


def section_promozione():
    cfg = {"block": {}, "sources": []}
    CT.promuovi(cfg)
    check("phishing-it" not in cfg["block"] and not cfg["sources"], "in osservazione la categoria non va creata")
    orig = CT.CONFIG_PATH, CT.CANDIDATI_PATH
    with tempfile.TemporaryDirectory() as td:
        conf = Path(td) / "ct.toml"
        conf.write_text("osservazione = false\n", encoding="utf-8")
        cand = CT.ROOT / "dist" / "osservazione" / "_test-candidati.txt"
        try:
            CT.CONFIG_PATH = conf
            CT.CANDIDATI_PATH = cand
            with redirect_stderr(io.StringIO()):
                CT.promuovi(cfg)
            check(not cfg["sources"], "promozione senza file dei candidati")
            cand.parent.mkdir(parents=True, exist_ok=True)
            cand.write_text("postepay-sblocco.top\n", encoding="utf-8")
            CT.promuovi(cfg)
            CT.promuovi(cfg)
            check("phishing-it" in cfg["block"] and len(cfg["sources"]) == 1, "promozione non applicata o duplicata")
            check(cfg["sources"][0]["path"] == "dist/osservazione/_test-candidati.txt", "percorso della fonte")
        finally:
            CT.CONFIG_PATH, CT.CANDIDATI_PATH = orig
            cand.unlink(missing_ok=True)
            if cand.parent.exists() and not any(cand.parent.iterdir()):
                cand.parent.rmdir()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    for section in (section_config, section_corrispondenze, section_esclusioni, section_scadenza, section_flusso,
                    section_fonte, section_promozione):
        section()
    print(f"PASS: {PASSES}  FAIL: {len(FAILS)}")
    for f in FAILS:
        print(" -", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
