# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-10-12: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 30 di 81 |
| errori della fonte | 8 |
| certificati letti | 13444 |
| certificati nella finestra | 49 |
| nomi distinti analizzati | 55 |
| scartati: nessun marchio | 14 |
| scartati: dominio ufficiale | 1 |
| scartati: già nelle nostre liste | 0 |
| scartati: piattaforma PSL | 0 |
| scartati: allowlist o servizio protetto | 0 |
| scartati: esclusione di cura | 0 |
| scartati: marchio globale senza segnale italiano | 0 |
| scartati: sotto soglia | 34 |
| scartati: non è un nome a dominio | 0 |
| non risolvono (in questo giro) | 1 |
| durata (secondi) | 2940 |
| candidati pubblicabili (sopra soglia e vivi) | 4 |
| voci nello stato | 18 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| appioschicken.online | pagoPA / app IO | 70 | marchio pagoPA / app IO nel dominio; TLD .online; wildcard; certificato DV gratuito | 2026-10-12 | 2026-10-12 |
| agenziaentrate.link | Agenzia delle Entrate / Riscossione | 65 | marchio Agenzia delle Entrate / Riscossione nel dominio; TLD .link; certificato recente | 2026-10-12 | 2026-10-12 |
| appiospg88ios.vip | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .vip; wildcard | 2026-10-12 | 2026-10-12 |
| arubapec.store | Aruba | 60 | marchio Aruba nel dominio; TLD .store | 2026-10-12 | 2026-10-12 |

Voci sotto soglia nello stato: 14 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- tim-%: HTTP Error 502: Bad Gateway
- mytim%: HTTP Error 502: Bad Gateway
- timpersonale%: HTTP Error 502: Bad Gateway
- telecomitalia%: HTTP Error 502: Bad Gateway
- vodafone%: HTTP Error 404: Not Found
- windtre%: HTTP Error 502: Bad Gateway
- wind3%: HTTP Error 502: Bad Gateway
- budget di tempo esaurito: saltati 13 prefissi
