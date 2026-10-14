# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-10-14: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 30 di 81 |
| errori della fonte | 3 |
| certificati letti | 33902 |
| certificati nella finestra | 46 |
| nomi distinti analizzati | 76 |
| scartati: nessun marchio | 30 |
| scartati: dominio ufficiale | 1 |
| scartati: già nelle nostre liste | 0 |
| scartati: piattaforma PSL | 0 |
| scartati: allowlist o servizio protetto | 0 |
| scartati: esclusione di cura | 0 |
| scartati: marchio globale senza segnale italiano | 3 |
| scartati: sotto soglia | 39 |
| scartati: non è un nome a dominio | 0 |
| non risolvono (in questo giro) | 2 |
| durata (secondi) | 1814 |
| candidati pubblicabili (sopra soglia e vivi) | 5 |
| voci nello stato | 23 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| appioschicken.online | pagoPA / app IO | 70 | marchio pagoPA / app IO nel dominio; TLD .online; wildcard; certificato DV gratuito | 2026-10-12 | 2026-10-14 |
| satispaybenefits.info | Satispay | 70 | marchio Satispay nel dominio; TLD .info; certificato recente; wildcard | 2026-10-14 | 2026-10-14 |
| agenziaentrate.link | Agenzia delle Entrate / Riscossione | 65 | marchio Agenzia delle Entrate / Riscossione nel dominio; TLD .link; certificato recente | 2026-10-12 | 2026-10-14 |
| appiospg88ios.vip | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .vip; wildcard | 2026-10-12 | 2026-10-14 |
| arubapec.store | Aruba | 60 | marchio Aruba nel dominio; TLD .store | 2026-10-12 | 2026-10-14 |

Voci sotto soglia nello stato: 18 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- mediolanum%: HTTP Error 502: Bad Gateway
- bancamediolanum%: HTTP Error 502: Bad Gateway
- ing-%: HTTP Error 502: Bad Gateway
