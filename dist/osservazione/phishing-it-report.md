# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-10-25: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 30 di 81 |
| errori della fonte | 1 |
| certificati letti | 20233 |
| certificati nella finestra | 0 |
| nomi distinti analizzati | 0 |
| scartati: nessun marchio | 0 |
| scartati: dominio ufficiale | 0 |
| scartati: già nelle nostre liste | 0 |
| scartati: piattaforma PSL | 0 |
| scartati: allowlist o servizio protetto | 0 |
| scartati: esclusione di cura | 0 |
| scartati: marchio globale senza segnale italiano | 0 |
| scartati: sotto soglia | 0 |
| scartati: non è un nome a dominio | 0 |
| non risolvono (in questo giro) | 3 |
| durata (secondi) | 2800 |
| candidati pubblicabili (sopra soglia e vivi) | 9 |
| voci nello stato | 40 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| appioschicken.online | pagoPA / app IO | 70 | marchio pagoPA / app IO nel dominio; TLD .online; wildcard; certificato DV gratuito | 2026-10-12 | 2026-10-25 |
| satispaybenefits.info | Satispay | 70 | marchio Satispay nel dominio; TLD .info; certificato recente; wildcard | 2026-10-14 | 2026-10-25 |
| agenziaentrate.link | Agenzia delle Entrate / Riscossione | 65 | marchio Agenzia delle Entrate / Riscossione nel dominio; TLD .link; certificato recente | 2026-10-12 | 2026-10-25 |
| appiospg88ios.vip | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .vip; wildcard | 2026-10-12 | 2026-10-25 |
| appiosu.site | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .site; wildcard | 2026-10-23 | 2026-10-25 |
| webank.online | Banco BPM / Webank | 65 | marchio Banco BPM / Webank nel dominio; TLD .online; certificato recente | 2026-10-16 | 2026-10-25 |
| arubapec.store | Aruba | 60 | marchio Aruba nel dominio; TLD .store | 2026-10-12 | 2026-10-25 |
| buddybanks.xyz | UniCredit | 60 | marchio UniCredit nel dominio; TLD .xyz | 2026-10-19 | 2026-10-25 |
| unicreditbank.shop | UniCredit | 60 | marchio UniCredit nel dominio; TLD .shop | 2026-10-16 | 2026-10-25 |

Voci sotto soglia nello stato: 30 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- budget di tempo esaurito: saltati 10 prefissi
