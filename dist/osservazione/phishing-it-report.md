# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-10-15: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 30 di 81 |
| errori della fonte | 1 |
| certificati letti | 14835 |
| certificati nella finestra | 15 |
| nomi distinti analizzati | 18 |
| scartati: nessun marchio | 11 |
| scartati: dominio ufficiale | 0 |
| scartati: già nelle nostre liste | 1 |
| scartati: piattaforma PSL | 0 |
| scartati: allowlist o servizio protetto | 0 |
| scartati: esclusione di cura | 0 |
| scartati: marchio globale senza segnale italiano | 1 |
| scartati: sotto soglia | 4 |
| scartati: non è un nome a dominio | 1 |
| non risolvono (in questo giro) | 2 |
| durata (secondi) | 1635 |
| candidati pubblicabili (sopra soglia e vivi) | 5 |
| voci nello stato | 23 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| appioschicken.online | pagoPA / app IO | 70 | marchio pagoPA / app IO nel dominio; TLD .online; wildcard; certificato DV gratuito | 2026-10-12 | 2026-10-15 |
| satispaybenefits.info | Satispay | 70 | marchio Satispay nel dominio; TLD .info; certificato recente; wildcard | 2026-10-14 | 2026-10-15 |
| agenziaentrate.link | Agenzia delle Entrate / Riscossione | 65 | marchio Agenzia delle Entrate / Riscossione nel dominio; TLD .link; certificato recente | 2026-10-12 | 2026-10-15 |
| appiospg88ios.vip | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .vip; wildcard | 2026-10-12 | 2026-10-15 |
| arubapec.store | Aruba | 60 | marchio Aruba nel dominio; TLD .store | 2026-10-12 | 2026-10-15 |

Voci sotto soglia nello stato: 18 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- sda-%: The read operation timed out
