# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-10-11: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 30 di 81 |
| errori della fonte | 11 |
| certificati letti | 0 |
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
| non risolvono (in questo giro) | 0 |
| durata (secondi) | 2811 |
| candidati pubblicabili (sopra soglia e vivi) | 0 |
| voci nello stato | 0 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| — | | | | | |

Voci sotto soglia nello stato: 0 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- intesa%: HTTP Error 502: Bad Gateway
- isybank%: HTTP Error 502: Bad Gateway
- unicredit%: HTTP Error 502: Bad Gateway
- buddybank%: HTTP Error 502: Bad Gateway
- bper%: HTTP Error 502: Bad Gateway
- bancobpm%: HTTP Error 502: Bad Gateway
- bpm-%: HTTP Error 502: Bad Gateway
- webank%: HTTP Error 502: Bad Gateway
- fineco%: HTTP Error 502: Bad Gateway
- mediolanum%: HTTP Error 502: Bad Gateway
- budget di tempo esaurito: saltati 20 prefissi
