# Phishing di marchi italiani da Certificate Transparency

> Generato da `scripts/ct_phishing_it.py` (config `domains/ct_marchi.toml`): **non modificare a mano**.

**Fase di osservazione**: i candidati non sono in nessuna blocklist pubblicata. Servono a misurare i falsi positivi prima di promuovere la lista a `block-phishing-it`.

Giro del 2026-11-23: fonte crt.sh, soglia 60, finestra 7 giorni, scadenza 7 giorni.

## Statistiche del giro

| Voce | Valore |
|---|---|
| prefissi interrogati | 20 di 81 |
| errori della fonte | 20 |
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
| non risolvono (in questo giro) | 1 |
| durata (secondi) | 907 |
| candidati pubblicabili (sopra soglia e vivi) | 7 |
| voci nello stato | 39 |
| uscite per scadenza | 0 |

## Candidati sopra soglia

| Dominio | Marchio | Punteggio | Motivi | Primo avvistamento | Ultima risposta DNS |
|---|---|---|---|---|---|
| appioschicken.online | pagoPA / app IO | 70 | marchio pagoPA / app IO nel dominio; TLD .online; wildcard; certificato DV gratuito | 2026-10-12 | 2026-11-23 |
| satispaybenefits.info | Satispay | 70 | marchio Satispay nel dominio; TLD .info; certificato recente; wildcard | 2026-10-14 | 2026-11-23 |
| appiospg88ios.vip | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .vip; wildcard | 2026-10-12 | 2026-11-23 |
| appiosu.site | pagoPA / app IO | 65 | marchio pagoPA / app IO nel dominio; TLD .site; wildcard | 2026-10-23 | 2026-11-23 |
| webank.online | Banco BPM / Webank | 65 | marchio Banco BPM / Webank nel dominio; TLD .online; certificato recente | 2026-10-16 | 2026-11-23 |
| buddybanks.xyz | UniCredit | 60 | marchio UniCredit nel dominio; TLD .xyz | 2026-10-19 | 2026-11-23 |
| unicreditbank.shop | UniCredit | 60 | marchio UniCredit nel dominio; TLD .shop | 2026-10-16 | 2026-11-23 |

Voci sotto soglia nello stato: 32 (non elencate: servono solo a misurare la soglia).

## Errori della fonte

- areaclienti%: HTTP Error 502: Bad Gateway
- verifica%: HTTP Error 502: Bad Gateway
- poste%: HTTP Error 502: Bad Gateway
- bancoposta%: HTTP Error 502: Bad Gateway
- posteid%: HTTP Error 502: Bad Gateway
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
- bancamediolanum%: HTTP Error 502: Bad Gateway
- ing-%: HTTP Error 502: Bad Gateway
- ingitalia%: HTTP Error 502: Bad Gateway
- ingdirect%: HTTP Error 502: Bad Gateway
- creditagricole%: HTTP Error 502: Bad Gateway
