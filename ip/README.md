# Feed IP: come funziona

I firewall puntano **solo** ai feed in `dist/ip/`. Gli URL non cambiano mai: aggiungere o togliere fonti qui si riflette su tutti i dispositivi al primo refresh, senza toccarli.

```
ip/sources.toml     fonti upstream e categorie
ip/custom/<cat>.txt voci manuali (una categoria per file)
ip/allowlist.txt    reti mai bloccate (vince su tutto)
ip/cache/           ultima versione valida di ogni fonte (generata)
dist/ip/            feed per i firewall (generati, non modificare)
```

Il build gira ogni 6 ore e a ogni modifica di questi file su `main`. Si può lanciare anche a mano: *Actions → Build feed IP → Run workflow*.

## Aggiungere un IP a mano

Si modifica `ip/custom/<categoria>.txt`, aggiungendo una riga:

```
203.0.113.10 | 2026-09-24 | bypass filtro porn, sito mirror | TCK-1234
198.51.100.0/24 | 2026-09-24 | C2 campagna phishing | TCK-1240 | 2026-12-31
```

Campi: `IP / CIDR / intervallo a-b | data inserimento | motivo | ticket o - | scadenza (opzionale)`.

- Le voci scadute vengono escluse in automatico.
- **Nel motivo non vanno dati personali** (nomi, email, telefoni: ISO 27701). La CI li rifiuta.
- Vengono rifiutate le reti private o riservate, quelle più ampie di /16 (IPv4) o /32 (IPv6) e i duplicati.
- Una nuova categoria va prima dichiarata in `sources.toml`.

## Sbloccare un falso positivo

Si aggiunge la rete a `ip/allowlist.txt`, con lo stesso formato. Viene tolta da **tutti** i feed; se è contenuta in un CIDR più ampio, il CIDR viene spezzato.

## Aggiungere una fonte

1. Verificare che la licenza sia compatibile con GPL-3.0 e con l'uso commerciale. Le fonti con clausole non commerciali (NC) sono escluse.
2. Aggiungere un blocco `[[sources]]` in `sources.toml`, con `id`, `category`, `url` (solo HTTPS) e `license`.

Formati riconosciuti:
- IP o CIDR per riga
- `IP # commento`
- `CIDR ; commento`
- intervalli `a-b`
- file hosts
- JSON per riga con chiave `cidr`

## Protezioni automatiche

- **Fonte irraggiungibile, vuota o calata oltre il 50%**: si usa la cache e il job mostra un warning.
- **Feed che varia oltre il 25%**: al posto del commit su `main` viene aperta una PR da approvare.
- **Righe manuali non valide**: vengono saltate, i feed escono comunque e il job risulta fallito, così arriva la notifica.

## Configurazione firewall

URL base: `https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/`

Feed consigliati:
- `all-v4.txt` / `all-v6.txt`: tutto tranne VPN e bogon.
- In aggiunta `vpn-v4.txt` solo dove serve, per esempio nelle scuole.
- `inbound-v4.txt` sulle regole **WAN in ingresso**: scanner e brute force verso i servizi esposti (~90k voci).
- `bogon-v4/v6.txt` **solo in ingresso sulla WAN**: contiene anche le reti LAN private. Su pfSense e OPNsense conviene l'opzione nativa *Block bogon networks*.
- Blocco per paese: usare il GeoIP nativo dei firewall. I dati RIR non sono ridistribuibili.

| Firewall | Dove |
|---|---|
| OPNsense | Firewall → Aliases → tipo *URL Table (IPs)*, refresh 1 giorno |
| pfSense | Firewall → Aliases → *URL Table (IPs)*, oppure pfBlockerNG → IPv4/IPv6 |
| FortiGate | Security Fabric → External Connectors → Threat Feeds → *IP Address* |
| SonicWall | Oggetti indirizzo dinamici esterni: il percorso di menu dipende dalla versione di SonicOS |

I limiti di voci per feed di FortiGate e SonicWall dipendono da modello e firmware e vanno verificati sui dispositivi. Si possono impostare in `max_entries` (`sources.toml`) per ricevere un avviso.
