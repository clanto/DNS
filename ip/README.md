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

## Infrastrutture condivise

Le fonti DoH e VPN contengono anche IP di CDN e piattaforme di hosting condivise: un resolver DoH ospitato su AWS Global Accelerator, Cloudflare o Vercel ha lo stesso IP di migliaia di siti legittimi. Nelle categorie con `exclude_shared = true` (`doh`, `vpn`) questi IP non vengono mai bloccati:

- intervalli ufficiali scaricati a ogni build: Cloudflare, AWS CloudFront e Global Accelerator, Fastly (`[[shared_sources]]` in `sources.toml`); non vengono pubblicati;
- reti che non pubblicano i propri intervalli, inserite a mano in `ip/condivisi.txt` (es. Vercel).

Se gli intervalli ufficiali non sono raggiungibili il build fallisce e restano online i feed precedenti. I resolver con IP dedicato (1.1.1.1, 8.8.8.8, 9.9.9.9…) restano bloccati; i loro domini sono comunque bloccati da AdGuard con `block-doh`.

Se un sito si rompe per colpa di un feed: trovare l'IP bloccato nel log del firewall e, se è una rete condivisa, aggiungerla a `ip/condivisi.txt`; se è un singolo falso positivo, a `ip/allowlist.txt`.

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
- **Aziende**: `all-v4.txt` / `all-v6.txt` (doh, tor, threat, c2).
- **Scuole**: `all-scuole-v4.txt` / `all-scuole-v6.txt` (come `all`, più vpn).
- Gli aggregati si configurano in `[aggregates]` di `sources.toml`: aggiungere una categoria lì la porta su tutti i firewall che usano quel feed.
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
