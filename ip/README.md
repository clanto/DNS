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
- CDN e hosting condivisi senza elenco completo, esclusi **per AS** (Akamai, GitHub Pages, Imperva, Bunny, Fastly, Cloudflare, front-end Google) con le reti di iptoasn.com (pubblico dominio); esclusi di proposito AWS, Azure, Google Cloud e Gcore, che ospitano VM dedicate;
- reti che non pubblicano i propri intervalli, inserite a mano in `ip/condivisi.txt` (es. Vercel, Apple, Firebase Hosting);
- eccezioni `keep`: resolver pubblici con IP dedicato dentro reti condivise (Google Public DNS, Cloudflare 1.1.1.1), che restano bloccati.

## Servizi protetti

Gli host di `domains/allowlist/protetti.txt` (Workspace, Gmail SMTP, Microsoft 365, iCloud/MDM, registri elettronici, SPID, pagoPA…) vengono risolti a ogni build: i loro IP sono esclusi da tutti i feed e dalle liste OPNsense, e ogni esclusione viene segnalata nel riepilogo del job come falso positivo evitato. Su AdGuard sono sbloccati da `allow-base`.

Se gli intervalli ufficiali non sono raggiungibili il build fallisce e restano online i feed precedenti. I resolver con IP dedicato (1.1.1.1, 8.8.8.8, 9.9.9.9…) restano bloccati; i loro domini sono comunque bloccati da AdGuard con `block-doh`.

Se un sito si rompe per colpa di un feed: trovare l'IP bloccato nel log del firewall e, se è una rete condivisa, aggiungerla a `ip/condivisi.txt`; se è un singolo falso positivo, a `ip/allowlist.txt`.

## IP e domini derivati dall'infrastruttura malevola (pivot)

Ogni mercoledì il workflow *Pivot infrastruttura malevola* (`scripts/pivot_infra.py`, configurazione in [`pivot.toml`](pivot.toml)) risolve un campione dei domini malevoli confermati (fonti di `block-malware` e `block-phishing`, più `domains/blocklist/malevoli.txt`; prima quelli presenti in più fonti) e apre una **PR da approvare**, mai un commit diretto:

- **IP dedicati** → `ip/custom/c2.txt`: proposti solo se ospitano almeno 3 domini registrati malevoli distinti (almeno uno in più fonti), nessun host delle allowlist o dei servizi protetti, non sono in infrastrutture condivise (stesso filtro dei feed, più bucket S3 e API Gateway), sinkhole (nameserver o PTR con *sinkhole*/*blackhole*, `microsoftinternetsafety.net`, reti in `sinkhole_nets`), parcheggi (nameserver *park*, Bodis, Above, Dan, Afternic, Uniregistry), AS o PTR di hosting web condiviso, `ip/allowlist.txt` o già nei feed. Oltre 50 domini nel campione l'IP finisce solo nel report da verificare a mano: densità tipica di parcheggi e hosting con siti compromessi.
- **Domini collegati** → `domains/blocklist/malware.txt`: nameserver su un IP del punto precedente e destinazioni CNAME comuni ad almeno 3 domini malevoli, mai usati dai domini delle allowlist.

Le voci hanno ticket `pivot-AAAAMMGG` e **scadenza a 30 giorni** (un IP dedicato può passare a un altro cliente del provider); quelle scadute vengono tolte alla PR successiva. Le voci derivate non diventano mai semi delle esecuzioni successive.

Limiti di carico: al massimo 1500 domini, 8000 query a 40 al secondo sul resolver del runner, 8 minuti di query, job sotto i 15 minuti. Le risoluzioni sono affidabili solo in CI: su una rete con AdGuard i domini malevoli risultano NXDOMAIN e lo script non propone nulla.

**Fonti esterne valutate e non usate** (passive DNS e reverse IP, verificate il 2026-10-09): HackerTarget (uso commerciale e ridistribuzione vietati), VirusTotal Public API (solo uso non commerciale), CIRCL Passive DNS (solo partner accreditati), mnemonic Passive DNS (query massive non consentite, termini di riuso non pubblicati). Per questo i domini nuovi derivano **solo da dati nostri** (nameserver e CNAME dei domini risolti): senza reverse IP non si vede quanti altri siti stanno su un IP, quindi la densità è stimata sul campione, con AS e PTR. Una fonte con termini compatibili potrà essere aggiunta con chiave solo come segreto GitHub.

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
- **Feed fermi**: ogni giorno il workflow *Controllo aggiornamento feed* fallisce (e notifica) se i feed IP non vengono aggiornati da più di 24 ore.
- **Domini morti**: ogni lunedì le voci delle blocklist manuali che risultano inesistenti (NXDOMAIN su Cloudflare e Google) vengono tolte con una PR da approvare.

## Configurazione firewall

URL base: `https://raw.githubusercontent.com/clanto/DNS/main/dist/`

### Quali liste

| Lista | URL | Scuole | Aziende | Dove si applica |
|---|---|---|---|---|
| Feed IP aggregato | `ip/all-scuole-v4.txt` / `-v6` | ✅ | — | LAN → WAN e WAN → LAN |
| Feed IP aggregato | `ip/all-v4.txt` / `-v6` | — | ✅ | LAN → WAN e WAN → LAN |
| Attacchi in ingresso | `ip/inbound-v4.txt` | ✅ | ✅ | solo WAN → LAN, se ci sono servizi esposti |
| Resolver DoH/DoT/DoQ (FQDN) | `opnsense/doh.txt` | ✅ | ✅ | LAN → WAN (solo OPNsense) |
| VPN e proxy (FQDN) | `opnsense/vpn.txt` | ✅ | — | LAN → WAN (solo OPNsense) |

- Gli aggregati si configurano in `[aggregates]` di `sources.toml`: aggiungere una categoria lì la porta su tutti i firewall che usano quel feed.
- Bogon: usare l'opzione nativa del firewall (*Block bogon networks* / *Block private networks* sulla WAN); in alternativa `ip/bogon-v4/v6.txt`, **solo in ingresso sulla WAN**.
- Blocco per paese: GeoIP nativo del firewall (i dati RIR non sono ridistribuibili).

### OPNsense

**Alias** (Firewall → Aliases), tutti di tipo **URL Table (IPs)**, refresh ogni 6-12 ore:

| Alias | Contenuto |
|---|---|
| `blk_all`, `blk_all6` | `all-scuole` (scuole) o `all` (aziende), v4 e v6 |
| `blk_inbound` | `inbound-v4` |
| `blk_doh_fqdn` | `opnsense/doh.txt` |
| `blk_vpn_fqdn` | `opnsense/vpn.txt` (scuole) |

Le liste `opnsense/*.txt` contengono **nomi di dominio**: OPNsense li risolve (record A e AAAA) a ogni aggiornamento dell'alias, quindi segue anche gli anycast. La documentazione cita solo IP, ma il comportamento è nel codice (`scripts/filter/lib/alias/base.py`, `resolve_dns()`), verificato nei rami stabili da 23.7 a 25.7.

> **Condizione indispensabile**: OPNsense risolve i nomi con il DNS del firewall stesso. Se il firewall usa AdGuard, AdGuard blocca proprio questi domini (risposta `0.0.0.0`) e l'alias resta di fatto vuoto, senza errori. Soluzioni: in AdGuard aggiungere l'IP del firewall come *client* con filtro disattivato, oppure impostare per il firewall un DNS non filtrato (System → Settings → General) o Unbound ricorsivo. Verifica: Firewall → Diagnostics → Aliases → `blk_doh_fqdn` deve contenere migliaia di IP reali, non `0.0.0.0`.

**Regole LAN → WAN**, in quest'ordine:

| # | Azione | Protocollo | Destinazione | Porta | Scuole | Aziende |
|---|---|---|---|---|---|---|
| 1 | Pass | TCP/UDP | AdGuard | 53, 853 | ✅ | ✅ |
| 2 | Block | **any** | `blk_all`, `blk_all6` | any | ✅ | ✅ |
| 3 | Block | **any** | `blk_doh_fqdn` | any | ✅ | ✅ |
| 4 | Block | **any** | `blk_vpn_fqdn` | any | ✅ | — |
| 5 | Block | TCP/UDP | any | 853 (DoT, DoQ) | ✅ | ✅ |
| 6 | Block | UDP | any | 443 (QUIC, DoH su HTTP/3) | ✅ dopo una settimana di prova con log | facoltativa |

Più un **NAT Port Forward** sulla LAN: TCP/UDP 53 verso destinazioni diverse da AdGuard → redirect ad AdGuard.

Il protocollo **any** nelle regole 2-4 è essenziale: con solo TCP o solo porta 443 passano DoQ (UDP 853) e DoH su HTTP/3 (UDP 443). Bloccare UDP 443 non rompe Meet, Teams e Zoom (usano altre porte UDP per audio e video): browser e app ripiegano su TCP 443.

**Regole WAN → LAN** (solo con servizi esposti: VPN, RDP, portali), sopra le regole che aprono le porte: block da `blk_inbound` e da `blk_all`.

**Impostazioni**: Firewall → Settings → Advanced → *Firewall Maximum Table Entries* almeno 500.000 (gli alias insieme superano le 130.000 voci). Attivare il log sulle regole di blocco nelle prime settimane per individuare i falsi positivi.

### Altri firewall

| Firewall | Dove |
|---|---|
| pfSense | Firewall → Aliases → *URL Table (IPs)*, oppure pfBlockerNG → IPv4/IPv6 |
| FortiGate | Security Fabric → External Connectors → Threat Feeds → *IP Address*; nella policy servizio **ALL** |
| SonicWall | Oggetti indirizzo dinamici esterni: il percorso di menu dipende dalla versione di SonicOS; servizio **Any** |

Le liste `opnsense/*.txt` (FQDN) sono verificate solo su OPNsense: sugli altri firewall usare i feed IP. I limiti di voci per feed di FortiGate e SonicWall dipendono da modello e firmware e vanno verificati sui dispositivi; si possono impostare in `max_entries` (`sources.toml`) per ricevere un avviso.
