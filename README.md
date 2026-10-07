# DNS-Blocklists

Liste di blocco e sblocco di **Clanto Services** per DNS (AdGuard Home, Unbound) e firewall (OPNsense, pfSense, FortiGate, SonicWall).

- **Domini**: AdGuard si abbona alle liste upstream e alle nostre liste curate.
- **IP**: generiamo noi i feed per i firewall, aggiornati **ogni 6 ore** da GitHub Actions. Aggiungendo una fonte, tutti i firewall la ricevono senza modifiche ai dispositivi.

URL base dei file: `https://raw.githubusercontent.com/clanto/DNS/main/`

| Sezione | Contenuto |
|---|---|
| [Feed IP per firewall](#feed-ip-per-firewall) | IP da bloccare, per categoria |
| [Liste domini per AdGuard](#liste-domini-per-adguard) | Allowlist e blocklist curate |
| [Liste upstream](#liste-upstream-consigliate-per-adguard) | Liste esterne con licenza verificata |
| [Liste storiche](#liste-storiche) | File originali del repository |
| [Contribuire](#contribuire) | Come aggiungere IP, domini e fonti |

---

## Feed IP per firewall

Formato: un IP o CIDR per riga, senza commenti. Compatibile con alias *URL Table* di OPNsense/pfSense, *Threat Feed* di FortiGate e oggetti dinamici di SonicWall.

| Feed | Contenuto | Direzione | IPv4 | IPv6 |
|---|---|---|---|---|
| **all** | **Aziende**: doh, tor, threat, c2 | Uscita e ingresso | [all-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v4.txt) | [all-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v6.txt) |
| **all-scuole** | **Scuole**: come `all`, più vpn | Uscita e ingresso | [all-scuole-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-scuole-v4.txt) | [all-scuole-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-scuole-v6.txt) |
| doh | Resolver DNS-over-HTTPS/TLS pubblici (anti-bypass del DNS aziendale) | Uscita | [doh-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v4.txt) | [doh-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v6.txt) |
| threat | IP malevoli attivi (exploit, sistemi compromessi, scanner) | Uscita e ingresso | [threat-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v4.txt) | [threat-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v6.txt) |
| c2 | Server di comando e controllo di botnet | Uscita | [c2-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v4.txt) | [c2-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v6.txt) |
| tor | Rete Tor: nodi di uscita e relay (blocca anche l'uso di Tor Browser) | Uscita e ingresso | [tor-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v4.txt) | [tor-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v6.txt) |
| vpn | VPN commerciali e proxy (in `all-scuole`, non in `all`) | Uscita | [vpn-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v4.txt) | [vpn-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v6.txt) |
| social | Meta (Facebook, Instagram, **WhatsApp**), TikTok, X, Telegram, per AS (non negli aggregati) | Uscita | [social-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/social-v4.txt) | [social-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/social-v6.txt) |
| inbound | Scanner e brute force verso servizi esposti (~90k voci, non in `all`) | **Solo ingresso WAN** | [inbound-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v4.txt) | [inbound-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v6.txt) |
| bogon | Reti riservate RFC 6890, comprese le private (non in `all`) | **Solo ingresso WAN** | [bogon-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v4.txt) | [bogon-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v6.txt) |

- **Dettagli**: numero di voci, fonti, licenze e stato dell'ultimo aggiornamento sono in [dist/ip/README.md](dist/ip/README.md); le statistiche in formato JSON in [stats.json](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/stats.json).
- **Registro variazioni**: [dist/CHANGELOG.md](dist/CHANGELOG.md), aggiunte e rimozioni a ogni build con la fonte di ogni IP. Primo posto da guardare quando un sito smette di funzionare.
- **Configurazione dei firewall**: in [ip/README.md](ip/README.md#configurazione-firewall).
- **Blocco per paese e bogon completi**: usare le funzioni native dei firewall (GeoIP, *Block bogon networks*). I dati di origine non sono ridistribuibili.

---

## Liste domini per AdGuard

In AdGuard Home le allowlist vanno in *Filtri → Allowlist DNS*, le blocklist in *Filtri → Blocklist DNS*.

### Allowlist

Solo host indispensabili, mai domini interi. Nessuna voce può contraddire le nostre blocklist o sbloccare servizi di bypass DNS/VPN: lo verificano il build e la CI.

| Lista | Contenuto |
|---|---|
| **[allow-base.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-base.txt)** | Tutte le categorie qui sotto tranne streaming: **da applicare a tutti** |
| [allow-protetti.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-protetti.txt) | **Servizi critici** (Workspace, Gmail SMTP, Microsoft 365, iCloud/MDM, registri elettronici, SPID, pagoPA): mai bloccati da liste domini, feed IP e liste OPNsense |
| [allow-google.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-google.txt) | Safe Browsing, app Android |
| [allow-apple.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-apple.txt) | Notifiche push Apple |
| [allow-microsoft.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-microsoft.txt) | Microsoft 365, licenze, Defender, Power BI |
| [allow-pa.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pa.txt) | PA italiana |
| [allow-pagamenti.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pagamenti.txt) | Checkout PayPal e antifrode |
| [allow-vendor-it.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-vendor-it.txt) | Documentazione vendor, GeoIP, RMM |
| [allow-siti-web.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-siti-web.txt) | Consenso cookie, font, tag manager, CDN necessari ai siti |
| [allow-smart-tv.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-smart-tv.txt) | App Samsung TV |
| [allow-scuola.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-scuola.txt) | Piattaforme didattiche |
| [allow-varie.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-varie.txt) | Siti specifici bloccati per errore |
| [allow-streaming.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-streaming.txt) | Host di Spotify, Netflix, Disney+, DAZN: **non per le scuole** |

### Blocklist

| Lista | Contenuto | Unbound | Solo domini |
|---|---|---|---|
| [block-malevoli.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malevoli.txt) | Truffe e domini malevoli segnalati da noi | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-malevoli.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malevoli.txt) |
| [block-tld.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tld.txt) | TLD interi (.xxx, .porn, .adult, .sex, .desi, .world) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-tld.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tld.txt) |
| [block-pubblicita.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | Pubblicità sfuggita alle liste upstream | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-pubblicita.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| [block-accesso-remoto.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | AnyDesk, TeamViewer, ScreenConnect… (escludere il proprio RMM) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-accesso-remoto.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| [block-ai-generativa.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | Chatbot AI (prevenzione fuga dati) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-ai-generativa.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| [block-file-sharing.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | WeTransfer, Mega, Gofile… (prevenzione fuga dati) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-file-sharing.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| [block-social.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | Social network e community, con fonti BlocklistProject (scuole). **Blocca anche WhatsApp** | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| [block-gaming.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | Piattaforme gaming, giochi da browser, Roblox, Fortnite (scuole) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-gaming.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |
| [block-tunnel.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tunnel.txt) | Tunnel ed esfiltrazione: ngrok, trycloudflare, webhook, DNS out-of-band, paste (aziende; `devtunnels.ms` va sbloccato per chi sviluppa) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-tunnel.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tunnel.txt) |
| [block-compiti.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-compiti.txt) | Risolutori e tutor per i compiti, da attivare con `block-ai-generativa` durante verifiche ed esami (scuole) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-compiti.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-compiti.txt) |
| [block-doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-doh.txt) | Resolver DoH/DoT/DoQ: HaGeZi e dibdot, aggiornati ogni 6 ore | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-doh.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-doh.txt) |
| [block-vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-vpn.txt) | VPN, proxy e bypass, esclusi i DoH: HaGeZi, aggiornati ogni 6 ore (scuole) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-vpn.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-vpn.txt) |
| [block-porno.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-porno.txt) | Contenuti per adulti (HaGeZi NSFW, ~85.000, + siti che superavano i filtri) | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-porno.txt) |
| [block-malware.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware.txt) | Malware e minacce confermate (HaGeZi Threat Intelligence mini, ~207.000) | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware.txt) |
| [block-phishing.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing.txt) | Phishing attivo (Phishing.Database, ~390.000) | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing.txt) |
| [block-redirect.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect.txt) | Redirect e URL shortener (BlocklistProject, ~109.000) | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect.txt) |
| [block-pirateria.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pirateria.txt) | Pirateria, warez, streaming illegale (HaGeZi Anti-Piracy + voci nostre) | — | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pirateria.txt) |
| [block-spyware.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware.txt) | Stalkerware e app spia (Stalkerware Indicators + voci nostre) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-spyware.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware.txt) |
| [block-cryptojacking.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking.txt) | Mining di criptovalute nel browser (NoCoin) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-cryptojacking.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking.txt) |

Le liste di policy (accesso remoto, AI, file sharing, social, gaming, streaming) in AdGuard Home valgono per **tutti** i client: vanno applicate solo sulle istanze dei clienti che le richiedono.

Le regole per singolo cliente (`$client`) restano nelle regole personalizzate di AdGuard: contengono nomi e IP dei clienti e **non vanno nel repository pubblico**.

---

### Liste FQDN per alias OPNsense

OPNsense risolve ogni dominio dell'alias e blocca gli IP ottenuti, quindi segue anche gli anycast. Le liste sono generate dalle blocklist `doh` e `vpn`, risolte in CI: sono **esclusi i domini morti** (solo carico sul resolver) e quelli su **IP di CDN condivise** (Cloudflare, CloudFront, Fastly), che bloccherebbero anche siti legittimi.

| Lista | Contenuto |
|---|---|
| [doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/doh.txt) | Resolver DoH/DoT/DoQ con IP dedicato |
| [vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/vpn.txt) | VPN e proxy con IP dedicato (scuole) |

Alias di tipo **URL Table (IPs)**. Il firewall deve risolvere i nomi con un DNS **non filtrato da AdGuard**, altrimenti l'alias resta vuoto: guida completa in [ip/README.md](ip/README.md#opnsense). Dettaglio di domini pubblicati, morti e su CDN: [dist/opnsense/README.md](dist/opnsense/README.md). Ogni lunedì un controllo risolve di nuovo le liste e segnala gli IP che stanno su CDN o hosting condivisi non ancora esclusi (Akamai, Netlify, GitHub Pages, front-end Google…) o che ospitano più domini: la rete va aggiunta a `ip/condivisi.txt`. Per AdGuard usare le liste complete `block-doh.txt` e `block-vpn.txt`.

## Liste upstream consigliate per AdGuard

Principali liste esterne, con licenza verificata per l'uso commerciale. Il catalogo completo, con lo stato di ogni lista (attiva, consigliata, da rimuovere), è in [dist/adguard/README.md](dist/adguard/README.md#catalogo-liste-upstream-abbonamento-diretto-su-adguard).

| Lista | Categoria | Licenza |
|---|---|---|
| [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | Pubblicità, tracking, malware | GPL-3.0 |
| [HaGeZi Threat Intelligence Feeds](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) | Malware, phishing | GPL-3.0 |
| [HaGeZi DoH/VPN/TOR/Proxy Bypass](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt) | Bypass del DNS | GPL-3.0 |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | Domini registrati da poco (~3,6M righe) | GPL-3.0 |
| [HaGeZi DynDNS](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt) | DNS dinamici | GPL-3.0 |
| [HaGeZi Gambling](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt) | Scommesse | GPL-3.0 |
| [HaGeZi NSFW](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt) | Contenuti per adulti | GPL-3.0 |
| [HaGeZi Anti-Piracy](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt) | Pirateria | GPL-3.0 |
| [AdGuard DNS filter](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) | Pubblicità, tracking | GPL-3.0 |
| [Stalkerware Indicators](https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt) | App spia | CC BY 4.0 |
| [NoCoin](https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt) | Cryptojacking | MIT |
| [WindowsSpyBlocker](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt) | Telemetria Windows | MIT |
| [Perflyst Smart TV](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | Telemetria smart TV | MIT |

**Da rimuovere da AdGuard**:
- **Phishing Army** (CC BY-NC: non consentita per uso commerciale)
- **Dandelion Sprout** (licenza non standard)
- **Big List of Hacked Malware** (ferma dal 2023)

---

## Liste storiche

Liste storiche **curate a mano**, mantenute agli stessi URL per compatibilità. Quelle sostituite da liste dinamiche sono state rimosse: `pornoextra` → `block-porno`, `roblox` → `block-gaming`, `ubound_safesearch.conf` → [`dist/unbound/safesearch.conf`](#safesearch-per-unbound), `appspia` → `block-spyware`, `criptojacking` → `block-cryptojacking`, `malware` → `block-malware`, `pishing` → `block-phishing`, `redirect` → `block-redirect`, `warez` e `lista_streaming_illegale` → `block-pirateria` (le voci curate da noi sono confluite nelle nuove liste). `DNSoverHTTPS/doh.txt` e `liste/vpn.txt` sono stati rimossi: li sostituiscono le liste dinamiche [block-doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-doh.txt) e [block-vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-vpn.txt).

| Lista | Contenuto | Stato |
|---|---|---|
| [ddos.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/ddos.txt) | Servizi di attacco DDoS | Curata da noi |
| [lista_streaming_legale_noscuola.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/lista_streaming_legale_noscuola.txt) | Streaming legale non ammesso a scuola | Curata da noi |
| [motori_ricerca_nosafesearch.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/motori_ricerca_nosafesearch.txt) | Motori di ricerca senza Safe Search | Curata da noi |
| [ipv4.txt](https://raw.githubusercontent.com/clanto/DNS/main/DNSoverHTTPS/ipv4.txt) | IP DNS-over-HTTPS | **Generata**: uguale a `dist/ip/doh-v4.txt` |

## SafeSearch per Unbound

[safesearch.conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/safesearch.conf): SafeSearch forzato su Google, YouTube (moderato), Bing, DuckDuckGo, Yandex e Pixabay. Generato a ogni build risolvendo i nomi ufficiali (`forcesafesearch.google.com`, `strict.bing.com`…), con record A e AAAA: gli IP restano corretti anche quando i motori li cambiano. Domini gestiti in [domains/safesearch.toml](domains/safesearch.toml). Su AdGuard Home usare l'opzione nativa *Ricerca sicura*.

---

## Contribuire

| Cosa | Dove | Guida |
|---|---|---|
| Aggiungere un IP da bloccare | `ip/custom/<categoria>.txt` | [ip/README.md](ip/README.md#aggiungere-un-ip-a-mano) |
| Sbloccare un IP (falso positivo) | [ip/allowlist.txt](ip/allowlist.txt) | [ip/README.md](ip/README.md#sbloccare-un-falso-positivo) |
| Proteggere un servizio critico | [domains/allowlist/protetti.txt](domains/allowlist/protetti.txt) | solo host esatti |
| Segnalare una rete di hosting/CDN condivisa | [ip/condivisi.txt](ip/condivisi.txt) | [ip/README.md](ip/README.md#infrastrutture-condivise) |
| Aggiungere una fonte IP | [ip/sources.toml](ip/sources.toml) | [ip/README.md](ip/README.md#aggiungere-una-fonte) |
| Bloccare o sbloccare un dominio | [domains/blocklist/](domains/blocklist/), [domains/allowlist/](domains/allowlist/) | formato sotto |
| Catalogare una lista upstream | [domains/upstream.toml](domains/upstream.toml) | licenza obbligatoria |

Formato delle voci manuali, una per riga:

```
voce | AAAA-MM-GG | motivo | ticket (o -) | scadenza AAAA-MM-GG (opzionale)
```

- **Nel motivo mai dati personali**: solo descrizione tecnica e ID ticket (ISO 27701). La CI rifiuta email e numeri di telefono.
- **File generati**: `dist/` e `DNSoverHTTPS/ipv4.txt` sono prodotti dal build e **non vanno modificati a mano**. La CI blocca le PR che li toccano.

---

## Altre risorse

Risorse esterne, non mantenute da noi:
- [UT1 Université Toulouse Capitole](https://dsi.ut-capitole.fr/blacklists/index_en.php): liste per categoria, utili per le scuole (CC BY-SA 4.0)
- [Blocklist.site](https://blocklist.site/): portale di liste suddivise per categoria

## Licenza

[GPL-3.0](LICENSE). Le attribuzioni delle fonti sono in [dist/ip/README.md](dist/ip/README.md) e [dist/adguard/README.md](dist/adguard/README.md).
