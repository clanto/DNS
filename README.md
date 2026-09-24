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
| **all** | Aggregato: doh, tor, threat, c2, hacking, warez | Uscita e ingresso | [all-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v4.txt) | [all-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v6.txt) |
| doh | Resolver DNS-over-HTTPS/TLS pubblici (anti-bypass del DNS aziendale) | Uscita | [doh-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v4.txt) | [doh-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v6.txt) |
| threat | IP malevoli attivi (exploit, sistemi compromessi, scanner) | Uscita e ingresso | [threat-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v4.txt) | [threat-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v6.txt) |
| c2 | Server di comando e controllo di botnet | Uscita | [c2-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v4.txt) | [c2-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v6.txt) |
| tor | Nodi di uscita Tor | Uscita e ingresso | [tor-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v4.txt) | [tor-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v6.txt) |
| hacking | IP di siti hacking (curati da noi) | Uscita | [hacking-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/hacking-v4.txt) | [hacking-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/hacking-v6.txt) |
| warez | IP di siti warez (curati da noi) | Uscita | [warez-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/warez-v4.txt) | [warez-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/warez-v6.txt) |
| vpn | VPN commerciali e proxy (non in `all`: solo dove serve, es. scuole) | Uscita | [vpn-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v4.txt) | [vpn-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v6.txt) |
| inbound | Scanner e brute force verso servizi esposti (~90k voci, non in `all`) | **Solo ingresso WAN** | [inbound-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v4.txt) | [inbound-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v6.txt) |
| bogon | Reti riservate RFC 6890, comprese le private (non in `all`) | **Solo ingresso WAN** | [bogon-v4.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v4.txt) | [bogon-v6.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v6.txt) |

- **Dettagli**: numero di voci, fonti, licenze e stato dell'ultimo aggiornamento sono in [dist/ip/README.md](dist/ip/README.md); le statistiche in formato JSON in [stats.json](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/stats.json).
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

### Blocklist curate

| Lista | Contenuto | Unbound | Solo domini |
|---|---|---|---|
| [block-malevoli.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malevoli.txt) | Truffe e domini malevoli segnalati da noi | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-malevoli.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malevoli.txt) |
| [block-tld.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tld.txt) | TLD interi (.xxx, .porn, .adult, .sex, .desi, .world) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-tld.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tld.txt) |
| [block-pubblicita.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | Pubblicità sfuggita alle liste upstream | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-pubblicita.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| [block-accesso-remoto.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | AnyDesk, TeamViewer, ScreenConnect… (escludere il proprio RMM) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-accesso-remoto.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| [block-ai-generativa.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | Chatbot AI (prevenzione fuga dati) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-ai-generativa.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| [block-file-sharing.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | WeTransfer, Mega, Gofile… (prevenzione fuga dati) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-file-sharing.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| [block-social.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | Social network e community (scuole) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-social.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| [block-gaming.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | Piattaforme gaming e giochi da browser (scuole) | [conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/block-gaming.conf) | [txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |

Le liste di policy (accesso remoto, AI, file sharing, social, gaming, streaming) in AdGuard Home valgono per **tutti** i client: vanno applicate solo sulle istanze dei clienti che le richiedono.

Le regole per singolo cliente (`$client`) restano nelle regole personalizzate di AdGuard: contengono nomi e IP dei clienti e **non vanno nel repository pubblico**.

---

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

File originali del repository, mantenuti agli stessi URL per compatibilità.

| Lista | Contenuto | Stato |
|---|---|---|
| [appspia.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/appspia.txt) | App spia | Integrata da Stalkerware Indicators |
| [criptojacking.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/criptojacking.txt) | Cryptojacking | Ferma; sostituita da NoCoin |
| [ddos.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/ddos.txt) | Servizi di attacco DDoS | Curata da noi |
| [hacking.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/hacking.txt) | Siti hacking | Curata da noi; IP anche nel feed `hacking` |
| [lista_streaming_illegale.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/lista_streaming_illegale.txt) | Streaming illegale | Curata da noi |
| [lista_streaming_legale_noscuola.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/lista_streaming_legale_noscuola.txt) | Streaming legale non ammesso a scuola | Curata da noi |
| [malware.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/malware.txt) | Malware | Ferma dal 2022; sostituita da HaGeZi TIF |
| [motori_ricerca_nosafesearch.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/motori_ricerca_nosafesearch.txt) | Motori di ricerca senza Safe Search | Curata da noi |
| [pishing.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/pishing.txt) | Phishing | Ferma; già contenuta in malware.txt |
| [pornoextra.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/pornoextra.txt) | Siti porno che superavano i filtri | Curata da noi |
| [redirect.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/redirect.txt) | Redirect e URL shortener | Ferma; sostituita da BlocklistProject Redirect |
| [roblox.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/roblox.txt) | Roblox | Curata da noi |
| [vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/vpn.txt) | Siti VPN | Curata da noi; integrata da HaGeZi Bypass |
| [warez.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/warez.txt) | Warez | Curata da noi; IP anche nel feed `warez` |
| [doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/DNSoverHTTPS/doh.txt) | Domini DNS-over-HTTPS | Curata da noi |
| [ipv4.txt](https://raw.githubusercontent.com/clanto/DNS/main/DNSoverHTTPS/ipv4.txt) | IP DNS-over-HTTPS | **Generata**: uguale a `dist/ip/doh-v4.txt` |
| [ubound_safesearch.conf](https://raw.githubusercontent.com/clanto/DNS/main/safe_search/ubound_safesearch.conf) | Unbound: Safe Search forzato (Google, Bing, DuckDuckGo, Yandex, YouTube, Pixabay) | Curata da noi |

---

## Contribuire

| Cosa | Dove | Guida |
|---|---|---|
| Aggiungere un IP da bloccare | `ip/custom/<categoria>.txt` | [ip/README.md](ip/README.md#aggiungere-un-ip-a-mano) |
| Sbloccare un IP (falso positivo) | [ip/allowlist.txt](ip/allowlist.txt) | [ip/README.md](ip/README.md#sbloccare-un-falso-positivo) |
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
