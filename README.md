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
| [Altre liste](#altre-liste) | Liste curate a mano agli URL originali |
| [SafeSearch per Unbound](#safesearch-per-unbound) | SafeSearch forzato via DNS |
| [Catalogo, attribuzioni e release](#catalogo-attribuzioni-e-release) | Catalogo JSON, licenze, copie settimanali |
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

OPNsense risolve ogni dominio dell'alias e blocca gli IP ottenuti, quindi segue anche gli anycast. Le liste sono generate dalle blocklist `doh` e `vpn`, risolte in CI: sono **esclusi i domini morti**, quelli in sinkhole, quelli su **infrastrutture condivise** (CDN e hosting) e quelli sugli IP dei servizi protetti, che bloccherebbero anche siti legittimi.

| Lista | Contenuto |
|---|---|
| [doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/doh.txt) | Resolver DoH/DoT/DoQ con IP dedicato |
| [vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/vpn.txt) | VPN e proxy con IP dedicato (scuole) |

Alias di tipo **URL Table (IPs)**. Il firewall deve risolvere i nomi con un DNS **non filtrato da AdGuard**, altrimenti l'alias resta vuoto: guida completa in [ip/README.md](ip/README.md#opnsense). Dettaglio di domini pubblicati, morti e su CDN: [dist/opnsense/README.md](dist/opnsense/README.md). Ogni lunedì un controllo risolve di nuovo le liste e segnala gli IP su hosting condivisi o che ospitano più domini: la rete va aggiunta a `ip/condivisi.txt`. Per AdGuard usare le liste complete `block-doh.txt` e `block-vpn.txt`.

## Liste upstream consigliate per AdGuard

Liste esterne da abbonare direttamente su AdGuard, insieme alle nostre liste di `dist/adguard/`. Le fonti che ripubblichiamo (DoH, VPN, redirect, spyware, cryptojacking, porno, pirateria, social) si prendono dalle nostre, che aggiungono voci curate, servizi protetti e controllo dei conflitti con le allowlist. Licenze verificate per l'uso commerciale; note per ogni lista in [dist/adguard/README.md](dist/adguard/README.md#liste-upstream-consigliate-abbonamento-diretto-su-adguard).

| Lista | Categoria | Ambito | Licenza |
|---|---|---|---|
| [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | pubblicità, tracking | tutti | GPL-3.0 |
| [HaGeZi Pop-Up Ads](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt) | pubblicità | tutti | GPL-3.0 |
| [HaGeZi Threat Intelligence Feeds](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) | malware, phishing | tutti | GPL-3.0 |
| [Phishing URL Blocklist (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt) | phishing | tutti | MIT |
| [uBlock Badware risks](https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt) | malware | tutti | GPL-3.0 |
| [DurableNapkin Scam](https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt) | truffe | tutti | MIT |
| [ShadowWhisperer Malware](https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt) | malware | tutti | Unlicense |
| [BlocklistProject Fraud](https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt) | truffe | tutti | Unlicense |
| [BlocklistProject Scam](https://blocklistproject.github.io/Lists/adguard/scam-ags.txt) | truffe | tutti | Unlicense |
| [BlocklistProject Ransomware](https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt) | ransomware | tutti | Unlicense |
| [URLhaus (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt) | malware | tutti | Termini abuse.ch |
| [HaGeZi DynDNS](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt) | DNS dinamici | tutti | GPL-3.0 |
| [HaGeZi Spam TLDs](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt) | TLD abusati | tutti | GPL-3.0 |
| [HaGeZi Fake](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt) | truffe | tutti | GPL-3.0 |
| [HaGeZi DGA 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/dga7.txt) | malware (domini generati) | tutti | GPL-3.0 |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | domini registrati da poco | tutti | GPL-3.0 |
| [Frogeye first-party trackers](https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt) | tracker CNAME cloaking | tutti | MIT |
| [Perflyst Smart TV (AdGuard)](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | telemetria smart TV | tutti | MIT |
| [WindowsSpyBlocker spy](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt) | telemetria Windows | aziende | MIT |
| [HaGeZi Gambling](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt) | scommesse | scuole | GPL-3.0 |
| [UT1 Université Toulouse Capitole](https://dsi.ut-capitole.fr/blacklists/index_en.php) | categorie per scuole | scuole | CC BY-SA 4.0 |
| [HaGeZi Allowlist Referral](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/whitelist-referral.txt) | allowlist (link di affiliazione) | tutti | GPL-3.0 |

---

## Altre liste

Liste curate a mano, agli URL originali.

| Lista | Contenuto |
|---|---|
| [ddos.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/ddos.txt) | Servizi di attacco DDoS |
| [lista_streaming_legale_noscuola.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/lista_streaming_legale_noscuola.txt) | Streaming legale non ammesso a scuola |
| [motori_ricerca_nosafesearch.txt](https://raw.githubusercontent.com/clanto/DNS/main/liste/motori_ricerca_nosafesearch.txt) | Motori di ricerca senza SafeSearch |
| [ipv4.txt](https://raw.githubusercontent.com/clanto/DNS/main/DNSoverHTTPS/ipv4.txt) | IP DNS-over-HTTPS: generata, uguale a `dist/ip/doh-v4.txt` |

## SafeSearch per Unbound

[safesearch.conf](https://raw.githubusercontent.com/clanto/DNS/main/dist/unbound/safesearch.conf): SafeSearch forzato su Google, YouTube (moderato), Bing, DuckDuckGo, Yandex e Pixabay. Generato a ogni build risolvendo i nomi ufficiali (`forcesafesearch.google.com`, `strict.bing.com`…), con record A e AAAA: gli IP restano corretti anche quando i motori li cambiano. Domini gestiti in [domains/safesearch.toml](domains/safesearch.toml). Su AdGuard Home usare l'opzione nativa *Ricerca sicura*.

## Catalogo, attribuzioni e release

- **Catalogo per automazioni**: [index.json](https://raw.githubusercontent.com/clanto/DNS/main/dist/index.json) elenca ogni feed e lista con URL, formato, numero di voci, descrizione e fonti.
- **Attribuzioni**: [THIRD_PARTY.md](dist/THIRD_PARTY.md) riporta tutte le fonti di terze parti con licenza e link.
- **Release settimanali**: ogni lunedì una [release](https://github.com/clanto/DNS/releases) datata con tutte le liste, `SHA256SUMS` e `liste.zip`; conservate le ultime 12. Per un **rollback** si sostituisce nell'URL del feed `raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v4.txt` con `github.com/clanto/DNS/releases/download/liste-AAAA-MM-GG/ip-all-v4.txt` (stesso schema `cartella-file` per le altre liste).

---

## Contribuire

| Cosa | Dove | Guida |
|---|---|---|
| Aggiungere un IP da bloccare | `ip/custom/<categoria>.txt` | [ip/README.md](ip/README.md#aggiungere-un-ip-a-mano) |
| Sbloccare un IP (falso positivo) | [ip/allowlist.txt](ip/allowlist.txt) | [ip/README.md](ip/README.md#sbloccare-un-falso-positivo) |
| Togliere un dominio legittimo arrivato da una fonte esterna | [domains/escludi.txt](domains/escludi.txt) | solo nome esatto |
| Proteggere un servizio critico | [domains/allowlist/protetti.txt](domains/allowlist/protetti.txt) | solo host esatti |
| Segnalare una rete di hosting/CDN condivisa | [ip/condivisi.txt](ip/condivisi.txt) | [ip/README.md](ip/README.md#infrastrutture-condivise) |
| Aggiungere una fonte IP | [ip/sources.toml](ip/sources.toml) | [ip/README.md](ip/README.md#aggiungere-una-fonte) |
| Bloccare o sbloccare un dominio | [domains/blocklist/](domains/blocklist/), [domains/allowlist/](domains/allowlist/) | formato sotto |
| Catalogare una lista upstream | [domains/upstream.toml](domains/upstream.toml) | licenza obbligatoria |

Regole complete in [CONTRIBUTING.md](CONTRIBUTING.md); segnalazioni con i moduli delle issue (*Segnala un falso positivo*, *Proponi un blocco*); problemi di sicurezza in privato, vedi [SECURITY.md](SECURITY.md).

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

[GPL-3.0](LICENSE). Attribuzioni delle fonti in [dist/THIRD_PARTY.md](dist/THIRD_PARTY.md).
