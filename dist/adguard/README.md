# Liste domini per AdGuard

> File generato da `scripts/build_domains.py`: **non modificare a mano**.
> Voci in [`domains/allowlist/`](../../domains/allowlist/) e [`domains/blocklist/`](../../domains/blocklist/).

In AdGuard Home: allowlist in *Filtri → Allowlist DNS*, blocklist in *Filtri → Blocklist DNS*.
Le liste valgono per **tutti** i client: le policy (streaming, social, gaming, AI) vanno applicate
solo su istanze dedicate ai clienti che le richiedono.

## Liste pubblicate

| Lista | Descrizione | Voci | AdGuard | Formato semplice |
|---|---|---|---|---|
| `allow-base.txt` | Aggregato allowlist: protetti, google, apple, microsoft, pa, pagamenti, vendor-it, siti-web, smart-tv, scuola, varie | 116 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-base.txt) | — |
| `allow-protetti.txt` | Servizi critici: mai bloccati da liste domini, feed IP e liste OPNsense | 46 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-protetti.txt) | — |
| `allow-google.txt` | Servizi Google indispensabili (Safe Browsing, app Android) | 8 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-google.txt) | — |
| `allow-apple.txt` | Notifiche push Apple | 2 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-apple.txt) | — |
| `allow-microsoft.txt` | Microsoft 365, licenze, Defender, Power BI | 8 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-microsoft.txt) | — |
| `allow-pa.txt` | PA italiana | 1 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pa.txt) | — |
| `allow-pagamenti.txt` | Checkout PayPal e antifrode | 9 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pagamenti.txt) | — |
| `allow-vendor-it.txt` | Documentazione vendor, GeoIP, RMM | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-vendor-it.txt) | — |
| `allow-siti-web.txt` | Script di terze parti senza cui i siti non funzionano (consenso cookie, font, tag manager, CDN) | 23 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-siti-web.txt) | — |
| `allow-smart-tv.txt` | App Samsung TV | 2 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-smart-tv.txt) | — |
| `allow-scuola.txt` | Piattaforme didattiche | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-scuola.txt) | — |
| `allow-varie.txt` | Siti specifici bloccati per errore | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-varie.txt) | — |
| `allow-streaming.txt` | Host specifici delle piattaforme streaming | 13 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-streaming.txt) | — |
| `block-tld.txt` | TLD interi bloccati | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tld.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tld.txt) |
| `block-malevoli.txt` | Domini malevoli e truffe segnalati da noi | 22 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malevoli.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malevoli.txt) |
| `block-pubblicita.txt` | Pubblicità sfuggita alle liste upstream | 3 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| `block-accesso-remoto.txt` | Strumenti di accesso remoto (abusati in truffe e ransomware): escludere il proprio RMM | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| `block-ai-generativa.txt` | Chatbot di AI generativa (policy di prevenzione fuga dati) | 17 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| `block-file-sharing.txt` | File sharing e trasferimento file anonimi (policy di prevenzione fuga dati) | 15 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| `block-social.txt` | Social network e piattaforme community (scuole) | 421 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| `block-gaming.txt` | Giochi online e piattaforme di gaming (scuole) | 23 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |
| `block-doh.txt` | Resolver DNS-over-HTTPS/TLS/QUIC: impediscono il bypass del DNS aziendale | 3299 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-doh.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-doh.txt) |
| `block-vpn.txt` | VPN, proxy e servizi di bypass (scuole) | 12798 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-vpn.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-vpn.txt) |
| `block-porno.txt` | Contenuti per adulti (HaGeZi NSFW + siti che superavano i filtri) | 84747 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-porno.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-porno.txt) |
| `block-tunnel.txt` | Tunnel, esfiltrazione e canali di controllo: ngrok, trycloudflare, webhook, out-of-band, paste (aziende) | 40 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tunnel.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tunnel.txt) |
| `block-compiti.txt` | Risolutori e tutor per i compiti: da attivare durante verifiche ed esami (scuole) | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-compiti.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-compiti.txt) |
| `block-malware.txt` | Malware e minacce confermate (HaGeZi Threat Intelligence mini, TweetFeed) | 239544 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware.txt) |
| `block-phishing.txt` | Phishing attivo (Phishing.Database, Validin) | 444552 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing.txt) |
| `block-spyware.txt` | Stalkerware e app spia | 528 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware.txt) |
| `block-cryptojacking.txt` | Mining di criptovalute nel browser | 296 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking.txt) |
| `block-redirect.txt` | Redirect e URL shortener (BlocklistProject) | 108680 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect.txt) |
| `block-pirateria.txt` | Pirateria, warez e streaming illegale | 55227 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pirateria.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pirateria.txt) |

## Liste upstream consigliate (abbonamento diretto su AdGuard)

| Lista | Categoria | Licenza | Ambito | Note |
|---|---|---|---|---|
| [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | pubblicità, tracking | GPL-3.0 | tutti |  |
| [HaGeZi Pop-Up Ads](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt) | pubblicità | GPL-3.0 | tutti |  |
| [HaGeZi Threat Intelligence Feeds](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) | malware, phishing | GPL-3.0 | tutti | Versione completa: con questa la nostra block-malware (versione mini) non serve |
| [Phishing URL Blocklist (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt) | phishing | MIT | tutti |  |
| [uBlock Badware risks](https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt) | malware | GPL-3.0 | tutti |  |
| [DurableNapkin Scam](https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt) | truffe | MIT | tutti |  |
| [ShadowWhisperer Malware](https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt) | malware | Unlicense | tutti |  |
| [BlocklistProject Fraud](https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt) | truffe | Unlicense | tutti |  |
| [BlocklistProject Scam](https://blocklistproject.github.io/Lists/adguard/scam-ags.txt) | truffe | Unlicense | tutti |  |
| [BlocklistProject Ransomware](https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt) | ransomware | Unlicense | tutti |  |
| [URLhaus (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt) | malware | Termini abuse.ch | tutti | Per l'uso commerciale i termini abuse.ch possono richiedere un abbonamento |
| [HaGeZi DynDNS](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt) | DNS dinamici | GPL-3.0 | tutti |  |
| [HaGeZi Spam TLDs](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt) | TLD abusati | GPL-3.0 | tutti |  |
| [HaGeZi Fake](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt) | truffe | GPL-3.0 | tutti |  |
| [HaGeZi DGA 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/dga7.txt) | malware (domini generati) | GPL-3.0 | tutti |  |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | domini registrati da poco | GPL-3.0 | tutti | Circa 3,6 milioni di voci: verificare la RAM di AdGuard |
| [Frogeye first-party trackers](https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt) | tracker CNAME cloaking | MIT | tutti |  |
| [Perflyst Smart TV (AdGuard)](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | telemetria smart TV | MIT | tutti |  |
| [WindowsSpyBlocker spy](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt) | telemetria Windows | MIT | aziende | Provare prima su pochi PC: può interferire con Windows Update e Defender |
| [HaGeZi Gambling](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt) | scommesse | GPL-3.0 | scuole |  |
| [UT1 Université Toulouse Capitole](https://dsi.ut-capitole.fr/blacklists/index_en.php) | categorie per scuole | CC BY-SA 4.0 | scuole | Liste per categoria da scegliere sul sito |
| [HaGeZi Allowlist Referral](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/whitelist-referral.txt) | allowlist (link di affiliazione) | GPL-3.0 | tutti |  |

## Contributo delle fonti

Voci pubblicate che arrivano **solo** da una fonte: misura quanto una lista dipende da ciascuna.

| Lista | Fonte | Voci esclusive | Quota |
|---|---|---|---|
| block-cryptojacking | nocoin | 312 | 100.0% |
| block-doh | dibdot-doh | 170 | 4.9% |
| block-doh | hagezi-doh | 2090 | 60.4% |
| block-doh | manuale | 5 | 0.1% |
| block-gaming | blocklistproject-fortnite | 5 | 18.5% |
| block-gaming | manuale | 22 | 81.5% |
| block-malware | hagezi-tif-mini | 238094 | 99.4% |
| block-malware | tweetfeed-domains | 366 | 0.2% |
| block-phishing | phishing-database-active | 383041 | 81.4% |
| block-phishing | validin-phish | 83775 | 17.8% |
| block-pirateria | hagezi-anti-piracy | 53827 | 97.5% |
| block-pirateria | manuale | 595 | 1.1% |
| block-porno | hagezi-nsfw | 84722 | 99.9% |
| block-porno | manuale | 34 | 0.0% |
| block-redirect | blocklistproject-redirect | 108684 | 100.0% |
| block-social | blocklistproject-facebook | 22358 | 81.9% |
| block-social | blocklistproject-tiktok | 3722 | 13.6% |
| block-social | blocklistproject-twitter | 1191 | 4.4% |
| block-social | manuale | 18 | 0.1% |
| block-spyware | manuale | 7 | 0.7% |
| block-spyware | stalkerware-indicators | 913 | 97.6% |
| block-vpn | hagezi-bypass | 12798 | 100.0% |

Pubblicato sotto GPL-3.0.
