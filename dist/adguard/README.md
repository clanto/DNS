# Liste domini per AdGuard

> File generato da `scripts/build_domains.py`: **non modificare a mano**.
> Voci in [`domains/allowlist/`](../../domains/allowlist/) e [`domains/blocklist/`](../../domains/blocklist/).

In AdGuard Home: allowlist in *Filtri → Allowlist DNS*, blocklist in *Filtri → Blocklist DNS*.
Le liste valgono per **tutti** i client: le policy (streaming, social, gaming, AI) vanno applicate
solo su istanze dedicate ai clienti che le richiedono.

## Liste pubblicate

| Lista | Descrizione | Voci | AdGuard | Formato semplice |
|---|---|---|---|---|
| `allow-base.txt` | Aggregato allowlist: google, apple, microsoft, pa, pagamenti, vendor-it, siti-web, smart-tv, scuola, varie | 66 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-base.txt) | — |
| `allow-apple.txt` | Notifiche push Apple | 1 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-apple.txt) | — |
| `allow-google.txt` | Servizi Google indispensabili (Safe Browsing, app Android) | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-google.txt) | — |
| `allow-microsoft.txt` | Microsoft 365, licenze, Defender, Power BI | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-microsoft.txt) | — |
| `allow-pa.txt` | PA italiana | 1 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pa.txt) | — |
| `allow-pagamenti.txt` | Checkout PayPal e antifrode | 9 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-pagamenti.txt) | — |
| `allow-scuola.txt` | Piattaforme didattiche | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-scuola.txt) | — |
| `allow-siti-web.txt` | Script di terze parti senza cui i siti non funzionano (consenso cookie, font, tag manager, CDN) | 23 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-siti-web.txt) | — |
| `allow-smart-tv.txt` | App Samsung TV | 2 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-smart-tv.txt) | — |
| `allow-streaming.txt` | Host specifici delle piattaforme streaming | 13 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-streaming.txt) | — |
| `allow-varie.txt` | Siti specifici bloccati per errore | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-varie.txt) | — |
| `allow-vendor-it.txt` | Documentazione vendor, GeoIP, RMM | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/allow-vendor-it.txt) | — |
| `block-accesso-remoto.txt` | Strumenti di accesso remoto (abusati in truffe e ransomware): escludere il proprio RMM | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| `block-ai-generativa.txt` | Chatbot di AI generativa (policy di prevenzione fuga dati) | 14 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| `block-file-sharing.txt` | File sharing e trasferimento file anonimi (policy di prevenzione fuga dati) | 15 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| `block-gaming.txt` | Giochi online e piattaforme di gaming (scuole) | 20 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |
| `block-malevoli.txt` | Domini malevoli e truffe segnalati da noi | 22 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malevoli.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malevoli.txt) |
| `block-pubblicita.txt` | Pubblicità sfuggita alle liste upstream | 3 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| `block-social.txt` | Social network e piattaforme community (scuole) | 27 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| `block-tld.txt` | TLD interi bloccati | 6 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tld.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tld.txt) |

## Catalogo liste upstream (abbonamento diretto su AdGuard)

| Lista | Categoria | Licenza | Stato | Note |
|---|---|---|---|---|
| [AdGuard DNS filter](https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt) | ads/tracking | GPL-3.0 | attiva |  |
| [AdAway Default Blocklist](https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt) | ads | GPL-3.0 | attiva |  |
| [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | multi | GPL-3.0 | attiva |  |
| [BlocklistProject Ads](https://blocklistproject.github.io/Lists/adguard/ads-ags.txt) | ads | Unlicense | attiva |  |
| [BlocklistProject Tracking](https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt) | tracking | Unlicense | attiva |  |
| [HaGeZi Pop-Up Ads](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt) | ads | GPL-3.0 | consigliata |  |
| [HaGeZi Threat Intelligence Feeds](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) | malware/phishing | GPL-3.0 | attiva | Fonte principale di sicurezza |
| [Phishing URL Blocklist (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt) | phishing | MIT | attiva |  |
| [uBlock Badware risks](https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt) | malware | GPL-3.0 | attiva |  |
| [DurableNapkin Scam](https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt) | scam | MIT | attiva |  |
| [ShadowWhisperer Malware](https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt) | malware | Unlicense | attiva |  |
| [Stalkerware Indicators](https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt) | spyware | CC BY-4.0 | attiva | Integra liste/appspia.txt |
| [NoCoin](https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt) | cryptojacking | MIT | attiva | Sostituisce liste/criptojacking.txt (4.804 righe corrotte) |
| [BlocklistProject Fraud](https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt) | scam | Unlicense | attiva |  |
| [BlocklistProject Malware](https://blocklistproject.github.io/Lists/adguard/malware-ags.txt) | malware | Unlicense | attiva | 2,6M righe, molto sovrapposta a HaGeZi TIF |
| [BlocklistProject Phishing](https://blocklistproject.github.io/Lists/adguard/phishing-ags.txt) | phishing | Unlicense | attiva |  |
| [BlocklistProject Ransomware](https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt) | ransomware | Unlicense | attiva |  |
| [BlocklistProject Scam](https://blocklistproject.github.io/Lists/adguard/scam-ags.txt) | scam | Unlicense | attiva |  |
| [BlocklistProject Redirect](https://blocklistproject.github.io/Lists/adguard/redirect-ags.txt) | redirect | Unlicense | attiva | Origine probabile di liste/redirect.txt |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | domini nuovi | GPL-3.0 | consigliata | 3,6M righe: verificare RAM di AdGuard; i successivi nrd14-8, nrd21-15, nrd28-22 aggiungono ~2-3M ciascuno |
| [HaGeZi DGA 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/dga7.txt) | malware (DGA) | GPL-3.0 | consigliata |  |
| [HaGeZi DynDNS](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/dyndns.txt) | dns dinamici | GPL-3.0 | consigliata |  |
| [HaGeZi Spam TLDs](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt) | tld abusati | GPL-3.0 | consigliata |  |
| [HaGeZi Fake](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt) | scam | GPL-3.0 | consigliata |  |
| [HaGeZi DoH/VPN/TOR/Proxy Bypass](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt) | bypass | GPL-3.0 | consigliata | Integra liste/vpn.txt e DNSoverHTTPS/doh.txt |
| [dibdot DoH domains](https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt) | bypass | GPL-3.0 | attiva |  |
| [Dandelion Sprout Anti-Malware](https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt) | malware | Dandelicence (non standard) | da rimuovere | Clausole non standard, incompatibili con GPL-3.0 e con uso commerciale certo; coperta da HaGeZi TIF |
| [Phishing Army](https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt) | phishing | CC BY-NC 4.0 | da rimuovere | Non commerciale: vietata per un MSP senza licenza dell'autore |
| [Big List of Hacked Malware Sites](https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt) | malware | MIT | da rimuovere | Ferma da ottobre 2023 |
| [URLhaus (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt) | malware | ToS abuse.ch | attiva | ToS abuse.ch: uso commerciale può richiedere abbonamento Spamhaus; chiedere conferma ad abuse.ch |
| [WindowsSpyBlocker spy](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt) | telemetria Windows | MIT | consigliata | Formato hosts; extra.txt è più aggressivo. Verificare che non rompa Windows Update/Defender |
| [Perflyst Smart TV (AdGuard)](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt) | telemetria smart TV | MIT | consigliata | allow-smart-tv ($important) mantiene comunque i servizi Samsung sbloccati |
| [Frogeye first-party trackers](https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt) | tracker CNAME cloaking | MIT | consigliata |  |
| [BlocklistProject Porn](https://blocklistproject.github.io/Lists/adguard/porn-ags.txt) | adulti | Unlicense | attiva |  |
| [HaGeZi NSFW](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt) | adulti | GPL-3.0 | consigliata |  |
| [HaGeZi Gambling](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt) | scommesse | GPL-3.0 | consigliata |  |
| [HaGeZi Anti-Piracy](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/anti.piracy.txt) | pirateria | GPL-3.0 | consigliata | Integra liste/warez.txt e liste/lista_streaming_illegale.txt |
| [ADM siti di gioco inibiti](https://www.adm.gov.it/portale/siti-web-inibiti-giochi) | scommesse | Non dichiarata | solo riferimento | Il file TXT ha URL versionato che cambia a ogni aggiornamento; licenza di riuso non indicata |
| [UT1 Université Toulouse Capitole](https://dsi.ut-capitole.fr/blacklists/index_en.php) | categorie scuola | CC BY-SA 4.0 | consigliata | Uso commerciale consentito con attribuzione e ShareAlike |
| [HaGeZi Allowlist Referral](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/whitelist-referral.txt) | allowlist | GPL-3.0 | consigliata | Link di affiliazione/referral legittimi |
| [HaGeZi Allowlist URL Shortener](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/whitelist-urlshortener.txt) | allowlist | GPL-3.0 | consigliata | Solo se si usa la blocklist redirect |
| [Ultimate Hosts Blacklist whitelist](https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list) | allowlist | MIT | solo riferimento | Ferma da luglio 2026: utile per cercare falsi positivi, non come abbonamento |
| [AdGuard HttpsExclusions banche](https://github.com/AdguardTeam/HttpsExclusions) | allowlist banche | Nessuna | solo riferimento | Senza licenza: consultabile, non ridistribuibile |

Pubblicato sotto GPL-3.0.
