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
| `block-pubblicita.txt` | Pubblicità: reti pubblicitarie e ad server (EasyList, ShadowWhisperer Ads + voci nostre) | 67413 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| `block-accesso-remoto.txt` | Strumenti di accesso remoto (abusati in truffe e ransomware): escludere il proprio RMM | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| `block-ai-generativa.txt` | Chatbot di AI generativa (policy di prevenzione fuga dati) | 17 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| `block-file-sharing.txt` | File sharing puro: trasferimento e hosting di file anonimi (policy di prevenzione fuga dati) | 930 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| `block-cloud-storage.txt` | Archiviazione cloud usata per lavoro (Dropbox, Box, OneDrive personale, pCloud...): solo dove la policy lo chiede | 21 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cloud-storage.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cloud-storage.txt) |
| `block-social.txt` | Social network e piattaforme community (scuole) | 8557 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| `block-gaming.txt` | Giochi online e piattaforme di gaming (scuole) | 23 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |
| `block-doh.txt` | Resolver DNS-over-HTTPS/TLS/QUIC: impediscono il bypass del DNS aziendale | 3246 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-doh.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-doh.txt) |
| `block-vpn.txt` | VPN, proxy e servizi di bypass (scuole) | 13434 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-vpn.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-vpn.txt) |
| `block-porno.txt` | Contenuti per adulti (HaGeZi NSFW + siti che superavano i filtri) | 118558 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-porno.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-porno.txt) |
| `block-tunnel.txt` | Tunnel, esfiltrazione e canali di controllo: ngrok, trycloudflare, webhook, out-of-band, paste (aziende) | 40 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tunnel.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tunnel.txt) |
| `block-compiti.txt` | Risolutori e tutor per i compiti: da attivare durante verifiche ed esami (scuole) | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-compiti.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-compiti.txt) |
| `block-malware.txt` | Malware e minacce confermate (HaGeZi Threat Intelligence mini, TweetFeed, ShadowWhisperer Malware, spmedia Crypto-Scam, uBlock Badware) | 265869 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware.txt) |
| `block-phishing.txt` | Phishing attivo (Phishing.Database, Validin) | 451175 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing.txt) |
| `block-traccianti.txt` | Telemetria e tracciamento (EasyPrivacy, ShadowWhisperer Tracking, Perflyst Smart TV) | 58987 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-traccianti.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-traccianti.txt) |
| `block-ddns.txt` | DNS dinamici (DuckDNS, No-IP, Dynu…): usati da malware e C2, non necessari in azienda e a scuola | 1602 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ddns.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ddns.txt) |
| `block-spyware.txt` | Stalkerware e app spia | 528 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware.txt) |
| `block-cryptojacking.txt` | Mining di criptovalute nel browser | 296 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking.txt) |
| `block-redirect.txt` | Redirect e URL shortener (BlocklistProject) | 120331 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect.txt) |
| `block-pirateria.txt` | Pirateria, warez e streaming illegale | 57386 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pirateria.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pirateria.txt) |
| `block-malware-strict.txt` | Livello strict di block-malware: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 231853 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware-strict.txt) |
| `block-phishing-strict.txt` | Livello strict di block-phishing: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 451171 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing-strict.txt) |
| `block-spyware-strict.txt` | Livello strict di block-spyware: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 528 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware-strict.txt) |
| `block-cryptojacking-strict.txt` | Livello strict di block-cryptojacking: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 296 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking-strict.txt) |
| `block-redirect-strict.txt` | Livello strict di block-redirect: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 112657 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect-strict.txt) |
| `block-pubblicita-strict.txt` | Livello strict di block-pubblicita: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 49808 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita-strict.txt) |
| `block-traccianti-strict.txt` | Livello strict di block-traccianti: solo voci con errore stimato ≤ 0.0200% (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 43228 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-traccianti-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-traccianti-strict.txt) |

## Liste upstream consigliate (abbonamento diretto su AdGuard)

| Lista | Categoria | Licenza | Ambito | Note |
|---|---|---|---|---|
| [HaGeZi Multi PRO](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt) | pubblicità, tracking | GPL-3.0 | tutti | Più ampia di block-pubblicita e block-traccianti (include anche malware e domini di disturbo): usare insieme, senza doppioni |
| [HaGeZi Pop-Up Ads](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt) | pubblicità | GPL-3.0 | tutti |  |
| [HaGeZi Threat Intelligence Feeds](https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt) | malware, phishing | GPL-3.0 | tutti | Versione completa: con questa la nostra block-malware (versione mini) non serve |
| [Phishing URL Blocklist (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt) | phishing | MIT | tutti |  |
| [DurableNapkin Scam](https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt) | truffe | MIT | tutti |  |
| [ShadowWhisperer Malware](https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt) | malware | Unlicense | tutti |  |
| [BlocklistProject Fraud](https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt) | truffe | Unlicense | tutti |  |
| [BlocklistProject Scam](https://blocklistproject.github.io/Lists/adguard/scam-ags.txt) | truffe | Unlicense | tutti |  |
| [BlocklistProject Ransomware](https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt) | ransomware | Unlicense | tutti |  |
| [HaGeZi Spam TLDs](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt) | TLD abusati | GPL-3.0 | tutti |  |
| [HaGeZi Fake](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt) | truffe | GPL-3.0 | tutti |  |
| [HaGeZi DGA 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/dga7.txt) | malware (domini generati) | GPL-3.0 | tutti |  |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | domini registrati da poco | GPL-3.0 | tutti | Circa 3,6 milioni di voci: verificare la RAM di AdGuard |
| [WindowsSpyBlocker spy](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt) | telemetria Windows | MIT | aziende | Provare prima su pochi PC: può interferire con Windows Update e Defender |
| [HaGeZi Gambling](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt) | scommesse | GPL-3.0 | scuole |  |
| [UT1 Université Toulouse Capitole](https://dsi.ut-capitole.fr/blacklists/index_en.php) | categorie per scuole | CC BY-SA 4.0 | scuole | Liste per categoria da scegliere sul sito |
| [HaGeZi Allowlist Referral](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/whitelist-referral.txt) | allowlist (link di affiliazione) | GPL-3.0 | tutti |  |

## Contributo delle fonti

Voci pubblicate che arrivano **solo** da una fonte: misura quanto una lista dipende da ciascuna.

| Lista | Fonte | Voci esclusive | Quota |
|---|---|---|---|
| block-cryptojacking | nocoin | 312 | 100.0% |
| block-ddns | hagezi-dyndns | 151 | 9.4% |
| block-ddns | shadowwhisperer-dynamic | 71 | 4.4% |
| block-doh | dibdot-doh | 162 | 4.6% |
| block-doh | hagezi-doh | 2075 | 59.0% |
| block-doh | manuale | 4 | 0.1% |
| block-doh | shadowwhisperer-dns-domains | 67 | 1.9% |
| block-file-sharing | manuale | 7 | 0.8% |
| block-file-sharing | ut1-filehosting | 916 | 98.4% |
| block-gaming | blocklistproject-fortnite | 5 | 18.5% |
| block-gaming | manuale | 22 | 81.5% |
| block-malware | hagezi-tif-mini | 214752 | 80.5% |
| block-malware | shadowwhisperer-malware-domains | 34174 | 12.8% |
| block-malware | spmedia-crypto-scam | 893 | 0.3% |
| block-malware | tweetfeed-domains | 1396 | 0.5% |
| block-malware | ublock-badware | 685 | 0.3% |
| block-phishing | phishing-database-active | 382987 | 81.4% |
| block-phishing | validin-phish | 83771 | 17.8% |
| block-pirateria | blocklistproject-piracy | 1522 | 2.6% |
| block-pirateria | hagezi-anti-piracy | 54970 | 94.0% |
| block-pirateria | manuale | 586 | 1.0% |
| block-porno | hagezi-nsfw | 78078 | 56.1% |
| block-porno | manuale | 16 | 0.0% |
| block-porno | sinfonietta-pornography | 47171 | 33.9% |
| block-pubblicita | easylist | 47962 | 71.1% |
| block-pubblicita | manuale | 3 | 0.0% |
| block-pubblicita | shadowwhisperer-ads | 17679 | 26.2% |
| block-redirect | blocklistproject-redirect | 108672 | 90.3% |
| block-redirect | hagezi-urlshortener | 5894 | 4.9% |
| block-redirect | peterdavehello-url-shorteners | 42 | 0.0% |
| block-redirect | ut1-shortener | 1772 | 1.5% |
| block-social | blocklistproject-facebook | 22343 | 62.9% |
| block-social | blocklistproject-tiktok | 3710 | 10.5% |
| block-social | blocklistproject-twitter | 1191 | 3.4% |
| block-social | hagezi-social | 8196 | 23.1% |
| block-social | manuale | 6 | 0.0% |
| block-spyware | manuale | 7 | 0.7% |
| block-spyware | stalkerware-indicators | 913 | 97.6% |
| block-traccianti | easyprivacy | 41972 | 70.0% |
| block-traccianti | perflyst-smarttv | 494 | 0.8% |
| block-traccianti | shadowwhisperer-tracking | 16262 | 27.1% |
| block-vpn | hagezi-bypass | 12425 | 92.5% |
| block-vpn | shadowwhisperer-tunnels-domains | 233 | 1.7% |

## Precisione delle fonti

Misurata a ogni build: quota di voci della fonte che colpiscono un falso positivo noto (esclusioni di cura, piattaforme PSL, servizi protetti o allowlist coperti, domini propri; per phishing e redirect anche siti molto visitati). Errore stimato smussato: (falsi positivi + 0.5) / (voci + 1000).

| Fonte | Lista | Voci | Falsi positivi | Precisione | Errore stimato | Esempi |
|---|---|---|---|---|---|---|
| nocoin | block-cryptojacking | 312 | 0 | 100.000% | 0.0381% |  |
| hagezi-dyndns | block-ddns | 1541 | 477 | 69.046% | 18.7918% | 16-b.it, 1cooldns.com, 32-b.it |
| shadowwhisperer-dynamic | block-ddns | 1463 | 436 | 70.198% | 17.7223% | 16-b.it, 1cooldns.com, 32-b.it |
| dibdot-doh | block-doh | 1357 | 4 | 99.705% | 0.1909% | dns.clanto.cloud, eth.link, iij.jp |
| hagezi-doh | block-doh | 3283 | 5 | 99.848% | 0.1284% | digitale-gesellschaft.ch, dns.clanto.cloud, eth.link |
| shadowwhisperer-dns-domains | block-doh | 146 | 7 | 95.205% | 0.6544% | adguard.com, adguard.io, digitale-gesellschaft.ch |
| ut1-filehosting | block-file-sharing | 940 | 12 | 98.723% | 0.6443% | 1und1.de, alamy.com, behance.net |
| blocklistproject-fortnite | block-gaming | 5 | 0 | 100.000% | 0.0498% |  |
| hagezi-tif-mini | block-malware | 229609 | 3 | 99.999% | 0.0015% | ludashisafe.com, rustdesk.io, wps-cn.com |
| shadowwhisperer-malware-domains | block-malware | 46344 | 45 | 99.903% | 0.0961% | 17173.com, akamaized.ca, amplifyapp.com |
| spmedia-crypto-scam | block-malware | 1480 | 0 | 100.000% | 0.0202% |  |
| tweetfeed-domains | block-malware | 1464 | 0 | 100.000% | 0.0203% |  |
| ublock-badware | block-malware | 2855 | 2 | 99.930% | 0.0649% | 3utilities.com, rustdesk.io |
| phishing-database-active | block-phishing | 386593 | 55 | 99.986% | 0.0143% | amazon.ie, amazonlogistics.eu, angelfire.com |
| validin-phish | block-phishing | 87325 | 2 | 99.998% | 0.0028% | jp-bank.japanpost.jp, on-fleek.app |
| blocklistproject-piracy | block-pirateria | 2154 | 2 | 99.907% | 0.0793% | kinguin.net, www.kinguin.net |
| hagezi-anti-piracy | block-pirateria | 56390 | 1 | 99.998% | 0.0026% | fandango.com |
| hagezi-nsfw | block-porno | 92021 | 26 | 99.972% | 0.0285% | 1337x.org, 3sktv.beauty, allmanga.to |
| sinfonietta-pornography | block-porno | 61154 | 66 | 99.892% | 0.1070% | 1337x.to, aletorrenty.pl, anidex.info |
| easylist | block-pubblicita | 49817 | 4 | 99.992% | 0.0089% | agenteimmobiliare.info, gvt2.com, imasdk.googleapis.com |
| shadowwhisperer-ads | block-pubblicita | 19571 | 41 | 99.791% | 0.2017% | aboutads.info, ad.nl, adage.com |
| blocklistproject-redirect | block-redirect | 108685 | 6 | 99.994% | 0.0059% | kicks-ass.net, name.com, operaprima.info |
| hagezi-urlshortener | block-redirect | 9904 | 13 | 99.869% | 0.1238% | bit.ly, cdl.booksy.com, dy.fi |
| peterdavehello-url-shorteners | block-redirect | 1454 | 7 | 99.519% | 0.3056% | bit.ly, cdl.booksy.com, dy.fi |
| ut1-shortener | block-redirect | 4562 | 7 | 99.847% | 0.1348% | bit.ly, dy.fi, eepurl.com |
| blocklistproject-facebook | block-social | 22362 | 1 | 99.996% | 0.0064% | apps.fbsbx.com |
| blocklistproject-tiktok | block-social | 3725 | 0 | 100.000% | 0.0106% |  |
| blocklistproject-twitter | block-social | 1193 | 0 | 100.000% | 0.0228% |  |
| hagezi-social | block-social | 8245 | 3 | 99.964% | 0.0379% | discordsays.com, mail.ru, nog.community |
| stalkerware-indicators | block-spyware | 928 | 0 | 100.000% | 0.0259% |  |
| easyprivacy | block-traccianti | 43234 | 8 | 99.981% | 0.0192% | data.diagnostics.office.com, fp.measure.office.com, go.tinder.com |
| perflyst-smarttv | block-traccianti | 498 | 4 | 99.197% | 0.3004% | osb-apps-v2.samsungqbe.com, samsungcloudsolution.com, samsungelectronics.com |
| shadowwhisperer-tracking | block-traccianti | 17630 | 115 | 99.348% | 0.6200% | adobedtm.com, agora.io, ahrefs.com |
| hagezi-bypass | block-vpn | 16270 | 26 | 99.840% | 0.1534% | adguard.io, digitale-gesellschaft.ch, dns.clanto.cloud |
| shadowwhisperer-tunnels-domains | block-vpn | 1025 | 17 | 98.341% | 0.8642% | checkpoint.com, fortinet.com, fortinet.net |

## Livello strict

Stesse liste con le sole voci a errore stimato basso. Errore di una voce = prodotto degli errori delle fonti che la contengono × (1 − 0.5 × persistenza), persistenza piena dopo 24 ore; voci manuali 0. Soglia = la maggiore tra errore massimo della categoria ed errore della fonte migliore della lista (con una sola fonte lo strict coincide con la lista completa, meno siti popolari e voci nuove). Una voce già nello strict esce oltre 1.5 × soglia.

| Lista | Soglia | Voci complete | Voci strict | Quota |
|---|---|---|---|---|
| block-malware | 0.0200% | 265869 | 231853 | 87.2% |
| block-phishing | 0.0200% | 451175 | 451171 | 100.0% |
| block-spyware | 0.0200% | 528 | 528 | 100.0% |
| block-cryptojacking | 0.0200% | 296 | 296 | 100.0% |
| block-redirect | 0.0200% | 120331 | 112657 | 93.6% |
| block-pubblicita | 0.0200% | 67413 | 49808 | 73.9% |
| block-traccianti | 0.0200% | 58987 | 43228 | 73.3% |

Pubblicato sotto GPL-3.0.
