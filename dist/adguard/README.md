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
| `block-pubblicita.txt` | Pubblicità: reti pubblicitarie e ad server (EasyList, ShadowWhisperer Ads + voci nostre) | 64653 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita.txt) |
| `block-accesso-remoto.txt` | Strumenti di accesso remoto (abusati in truffe e ransomware): escludere il proprio RMM | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-accesso-remoto.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-accesso-remoto.txt) |
| `block-ai-generativa.txt` | Chatbot di AI generativa (policy di prevenzione fuga dati) | 17 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ai-generativa.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ai-generativa.txt) |
| `block-file-sharing.txt` | File sharing e trasferimento file anonimi (policy di prevenzione fuga dati) | 15 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-file-sharing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-file-sharing.txt) |
| `block-social.txt` | Social network e piattaforme community (scuole) | 421 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-social.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-social.txt) |
| `block-gaming.txt` | Giochi online e piattaforme di gaming (scuole) | 23 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-gaming.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-gaming.txt) |
| `block-doh.txt` | Resolver DNS-over-HTTPS/TLS/QUIC: impediscono il bypass del DNS aziendale | 3248 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-doh.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-doh.txt) |
| `block-vpn.txt` | VPN, proxy e servizi di bypass (scuole) | 12833 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-vpn.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-vpn.txt) |
| `block-porno.txt` | Contenuti per adulti (HaGeZi NSFW + siti che superavano i filtri) | 87306 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-porno.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-porno.txt) |
| `block-tunnel.txt` | Tunnel, esfiltrazione e canali di controllo: ngrok, trycloudflare, webhook, out-of-band, paste (aziende) | 40 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-tunnel.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-tunnel.txt) |
| `block-compiti.txt` | Risolutori e tutor per i compiti: da attivare durante verifiche ed esami (scuole) | 18 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-compiti.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-compiti.txt) |
| `block-malware.txt` | Malware e minacce confermate (HaGeZi Threat Intelligence mini, TweetFeed, ShadowWhisperer Malware, spmedia Crypto-Scam, uBlock Badware) | 275900 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware.txt) |
| `block-phishing.txt` | Phishing attivo (Phishing.Database, Validin) | 451177 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing.txt) |
| `block-traccianti.txt` | Telemetria e tracciamento (EasyPrivacy, ShadowWhisperer Tracking, Perflyst Smart TV) | 58931 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-traccianti.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-traccianti.txt) |
| `block-ddns.txt` | DNS dinamici (DuckDNS, No-IP, Dynu…): usati da malware e C2, non necessari in azienda e a scuola | 1602 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-ddns.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-ddns.txt) |
| `block-spyware.txt` | Stalkerware e app spia | 528 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware.txt) |
| `block-cryptojacking.txt` | Mining di criptovalute nel browser | 296 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking.txt) |
| `block-redirect.txt` | Redirect e URL shortener (BlocklistProject) | 108676 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect.txt) |
| `block-pirateria.txt` | Pirateria, warez e streaming illegale | 55497 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pirateria.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pirateria.txt) |
| `block-malware-strict.txt` | Livello strict di block-malware: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 240025 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-malware-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-malware-strict.txt) |
| `block-phishing-strict.txt` | Livello strict di block-phishing: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 451173 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-phishing-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-phishing-strict.txt) |
| `block-spyware-strict.txt` | Livello strict di block-spyware: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 528 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-spyware-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-spyware-strict.txt) |
| `block-cryptojacking-strict.txt` | Livello strict di block-cryptojacking: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 296 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-cryptojacking-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-cryptojacking-strict.txt) |
| `block-redirect-strict.txt` | Livello strict di block-redirect: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 108674 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-redirect-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-redirect-strict.txt) |
| `block-pubblicita-strict.txt` | Livello strict di block-pubblicita: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 46854 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-pubblicita-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-pubblicita-strict.txt) |
| `block-traccianti-strict.txt` | Livello strict di block-traccianti: solo voci con punteggio ≥ 86 (fonti affidabili e persistenti, voci manuali), per aziende e scuole | 43192 | [adguard](https://raw.githubusercontent.com/clanto/DNS/main/dist/adguard/block-traccianti-strict.txt) | [domini](https://raw.githubusercontent.com/clanto/DNS/main/dist/domains/block-traccianti-strict.txt) |

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
| [URLhaus (malware-filter)](https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt) | malware | Termini abuse.ch | tutti | Per l'uso commerciale i termini abuse.ch possono richiedere un abbonamento |
| [HaGeZi Spam TLDs](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds-adblock.txt) | TLD abusati | GPL-3.0 | tutti |  |
| [HaGeZi Fake](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt) | truffe | GPL-3.0 | tutti |  |
| [HaGeZi DGA 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/dga7.txt) | malware (domini generati) | GPL-3.0 | tutti |  |
| [HaGeZi NRD 7 giorni](https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt) | domini registrati da poco | GPL-3.0 | tutti | Circa 3,6 milioni di voci: verificare la RAM di AdGuard |
| [Frogeye first-party trackers](https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt) | tracker CNAME cloaking | MIT | tutti |  |
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
| block-ddns | shadowwhisperer-dynamic | 77 | 4.8% |
| block-doh | dibdot-doh | 166 | 4.7% |
| block-doh | hagezi-doh | 2066 | 58.8% |
| block-doh | manuale | 4 | 0.1% |
| block-doh | shadowwhisperer-dns-domains | 67 | 1.9% |
| block-gaming | blocklistproject-fortnite | 5 | 18.5% |
| block-gaming | manuale | 22 | 81.5% |
| block-malware | hagezi-tif-mini | 224843 | 81.2% |
| block-malware | shadowwhisperer-malware-domains | 34066 | 12.3% |
| block-malware | spmedia-crypto-scam | 907 | 0.3% |
| block-malware | tweetfeed-domains | 1280 | 0.5% |
| block-malware | ublock-badware | 683 | 0.2% |
| block-phishing | phishing-database-active | 382987 | 81.4% |
| block-phishing | validin-phish | 83773 | 17.8% |
| block-pirateria | hagezi-anti-piracy | 54097 | 97.5% |
| block-pirateria | manuale | 596 | 1.1% |
| block-porno | hagezi-nsfw | 87281 | 99.9% |
| block-porno | manuale | 34 | 0.0% |
| block-pubblicita | easylist | 45276 | 69.9% |
| block-pubblicita | manuale | 3 | 0.0% |
| block-pubblicita | shadowwhisperer-ads | 17628 | 27.2% |
| block-redirect | blocklistproject-redirect | 108680 | 100.0% |
| block-social | blocklistproject-facebook | 22358 | 81.9% |
| block-social | blocklistproject-tiktok | 3722 | 13.6% |
| block-social | blocklistproject-twitter | 1191 | 4.4% |
| block-social | manuale | 18 | 0.1% |
| block-spyware | manuale | 7 | 0.7% |
| block-spyware | stalkerware-indicators | 913 | 97.6% |
| block-traccianti | easyprivacy | 41946 | 70.0% |
| block-traccianti | perflyst-smarttv | 494 | 0.8% |
| block-traccianti | shadowwhisperer-tracking | 16232 | 27.1% |
| block-vpn | hagezi-bypass | 11824 | 92.1% |
| block-vpn | shadowwhisperer-tunnels-domains | 220 | 1.7% |

## Precisione delle fonti

Misurata a ogni build: quota di voci della fonte che colpiscono un falso positivo noto (esclusioni di cura, piattaforme PSL, servizi protetti o allowlist coperti, domini propri). Il peso entra nel punteggio delle voci: peso = 0.8 × (1 − 100 × quota), minimo 0.1.

| Fonte | Lista | Voci | Falsi positivi | Precisione | Peso | Esempi |
|---|---|---|---|---|---|---|
| nocoin | block-cryptojacking | 312 | 0 | 100.000% | 0.80 |  |
| hagezi-dyndns | block-ddns | 1535 | 477 | 68.925% | 0.10 | 16-b.it, 1cooldns.com, 32-b.it |
| shadowwhisperer-dynamic | block-ddns | 1463 | 436 | 70.198% | 0.10 | 16-b.it, 1cooldns.com, 32-b.it |
| dibdot-doh | block-doh | 1363 | 4 | 99.707% | 0.55 | dns.clanto.cloud, eth.link, iij.jp |
| hagezi-doh | block-doh | 3276 | 5 | 99.847% | 0.70 | digitale-gesellschaft.ch, dns.clanto.cloud, eth.link |
| shadowwhisperer-dns-domains | block-doh | 146 | 7 | 95.205% | 0.10 | adguard.com, adguard.io, digitale-gesellschaft.ch |
| blocklistproject-fortnite | block-gaming | 5 | 0 | 100.000% | 0.80 |  |
| hagezi-tif-mini | block-malware | 239878 | 3 | 99.999% | 0.80 | ludashisafe.com, rustdesk.io, wps-cn.com |
| shadowwhisperer-malware-domains | block-malware | 46293 | 45 | 99.903% | 0.70 | 17173.com, akamaized.ca, amplifyapp.com |
| spmedia-crypto-scam | block-malware | 1473 | 0 | 100.000% | 0.80 |  |
| tweetfeed-domains | block-malware | 1492 | 0 | 100.000% | 0.80 |  |
| ublock-badware | block-malware | 2850 | 2 | 99.930% | 0.75 | 3utilities.com, rustdesk.io |
| phishing-database-active | block-phishing | 386593 | 55 | 99.986% | 0.80 | amazon.ie, amazonlogistics.eu, angelfire.com |
| validin-phish | block-phishing | 87327 | 2 | 99.998% | 0.80 | jp-bank.japanpost.jp, on-fleek.app |
| hagezi-anti-piracy | block-pirateria | 54910 | 1 | 99.998% | 0.80 | fandango.com |
| hagezi-nsfw | block-porno | 87298 | 0 | 100.000% | 0.80 |  |
| easylist | block-pubblicita | 47107 | 4 | 99.992% | 0.80 | agenteimmobiliare.info, gvt2.com, imasdk.googleapis.com |
| shadowwhisperer-ads | block-pubblicita | 19496 | 41 | 99.790% | 0.65 | aboutads.info, ad.nl, adage.com |
| blocklistproject-redirect | block-redirect | 108685 | 6 | 99.994% | 0.80 | kicks-ass.net, name.com, operaprima.info |
| blocklistproject-facebook | block-social | 22362 | 1 | 99.996% | 0.80 | apps.fbsbx.com |
| blocklistproject-tiktok | block-social | 3725 | 0 | 100.000% | 0.80 |  |
| blocklistproject-twitter | block-social | 1193 | 0 | 100.000% | 0.80 |  |
| stalkerware-indicators | block-spyware | 928 | 0 | 100.000% | 0.80 |  |
| easyprivacy | block-traccianti | 43206 | 7 | 99.984% | 0.80 | data.diagnostics.office.com, fp.measure.office.com, mato.clanto.cloud |
| perflyst-smarttv | block-traccianti | 498 | 4 | 99.197% | 0.15 | osb-apps-v2.samsungqbe.com, samsungcloudsolution.com, samsungelectronics.com |
| shadowwhisperer-tracking | block-traccianti | 17599 | 115 | 99.347% | 0.30 | adobedtm.com, agora.io, ahrefs.com |
| hagezi-bypass | block-vpn | 15675 | 26 | 99.834% | 0.65 | adguard.io, digitale-gesellschaft.ch, dns.clanto.cloud |
| shadowwhisperer-tunnels-domains | block-vpn | 1025 | 17 | 98.341% | 0.10 | checkpoint.com, fortinet.com, fortinet.net |

## Livello strict

Stesse liste con le sole voci a punteggio alto: meno voci, meno falsi positivi. Punteggio = 100 × (1 − Π(1 − peso fonte) × (1 − 0.5 × persistenza)), persistenza piena dopo 24 ore di presenza continuativa; voci manuali sempre 100.

| Lista | Soglia | Voci complete | Voci strict | Quota |
|---|---|---|---|---|
| block-malware | 86 | 275900 | 240025 | 87.0% |
| block-phishing | 86 | 451177 | 451173 | 100.0% |
| block-spyware | 86 | 528 | 528 | 100.0% |
| block-cryptojacking | 86 | 296 | 296 | 100.0% |
| block-redirect | 86 | 108676 | 108674 | 100.0% |
| block-pubblicita | 86 | 64653 | 46854 | 72.5% |
| block-traccianti | 86 | 58931 | 43192 | 73.3% |

Pubblicato sotto GPL-3.0.
