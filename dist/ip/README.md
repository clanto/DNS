# Feed IP per firewall

> File generato da `scripts/build_ip.py`: **non modificare a mano**.
> Fonti in [`ip/sources.toml`](../../ip/sources.toml), voci manuali in [`ip/custom/`](../../ip/custom/),
> esclusioni in [`ip/allowlist.txt`](../../ip/allowlist.txt).

## Feed

| Feed | Descrizione | IPv4 | IPv6 |
|---|---|---|---|
| `all` | Aziende: uscita e ingresso — aggregato: doh, tor, threat, c2 | [33789](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v4.txt) | [3126](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v6.txt) |
| `all-scuole` | Scuole: come all, più VPN commerciali e proxy — aggregato: doh, tor, threat, c2, vpn | [42409](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-scuole-v4.txt) | [3487](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-scuole-v6.txt) |
| `doh` | Resolver DNS-over-HTTPS/TLS pubblici: impediscono il bypass del DNS aziendale | [1328](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v4.txt) | [696](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v6.txt) |
| `tor` | Rete Tor: nodi di uscita e relay (blocca sia gli attacchi da Tor sia l'uso di Tor Browser) | [5138](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v4.txt) | [2430](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v6.txt) |
| `threat` | IP malevoli attivi (scanner, brute force, attacchi) segnalati da più blacklist | [27035](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v6.txt) |
| `c2` | Server di comando e controllo di botnet e malware | [463](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v6.txt) |
| `vpn` | VPN commerciali e proxy anonimizzanti | [9107](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v4.txt) | [414](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v6.txt) |
| `social` | Social network e messaggistica per AS: Meta (Facebook, Instagram, WhatsApp), TikTok, X, Telegram | [211](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/social-v4.txt) | [119](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/social-v6.txt) |
| `inbound` | IP che attaccano servizi esposti (scanner, brute force): SOLO in ingresso WAN → LAN | [77733](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v6.txt) |
| `bogon` | Reti riservate/private (RFC 6890): SOLO in ingresso su interfacce WAN, mai su LAN | [14](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v4.txt) | [11](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v6.txt) |

## Fonti

| ID | Categoria | Licenza | Stato | Voci | Note |
|---|---|---|---|---|---|
| [dibdot-doh-v4](https://github.com/dibdot/DoH-IP-blocklists) | doh | GPL-3.0 | ok | 1968 | scartate 1 non instradabile |
| [dibdot-doh-v6](https://github.com/dibdot/DoH-IP-blocklists) | doh | GPL-3.0 | ok | 1385 | scartate 1 non instradabile |
| [tor-exit](https://metrics.torproject.org/) | tor | CC0 (Tor Metrics) | ok | 1206 |  |
| [tor-relay](https://metrics.torproject.org/onionoo.html) | tor | CC0 (Tor Metrics) | ok | 9646 | Tutti i relay attivi (guard, middle, exit) |
| [ipsum-level3](https://github.com/stamparm/ipsum) | threat | Unlicense | ok | 18526 | IP presenti in almeno 3 blacklist pubbliche |
| [shadowwhisperer-threats](https://github.com/ShadowWhisperer/IPs) | threat | Unlicense | ok | 16750 | Honeypot propri: exploit, sistemi compromessi, dropper |
| [shadowwhisperer-dns](https://github.com/ShadowWhisperer/IPs) | doh | Unlicense | ok | 183 | Resolver DNS pubblici |
| [shadowwhisperer-tunnels](https://github.com/ShadowWhisperer/IPs) | vpn | Unlicense | ok | 13138 | scartate 1 non instradabile |
| [data-shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | inbound | GPL-3.0 | ok | 88418 | Sonde e SIEM propri, non aggregatore |
| [social-meta](https://iptoasn.com/) | social | PDDL 1.0 (iptoasn.com) | ok | 120 | Meta: Facebook, Instagram, WhatsApp, Threads |
| [social-tiktok](https://iptoasn.com/) | social | PDDL 1.0 (iptoasn.com) | ok | 181 | ByteDance e TikTok (i contenuti video passano anche da CDN condivise: bloccare anche via DNS) |
| [social-x](https://iptoasn.com/) | social | PDDL 1.0 (iptoasn.com) | ok | 17 | X (Twitter) |
| [social-telegram](https://iptoasn.com/) | social | PDDL 1.0 (iptoasn.com) | ok | 12 | Telegram |
| [tweetfeed-ip](https://github.com/0xDanielLopez/TweetFeed) | c2 | CC0-1.0 | ok | 466 | IoC degli ultimi 30 giorni condivisi da ricercatori di sicurezza |
| [abusech-feodo](https://feodotracker.abuse.ch/blocklist/) | c2 | CC0 | ok | 5 | CC0 dichiarato sulla pagina Feodo Tracker (regime diverso dai ToS generali abuse.ch) |
| [x4b-vpn-v4](https://github.com/X4BNet/lists_vpn) | vpn | MIT | ok | 11054 |  |
| [x4b-vpn-v6](https://github.com/X4BNet/lists_vpn) | vpn | MIT | ok | 414 | scartate 84 troppo ampia |

## Voci manuali

| Categoria | Attive | Scadute |
|---|---|---|
| bogon | 28 | 0 |
| c2 | 0 | 0 |
| doh | 5 | 0 |

Pubblicato sotto GPL-3.0. Attribuzioni: vedi tabella Fonti.
