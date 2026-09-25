# Feed IP per firewall

> File generato da `scripts/build_ip.py`: **non modificare a mano**.
> Fonti in [`ip/sources.toml`](../../ip/sources.toml), voci manuali in [`ip/custom/`](../../ip/custom/),
> esclusioni in [`ip/allowlist.txt`](../../ip/allowlist.txt).

## Feed

| Feed | Descrizione | IPv4 | IPv6 |
|---|---|---|---|
| `all` | Aggregato: doh, tor, threat, c2, hacking, warez | [31698](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v4.txt) | [1109](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/all-v6.txt) |
| `doh` | Resolver DNS-over-HTTPS/TLS pubblici: impediscono il bypass del DNS aziendale | [1966](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v4.txt) | [1109](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/doh-v6.txt) |
| `tor` | Nodi di uscita della rete Tor | [796](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/tor-v6.txt) |
| `threat` | IP malevoli attivi (scanner, brute force, attacchi) segnalati da più blacklist | [28990](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/threat-v6.txt) |
| `inbound` | IP che attaccano servizi esposti (scanner, brute force): SOLO in ingresso WAN → LAN | [85678](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/inbound-v6.txt) |
| `c2` | Server di comando e controllo di botnet e malware | [5](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/c2-v6.txt) |
| `vpn` | VPN commerciali e proxy anonimizzanti | [11576](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v4.txt) | [414](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/vpn-v6.txt) |
| `hacking` | IP di siti hacking (curati manualmente) | [73](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/hacking-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/hacking-v6.txt) |
| `warez` | IP di siti warez (curati manualmente) | [22](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/warez-v4.txt) | [0](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/warez-v6.txt) |
| `bogon` | Reti riservate/private (RFC 6890): SOLO in ingresso su interfacce WAN, mai su LAN | [14](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v4.txt) | [12](https://raw.githubusercontent.com/clanto/DNS/main/dist/ip/bogon-v6.txt) |

## Fonti

| ID | Categoria | Licenza | Stato | Voci | Note |
|---|---|---|---|---|---|
| [dibdot-doh-v4](https://github.com/dibdot/DoH-IP-blocklists) | doh | GPL-3.0 | ok | 1973 | scartate 1 non instradabile |
| [dibdot-doh-v6](https://github.com/dibdot/DoH-IP-blocklists) | doh | GPL-3.0 | ok | 1370 | scartate 1 non instradabile |
| [tor-exit](https://metrics.torproject.org/) | tor | CC0 (Tor Metrics) | ok | 1375 |  |
| [ipsum-level3](https://github.com/stamparm/ipsum) | threat | Unlicense | ok | 19040 | IP presenti in almeno 3 blacklist pubbliche |
| [shadowwhisperer-threats](https://github.com/ShadowWhisperer/IPs) | threat | Unlicense | ok | 17508 | Honeypot propri: exploit, sistemi compromessi, dropper |
| [shadowwhisperer-dns](https://github.com/ShadowWhisperer/IPs) | doh | Unlicense | ok | 183 | Resolver DNS pubblici |
| [shadowwhisperer-tunnels](https://github.com/ShadowWhisperer/IPs) | vpn | Unlicense | ok | 13138 | scartate 1 non instradabile |
| [data-shield](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist) | inbound | GPL-3.0 | ok | 95108 | Sonde e SIEM propri, non aggregatore |
| [abusech-feodo](https://feodotracker.abuse.ch/blocklist/) | c2 | CC0 | ok | 5 | CC0 dichiarato sulla pagina Feodo Tracker (regime diverso dai ToS generali abuse.ch) |
| [x4b-vpn-v4](https://github.com/X4BNet/lists_vpn) | vpn | MIT | ok | 10989 |  |
| [x4b-vpn-v6](https://github.com/X4BNet/lists_vpn) | vpn | MIT | ok | 414 | scartate 84 troppo ampia |
| [et-compromised](https://rules.emergingthreats.net/) | threat | ET Open (BSD/GPLv2, file non etichettato) | disattivata | 0 | Chiarire con Proofpoint quale licenza copre il file |
| [cins-badguys](https://cinsscore.com/) | threat | Non pubblicata | disattivata | 0 | Serve contatto con CINS |
| [blocklist-de](https://www.blocklist.de/) | threat | Non esplicita | disattivata | 0 | Serve contatto con blocklist.de |

## Voci manuali

| Categoria | Attive | Scadute |
|---|---|---|
| bogon | 29 | 0 |
| doh | 336 | 0 |
| hacking | 77 | 0 |
| warez | 22 | 0 |

Pubblicato sotto GPL-3.0. Attribuzioni: vedi tabella Fonti.
