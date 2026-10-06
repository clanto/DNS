# Liste FQDN per alias OPNsense

> File generato da `scripts/build_opnsense.py`: **non modificare a mano**.

OPNsense risolve ogni dominio dell'alias e blocca gli IP ottenuti, quindi segue anche gli anycast.
Rispetto alle liste AdGuard sono esclusi i domini morti, quelli su IP non instradabili e quelli
su IP di CDN condivise (Cloudflare, CloudFront, Fastly), che bloccherebbero anche siti legittimi.

| Lista | Descrizione | Pubblicati | Morti | CDN condivise | Totale AdGuard |
|---|---|---|---|---|---|
| [doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/doh.txt) | Resolver DNS-over-HTTPS/TLS/QUIC: impediscono il bypass del DNS aziendale | 2675 | 361 | 281 | 3317 |
| [vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/vpn.txt) | VPN, proxy e servizi di bypass (scuole) | 5936 | 2587 | 4523 | 13046 |
