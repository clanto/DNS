# Liste FQDN per alias OPNsense

> File generato da `scripts/build_opnsense.py`: **non modificare a mano**.

OPNsense risolve ogni dominio dell'alias e blocca gli IP ottenuti, quindi segue anche gli anycast.
Rispetto alle liste AdGuard sono esclusi i domini morti, quelli su IP non instradabili e quelli
su IP di CDN/hosting condivisi (Cloudflare, AWS, Fastly, Vercel…), che bloccherebbero anche siti legittimi.

| Lista | Descrizione | Pubblicati | Morti | CDN condivise | Totale AdGuard |
|---|---|---|---|---|---|
| [file-sharing.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/file-sharing.txt) | File sharing puro: trasferimento e hosting di file anonimi (policy di prevenzione fuga dati) | 424 | 248 | 259 | 931 |
| [doh.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/doh.txt) | Resolver DNS-over-HTTPS/TLS/QUIC: impediscono il bypass del DNS aziendale | 2819 | 350 | 344 | 3513 |
| [vpn.txt](https://raw.githubusercontent.com/clanto/DNS/main/dist/opnsense/vpn.txt) | VPN, proxy e servizi di bypass (scuole) | 5258 | 2441 | 5086 | 12785 |
