"""Reti per AS dal database iptoasn.com (licenza PDDL 1.0, pubblico dominio).

Usato per escludere CDN/hosting condivisi ([[shared_sources]] con format = "asn"), per i feed costruiti
per AS (es. social) e per il controllo settimanale delle liste OPNsense.
Il database viene scaricato una volta per esecuzione e tenuto in memoria.
"""
from __future__ import annotations

import gzip
import ipaddress
import urllib.request

IPTOASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
USER_AGENT = "clanto-dns-ip-builder/1.0 (+https://github.com/clanto/DNS)"
MAX_BYTES = 50 * 1024 * 1024

_rows: list[tuple[int, int, int, int, str]] | None = None  # (versione, inizio, fine, asn, descrizione)


def download_raw() -> bytes:
    req = urllib.request.Request(IPTOASN_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("database iptoasn oltre 50 MB")
    return data


def rows() -> list[tuple[int, int, int, int, str]]:
    global _rows
    if _rows is None:
        parsed = []
        for line in gzip.decompress(download_raw()).decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 5 or parts[2] == "0":
                continue
            start, end = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
            parsed.append((start.version, int(start), int(end), int(parts[2]), parts[4]))
        if not parsed:
            raise ValueError("database iptoasn vuoto")
        _rows = parsed
    return _rows


def networks(asns: list[int]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Tutte le reti annunciate dagli AS indicati, accorpate."""
    wanted = set(asns)
    nets = []
    for version, start, end, asn, _ in rows():
        if asn in wanted:
            cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
            nets += ipaddress.summarize_address_range(cls(start), cls(end))
    return [n for v in (4, 6) for n in ipaddress.collapse_addresses(x for x in nets if x.version == v)]


def names(asns: list[int]) -> dict[int, str]:
    wanted = set(asns)
    return {asn: desc for _, _, _, asn, desc in rows() if asn in wanted}
