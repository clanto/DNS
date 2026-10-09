"""Reti per AS dal database iptoasn.com (licenza PDDL 1.0, pubblico dominio).

Usato per escludere CDN/hosting condivisi ([[shared_sources]] con format = "asn"), per i feed costruiti
per AS (es. social) e per il controllo settimanale delle liste OPNsense.
Il database viene scaricato una volta per esecuzione e tenuto in memoria.
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

IPTOASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
USER_AGENT = "clanto-dns-ip-builder/1.0 (+https://github.com/clanto/DNS)"
MAX_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # contro le gzip bomb: il database decompresso è ~50 MB

_rows: list[tuple[int, int, int, int, str]] | None = None  # (versione, inizio, fine, asn, descrizione)


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Segue i redirect solo verso HTTPS: un downgrade a HTTP renderebbe la fonte manomettibile in transito."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError("redirect verso un URL non HTTPS rifiutato")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect)


def read_https(url: str, *, timeout: float, limit: int) -> bytes:
    """Scarica al massimo limit byte da un URL HTTPS (certificato verificato, redirect solo HTTPS)."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("solo URL HTTPS")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with _OPENER.open(req, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"download oltre {limit // (1024 * 1024)} MB")
    return data


def gunzip(data: bytes, limit: int = MAX_UNCOMPRESSED_BYTES) -> bytes:
    """Decompressione gzip con limite sulla dimensione in uscita."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
        out = fh.read(limit + 1)
    if len(out) > limit:
        raise ValueError(f"contenuto decompresso oltre {limit // (1024 * 1024)} MB")
    return out


def download_raw() -> bytes:
    return read_https(IPTOASN_URL, timeout=120, limit=MAX_BYTES)


def _ip_int(text: str) -> tuple[int, int]:
    """(versione, intero) di un indirizzo IP: inet_pton è molto più veloce di ipaddress su ~10^6 righe."""
    family, version = (socket.AF_INET6, 6) if ":" in text else (socket.AF_INET, 4)
    return version, int.from_bytes(socket.inet_pton(family, text), "big")


def rows() -> list[tuple[int, int, int, int, str]]:
    global _rows
    if _rows is None:
        parsed = []
        for line in gunzip(download_raw()).decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) < 5 or parts[2] == "0":
                continue
            try:
                (version, start), (_, end) = _ip_int(parts[0]), _ip_int(parts[1])
            except OSError:  # indirizzo malformato
                continue
            parsed.append((version, start, end, int(parts[2]), parts[4]))
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
