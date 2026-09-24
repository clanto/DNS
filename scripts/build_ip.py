#!/usr/bin/env python3
"""Genera i feed IP per i firewall da fonti upstream (ip/sources.toml) e liste manuali (ip/custom/).

Uso:
  python scripts/build_ip.py              build completo (download + scrittura dist/ip)
  python scripts/build_ip.py --offline    build dalla cache, senza rete
  python scripts/build_ip.py --check      valida config e liste manuali, nessuna scrittura (CI su PR)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tomllib
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IP_DIR = ROOT / "ip"
CONFIG_PATH = IP_DIR / "sources.toml"
CUSTOM_DIR = IP_DIR / "custom"
ALLOWLIST_PATH = IP_DIR / "allowlist.txt"
CACHE_DIR = IP_DIR / "cache"
DIST_DIR = ROOT / "dist" / "ip"
RAW_BASE = "https://raw.githubusercontent.com/clanto/DNS/main"
USER_AGENT = "clanto-dns-ip-builder/1.0 (+https://github.com/clanto/DNS)"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
FAMILIES = (4, 6)

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TICKET_RE = re.compile(r"^[A-Za-z0-9#._/-]{1,40}$")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
PHONE_RE = re.compile(r"\+?\d[\d /-]{7,}\d")
IN_GHA = os.environ.get("GITHUB_ACTIONS") == "true"

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Entry:
    net: Network
    added: str
    reason: str
    ticket: str
    expires: str
    origin: str


@dataclass
class SourceResult:
    id: str
    category: str
    license: str
    homepage: str
    enabled: bool
    status: str
    entries: int
    detail: str = ""


def warn(msg: str) -> None:
    print(f"::warning::{msg}" if IN_GHA else f"ATTENZIONE: {msg}", file=sys.stderr)


def fail(msg: str) -> None:
    print(f"::error::{msg}" if IN_GHA else f"ERRORE: {msg}", file=sys.stderr)


def sort_key(net: Network) -> tuple[int, int, int]:
    return net.version, int(net.network_address), net.prefixlen


def fmt(net: Network) -> str:
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def parse_token(token: str) -> list[Network]:
    """Accetta IP singolo, CIDR o intervallo 'a-b'."""
    if "-" in token and "/" not in token:
        start, end = (ipaddress.ip_address(p.strip()) for p in token.split("-", 1))
        return list(ipaddress.summarize_address_range(start, end))
    return [ipaddress.ip_network(token, strict=False)]


def reject_reason(net: Network, min_prefix: dict[int, int]) -> str | None:
    if (net.is_private or net.is_multicast or net.is_reserved or net.is_loopback
            or net.is_link_local or net.is_unspecified or not net.is_global):
        return "non instradabile"
    if net.prefixlen < min_prefix[net.version]:
        return "troppo ampia"
    return None


def parse_source_text(text: str, min_prefix: dict[int, int] | None) -> tuple[set[Network], Counter]:
    """Estrae le reti da liste plain, hosts, 'IP # commento', 'CIDR ; SBL' e JSON per riga.

    min_prefix None = nessun filtro (categorie con reti riservate, es. bogon).
    """
    nets: set[Network] = set()
    rejected: Counter = Counter()
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line[0] in "#;!":
            continue
        if line.startswith("{"):
            try:
                token = json.loads(line).get("cidr")
            except json.JSONDecodeError:
                token = None
            if not token:
                continue
        else:
            token = re.split(r"[#;\s,]", line, maxsplit=1)[0]
        try:
            parsed = parse_token(token)
        except (ValueError, TypeError):
            rejected["non valida"] += 1
            continue
        for net in parsed:
            reason = reject_reason(net, min_prefix) if min_prefix is not None else None
            if reason:
                rejected[reason] += 1
            else:
                nets.add(net)
    return nets, rejected


def valid_date(value: str) -> bool:
    if not DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def contains_pii(text: str) -> bool:
    if EMAIL_RE.search(text):
        return True
    return any(sum(c.isdigit() for c in m.group()) >= 9 for m in PHONE_RE.finditer(text))


def load_annotated(path: Path, *, min_prefix: dict[int, int] | None, today: date,
                   errors: list[str]) -> tuple[list[Entry], int]:
    """Legge un file 'IP | data | motivo | ticket | scadenza'. Restituisce (voci attive, voci scadute)."""
    entries: list[Entry] = []
    seen: dict[Network, str] = {}
    expired = 0
    rel = path.relative_to(ROOT).as_posix()
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{rel}:{no}"
        fields = [f.strip() for f in line.split("|")]
        if not 3 <= len(fields) <= 5:
            errors.append(f"{where}: formato atteso 'IP/CIDR | AAAA-MM-GG | motivo | ticket | scadenza'")
            continue
        token, added, reason, ticket, expires = fields + [""] * (5 - len(fields))
        try:
            nets = parse_token(token)
        except (ValueError, TypeError):
            errors.append(f"{where}: indirizzo non valido '{token}'")
            continue
        if not valid_date(added):
            errors.append(f"{where}: data inserimento non valida '{added}' (AAAA-MM-GG)")
            continue
        if not reason:
            errors.append(f"{where}: motivo obbligatorio")
            continue
        if contains_pii(reason) or EMAIL_RE.search(ticket):
            errors.append(f"{where}: possibile dato personale nel motivo/ticket (ISO 27701): usare solo ID ticket")
            continue
        if ticket and ticket != "-" and not TICKET_RE.match(ticket):
            errors.append(f"{where}: ticket non valido '{ticket}'")
            continue
        if expires:
            if not valid_date(expires):
                errors.append(f"{where}: scadenza non valida '{expires}' (AAAA-MM-GG)")
                continue
            if date.fromisoformat(expires) < today:
                expired += 1
                continue
        for net in nets:
            if min_prefix is not None and (bad := reject_reason(net, min_prefix)):
                errors.append(f"{where}: {net} {bad}")
                continue
            if net in seen:
                errors.append(f"{where}: {net} duplicato di {seen[net]}")
                continue
            seen[net] = where
            entries.append(Entry(net, added, reason, ticket or "-", expires, where))
    return entries, expired


def load_config(errors: list[str]) -> dict:
    cfg = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg.setdefault("settings", {})
    categories = cfg.get("categories", {})
    ids: set[str] = set()
    for src in cfg.get("sources", []):
        sid = src.get("id", "?")
        if sid in ids:
            errors.append(f"sources.toml: id duplicato '{sid}'")
        ids.add(sid)
        if src.get("category") not in categories:
            errors.append(f"sources.toml: fonte '{sid}' con categoria inesistente '{src.get('category')}'")
        if not str(src.get("url", "")).startswith("https://"):
            errors.append(f"sources.toml: fonte '{sid}' deve usare HTTPS")
        if not src.get("license"):
            errors.append(f"sources.toml: fonte '{sid}' senza licenza dichiarata")
    return cfg


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download oltre 50 MB")
    return data.decode("utf-8", errors="replace")


def load_source(src: dict, settings: dict, offline: bool, persist: bool,
                raw: bool = False) -> tuple[set[Network], SourceResult]:
    min_prefix = None if raw else {
        4: src.get("min_prefix_v4", settings.get("min_prefix_v4", 16)),
        6: src.get("min_prefix_v6", settings.get("min_prefix_v6", 32)),
    }
    result = SourceResult(src["id"], src["category"], src["license"], src.get("homepage", ""),
                          src.get("enabled", True), "disattivata", 0, src.get("note", ""))
    if not result.enabled:
        return set(), result
    cache_path = CACHE_DIR / f"{src['id']}.txt"
    cached: set[Network] = set()
    if cache_path.exists():
        cached, _ = parse_source_text(cache_path.read_text(encoding="utf-8"), min_prefix)
    if offline:
        result.status, result.entries = "cache", len(cached)
        return cached, result
    try:
        nets, rejected = parse_source_text(fetch(src["url"]), min_prefix)
        if not nets:
            raise ValueError("nessuna voce valida")
        drop = settings.get("max_drop_ratio", 0.5)
        if cached and len(nets) < len(cached) * (1 - drop):
            raise ValueError(f"calo sospetto {len(cached)} → {len(nets)} voci")
    except Exception as exc:  # qualsiasi errore di rete/parsing: si ripiega sulla cache
        warn(f"fonte {src['id']}: {exc}; uso la cache ({len(cached)} voci)")
        result.status = "cache" if cached else "fallita"
        result.entries = len(cached)
        result.detail = str(exc)
        return cached, result
    if persist:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("".join(f"{fmt(n)}\n" for n in sorted(nets, key=sort_key)),
                              encoding="utf-8", newline="\n")
    result.status, result.entries = "ok", len(nets)
    if rejected:
        result.detail = ", ".join(f"scartate {v} {k}" for k, v in sorted(rejected.items()))
    return nets, result


def subtract(nets: list[Network], allow: list[Network]) -> tuple[list[Network], int]:
    """Rimuove le reti in allowlist, spezzando i CIDR che le contengono."""
    out: list[Network] = []
    touched = 0
    for net in nets:
        pieces = [net]
        for a in allow:
            if a.version != net.version:
                continue
            nxt: list[Network] = []
            for p in pieces:
                if not p.overlaps(a):
                    nxt.append(p)
                elif not p.subnet_of(a):
                    nxt.extend(p.address_exclude(a))
            pieces = nxt
        if pieces != [net]:
            touched += 1
        out.extend(pieces)
    return out, touched


def finalize(nets: set[Network], allow: list[Network], version: int) -> tuple[list[Network], int]:
    same = [n for n in nets if n.version == version]
    collapsed = list(ipaddress.collapse_addresses(same))
    cleaned, touched = subtract(collapsed, allow)
    return sorted(ipaddress.collapse_addresses(cleaned), key=sort_key), touched


def count_lines(path: Path) -> int | None:
    if not path.exists():
        return None
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def render_readme(cfg: dict, outputs: dict[str, list[Network]], sources: list[SourceResult],
                  custom: dict[str, dict]) -> str:
    base = f"{RAW_BASE}/dist/ip"
    lines = [
        "# Feed IP per firewall",
        "",
        "> File generato da `scripts/build_ip.py`: **non modificare a mano**.",
        "> Fonti in [`ip/sources.toml`](../../ip/sources.toml), voci manuali in [`ip/custom/`](../../ip/custom/),",
        "> esclusioni in [`ip/allowlist.txt`](../../ip/allowlist.txt).",
        "",
        "## Feed",
        "",
        "| Feed | Descrizione | IPv4 | IPv6 |",
        "|---|---|---|---|",
    ]
    in_all = [c for c, m in cfg["categories"].items() if m.get("in_all", True) and not m.get("reserved")]
    rows = [("all", f"Aggregato: {', '.join(in_all)}")]
    rows += [(c, m.get("description", "")) for c, m in cfg["categories"].items()]
    for name, desc in rows:
        v4, v6 = f"{name}-v4.txt", f"{name}-v6.txt"
        lines.append(f"| `{name}` | {desc} | [{len(outputs[v4])}]({base}/{v4}) | [{len(outputs[v6])}]({base}/{v6}) |")
    lines += ["", "## Fonti", "", "| ID | Categoria | Licenza | Stato | Voci | Note |", "|---|---|---|---|---|---|"]
    for s in sources:
        sid = f"[{s.id}]({s.homepage})" if s.homepage else s.id
        lines.append(f"| {sid} | {s.category} | {s.license} | {s.status} | {s.entries} | {s.detail} |")
    lines += ["", "## Voci manuali", "", "| Categoria | Attive | Scadute |", "|---|---|---|"]
    for cat, st in sorted(custom.items()):
        lines.append(f"| {cat} | {st['attive']} | {st['scadute']} |")
    lines += ["", "Pubblicato sotto GPL-3.0. Attribuzioni: vedi tabella Fonti.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="solo validazione, nessuna scrittura")
    parser.add_argument("--offline", action="store_true", help="usa solo la cache locale")
    parser.add_argument("--report", type=Path, help="scrive il report markdown in questo file")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    offline = args.offline or args.check
    write = not args.check

    errors: list[str] = []
    cfg = load_config(errors)
    settings, categories = cfg["settings"], cfg.get("categories", {})
    min_prefix = {4: settings.get("min_prefix_v4", 16), 6: settings.get("min_prefix_v6", 32)}
    today = date.today()

    per_cat: dict[str, set[Network]] = {c: set() for c in categories}
    custom_stats: dict[str, dict] = {}
    for path in sorted(CUSTOM_DIR.glob("*.txt")):
        if path.stem not in categories:
            errors.append(f"{path.relative_to(ROOT).as_posix()}: categoria '{path.stem}' non definita in sources.toml")
            continue
        reserved = categories[path.stem].get("reserved", False)
        entries, expired = load_annotated(path, min_prefix=None if reserved else min_prefix,
                                          today=today, errors=errors)
        per_cat[path.stem].update(e.net for e in entries)
        custom_stats[path.stem] = {"attive": len(entries), "scadute": expired}

    allow_entries, _ = load_annotated(ALLOWLIST_PATH, min_prefix=None, today=today, errors=errors)
    allow = [e.net for e in allow_entries]

    source_results: list[SourceResult] = []
    outputs: dict[str, list[Network]] = {}
    for src in cfg.get("sources", []):
        if src.get("category") not in categories:
            continue
        reserved = categories[src["category"]].get("reserved", False)
        nets, res = load_source(src, settings, offline, persist=write, raw=reserved)
        per_cat[src["category"]].update(nets)
        source_results.append(res)

    allow_hits = 0
    for cat, meta in categories.items():
        cat_allow = [] if meta.get("reserved") else allow
        for v in FAMILIES:
            outputs[f"{cat}-v{v}.txt"], touched = finalize(per_cat[cat], cat_allow, v)
            allow_hits += touched
    # Unione dei feed già filtrati: ogni categoria mantiene la propria allowlist
    in_all = [c for c, m in categories.items() if m.get("in_all", True) and not m.get("reserved")]
    for v in FAMILIES:
        merged = (n for c in in_all for n in outputs[f"{c}-v{v}.txt"])
        outputs[f"all-v{v}.txt"] = sorted(ipaddress.collapse_addresses(merged), key=sort_key)

    anomalies: list[str] = []
    threshold = settings.get("pr_threshold", 0.25)
    min_base = settings.get("anomaly_min_entries", 100)
    max_entries = settings.get("max_entries", 0)
    for name, nets in outputs.items():
        prev = count_lines(DIST_DIR / name)
        if prev and prev >= min_base and abs(len(nets) - prev) / prev > threshold:
            anomalies.append(f"`{name}`: {prev} → {len(nets)} voci")
        if max_entries and len(nets) > max_entries:
            anomalies.append(f"`{name}`: {len(nets)} voci oltre il limite max_entries={max_entries}")

    if write:
        DIST_DIR.mkdir(parents=True, exist_ok=True)
        for stale in DIST_DIR.glob("*.txt"):
            if stale.name not in outputs:
                stale.unlink()
        active = {f"{s['id']}.txt" for s in cfg.get("sources", []) if s.get("enabled", True)}
        for stale in CACHE_DIR.glob("*.txt"):
            if stale.name not in active:
                stale.unlink()
        for name, nets in outputs.items():
            (DIST_DIR / name).write_text("".join(f"{fmt(n)}\n" for n in nets), encoding="utf-8", newline="\n")
        for cat, meta in categories.items():
            for rel in meta.get("compat_v4", []):
                (ROOT / rel).write_text("".join(f"{fmt(n)}\n" for n in outputs[f"{cat}-v4.txt"]),
                                        encoding="utf-8", newline="\n")
        stats = {
            "feed": {name: len(nets) for name, nets in outputs.items()},
            "fonti": [vars(s) for s in source_results],
            "manuali": custom_stats,
            "allowlist": {"voci": len(allow), "reti_modificate": allow_hits},
        }
        (DIST_DIR / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n",
                                             encoding="utf-8", newline="\n")
        (DIST_DIR / "README.md").write_text(render_readme(cfg, outputs, source_results, custom_stats),
                                            encoding="utf-8", newline="\n")

    report = ["## Build feed IP", ""]
    report += [f"- `{s.id}`: {s.status}, {s.entries} voci {s.detail}".rstrip() for s in source_results if s.enabled]
    report += [f"- allowlist: {len(allow)} voci, {allow_hits} reti modificate", ""]
    if anomalies:
        report += ["### Variazioni anomale", ""] + [f"- {a}" for a in anomalies] + [""]
    if errors:
        report += ["### Errori nelle liste manuali (righe ignorate)", ""] + [f"- {e}" for e in errors] + [""]
    text = "\n".join(report)
    print(text)
    if args.report:
        args.report.write_text(text, encoding="utf-8")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if gh_out := os.environ.get("GITHUB_OUTPUT"):
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"anomaly={'true' if anomalies else 'false'}\nerrors={len(errors)}\n")
    for e in errors:
        fail(e)
    # In build le righe errate vengono saltate e i feed pubblicati comunque; il workflow fallisce dopo.
    return 1 if errors and args.check else 0


if __name__ == "__main__":
    sys.exit(main())
