"""Normalizzazione degli asset — TRAPIANTO dal vecchio MVP, ora sotto test.

Funzioni pure (nessun I/O): mappano un `asset_identifier` grezzo in
`(normalized_type, normalized_value)` dove type ∈ {url, api, domain, wildcard},
più gli helper di riduzione URL usati dal recon.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable, List, Tuple
from urllib.parse import urlparse, urlunparse

# --- Rilevazione tipo asset ------------------------------------------------ #


def is_url(s: str) -> bool:
    s = s.strip()
    return s.startswith("http://") or s.startswith("https://")


def is_wildcard(s: str) -> bool:
    return "*" in s


def clean_url(u: str) -> str:
    u = u.strip()
    try:
        p = urlparse(u)
        p = p._replace(fragment="")
        return urlunparse(p)
    except Exception:
        return u


def hostname_from_any(s: str) -> str | None:
    try:
        if is_url(s):
            return urlparse(s).hostname
        host = s.strip().replace("*.", "").strip()
        if "." in host and "/" not in host and not host.startswith("http"):
            return host
    except Exception:
        return None
    return None


def detect_and_normalize(asset_identifier: str) -> Tuple[str, str]:
    """Ritorna (type, value). type ∈ {wildcard, api, url, domain}."""
    a = asset_identifier.strip()
    if is_wildcard(a):
        return ("wildcard", a)
    if is_url(a):
        host = urlparse(a).hostname or ""
        if "/api" in a or host.startswith("api.") or ".api." in host:
            return ("api", clean_url(a))
        return ("url", clean_url(a))
    host = hostname_from_any(a)
    if host:
        if host.startswith("api.") or ".api." in host:
            return ("api", f"https://{host}/")
        return ("domain", f"https://{host}/")
    return ("url", clean_url(a))


def strip_wildcard_to_domain(value: str) -> str:
    v = value.strip()
    if v.startswith("*."):
        return v[2:]
    return v


def host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def ensure_https_root(host_or_url: str) -> str:
    h = host_or_url.strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h
    return f"https://{h}/"


def sha256_hex(items: Iterable[str]) -> str:
    """Hash deterministico di una collezione (ordine-indipendente)."""
    h = hashlib.sha256()
    for s in sorted(items):
        h.update(s.encode("utf-8", errors="ignore"))
    return h.hexdigest()


# --- Riduzione URL (per recon/reduce) -------------------------------------- #

SKIP_EXT = {
    ".css", ".map", ".less", ".sass", ".scss",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".webm",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
}
TRACKING_QS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid",
}


def normalize_url(u: str) -> str:
    u = u.strip()
    u = re.sub(r"#.*$", "", u)
    if "?" in u:
        base, qs = u.split("?", 1)
        params = [
            p for p in qs.split("&")
            if p and p.split("=", 1)[0].lower() not in TRACKING_QS
        ]
        u = base if not params else base + "?" + "&".join(params)
    return u


def is_static_asset(u: str) -> bool:
    low = u.lower().split("?", 1)[0]
    return any(low.endswith(ext) for ext in SKIP_EXT)


def reduce_urls(urls: Iterable[str]) -> List[str]:
    """Normalizza, scarta asset statici, deduplica preservando l'ordine."""
    out: List[str] = []
    seen = set()
    for raw in urls:
        u = normalize_url(raw)
        if not u or is_static_asset(u):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out
