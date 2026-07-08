"""Pipeline di recon passivo per un singolo programma.

    seeds (wildcard/domain)  ->  subfinder  ->  dnsx (risolve)  ->  httpx (probe vivo)

Passiva per definizione: nessuna richiesta intrusiva agli asset. Ogni step è saltato
se il tool relativo non è installato. Produce asset scoperti e delta (findings).

I *seed builder* sono puri e testabili; l'esecuzione dei tool è isolata dietro
`recon.tools.run_tool`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bbh_scanner.normalize import ensure_https_root, strip_wildcard_to_domain
from bbh_scanner.recon.tools import check_tools, run_tool


@dataclass
class ReconResult:
    handle: str
    subdomains: List[str] = field(default_factory=list)
    resolved: List[str] = field(default_factory=list)
    alive: List[str] = field(default_factory=list)
    skipped_steps: List[str] = field(default_factory=list)


def build_subfinder_seeds(scopes: List[Dict]) -> List[str]:
    """Domini/root da cui subfinder enumera i sottodomini (wildcard + domain)."""
    seeds = set()
    for s in scopes:
        ntype = (s.get("normalized_type") or "").lower()
        nval = (s.get("normalized_value") or "").strip()
        if not nval:
            continue
        if ntype == "wildcard":
            seeds.add(strip_wildcard_to_domain(nval))
        elif ntype == "domain":
            from bbh_scanner.normalize import host_from_url

            seeds.add(host_from_url(nval) or nval)
    return sorted(seeds)


def _lines(text: str) -> List[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def run_passive(handle: str, scopes: List[Dict], workdir,
                timeout: int = 1800, nice: int = 10,
                tools: Optional[Dict] = None) -> ReconResult:
    """Esegue subfinder -> dnsx -> httpx sui seed derivati dagli scope."""
    from pathlib import Path

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    result = ReconResult(handle=handle)
    status = tools if tools is not None else check_tools()

    seeds = build_subfinder_seeds(scopes)
    if not seeds:
        result.skipped_steps.append("no-seeds")
        return result
    seeds_file = workdir / "seeds.txt"
    seeds_file.write_text("\n".join(seeds) + "\n", encoding="utf-8")

    # 1) subfinder — enumerazione passiva sottodomini
    if status.get("subfinder") and status["subfinder"].available:
        out = workdir / "subfinder.txt"
        rc, stdout, _ = run_tool(
            ["subfinder", "-dL", str(seeds_file), "-silent", "-o", str(out)],
            timeout=timeout, nice=nice,
        )
        if out.exists():
            result.subdomains = _lines(out.read_text(encoding="utf-8"))
        elif stdout:
            result.subdomains = _lines(stdout)
    else:
        result.skipped_steps.append("subfinder")
        result.subdomains = list(seeds)  # almeno i root come punto di partenza

    # 2) dnsx — tiene solo i sottodomini che risolvono
    if status.get("dnsx") and status["dnsx"].available and result.subdomains:
        subs_file = workdir / "subs.txt"
        subs_file.write_text("\n".join(result.subdomains) + "\n", encoding="utf-8")
        out = workdir / "resolved.txt"
        run_tool(
            ["dnsx", "-l", str(subs_file), "-silent", "-o", str(out)],
            timeout=timeout, nice=nice,
        )
        if out.exists():
            result.resolved = _lines(out.read_text(encoding="utf-8"))
    else:
        result.skipped_steps.append("dnsx")
        result.resolved = list(result.subdomains)

    # 3) httpx — probe leggero per capire quali host sono vivi
    if status.get("httpx") and status["httpx"].available and result.resolved:
        hosts = [ensure_https_root(h) for h in result.resolved]
        hosts_file = workdir / "hosts.txt"
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        out = workdir / "alive.txt"
        run_tool(
            ["httpx", "-l", str(hosts_file), "-silent", "-no-color",
             "-timeout", "10", "-o", str(out)],
            timeout=timeout, nice=nice,
        )
        if out.exists():
            result.alive = _lines(out.read_text(encoding="utf-8"))
    else:
        result.skipped_steps.append("httpx")

    return result
