"""Esecuzione di nuclei e parsing dei findings.

- `build_targets` compone la lista di URL da scansionare: scope url/api eleggibili +
  host vivi scoperti dal recon, ridotti/deduplicati.
- `parse_nuclei_jsonl` è puro (testabile senza rete/tool).
- `run_nuclei` scrive l'input, lancia nuclei con rate-limit e severità configurati,
  e ritorna i findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from bbh_scanner.config import ActiveScanConfig
from bbh_scanner.normalize import reduce_urls
from bbh_scanner.recon.tools import run_tool


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    host: str = ""


@dataclass
class NucleiScanResult:
    handle: str
    rc: int = 0
    findings: List[NucleiFinding] = field(default_factory=list)
    skipped: bool = False


def build_targets(scopes_url_api: List[Dict], alive_hosts: List[str]) -> List[str]:
    """Bersagli nuclei = valori normalizzati degli scope url/api + host vivi, ridotti."""
    urls: List[str] = []
    for s in scopes_url_api:
        v = (s.get("normalized_value") or "").strip()
        if v:
            urls.append(v)
    urls.extend(alive_hosts)
    return reduce_urls(urls)


def parse_nuclei_jsonl(text: str) -> List[NucleiFinding]:
    """Estrae i findings dall'output JSONL di nuclei (`-jsonl`). Righe non valide ignorate."""
    out: List[NucleiFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info") or {}
        template_id = obj.get("template-id") or obj.get("templateID") or "?"
        out.append(NucleiFinding(
            template_id=str(template_id),
            name=info.get("name") or str(template_id),
            severity=(info.get("severity") or "info").lower(),
            matched_at=obj.get("matched-at") or obj.get("host") or "",
            host=obj.get("host") or "",
        ))
    return out


def run_nuclei(handle: str, targets: List[str], workdir: Path,
               cfg: ActiveScanConfig, nice: int = 10, timeout: int = 3600,
               tools: Dict = None) -> NucleiScanResult:
    """Esegue nuclei sui bersagli. Se il tool manca o non ci sono bersagli, salta."""
    from bbh_scanner.recon.tools import check_tools

    status = tools if tools is not None else check_tools(("nuclei",))
    nuclei = status.get("nuclei")
    if nuclei is None or not nuclei.available:
        return NucleiScanResult(handle=handle, skipped=True)
    if not targets:
        return NucleiScanResult(handle=handle, skipped=True)

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    infile = workdir / "nuclei_in.txt"
    infile.write_text("\n".join(targets) + "\n", encoding="utf-8")
    outfile = workdir / "nuclei.jsonl"
    if outfile.exists():
        outfile.unlink()

    cmd = [
        "nuclei", "-l", str(infile), "-jsonl", "-o", str(outfile),
        "-silent", "-no-color",
        "-rate-limit", str(cfg.rate_limit), "-c", str(cfg.concurrency),
    ]
    if cfg.severity:
        cmd += ["-severity", cfg.severity]
    if cfg.templates:
        cmd += ["-t", cfg.templates]
    if cfg.extra_args:
        import shlex

        cmd += shlex.split(cfg.extra_args)

    rc, _out, _err = run_tool(cmd, timeout=timeout, nice=nice)
    findings: List[NucleiFinding] = []
    if outfile.exists():
        findings = parse_nuclei_jsonl(outfile.read_text(encoding="utf-8", errors="ignore"))
    return NucleiScanResult(handle=handle, rc=rc, findings=findings)
