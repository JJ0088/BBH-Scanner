#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bbh_code/runner.py — Fase 3 (Runner/Orchestrator)

Pipeline per handle:
  subfinder -> httpx -> katana -> reduce -> nuclei

Migliorie richieste:
- Messaggi Slack migliorati:
  • start con timestamp "YYYY.MM.DD-HH.MM.SS"
  • progress ogni 10 programmi: "⏩ [10:536] restanti:526"
  • un messaggio per ogni finding medium/high/critical (emoji per severità)
  • messaggio di completamento per programma
- Timestamp delle cartelle risultati in formato "YYYY.MM.DD-HH.MM.SS" (con i punti)
- Console "leggera" (solo righe essenziali)
- Output più pulito: httpx come intermedio (cancellato), katana in sottocartella dedicata
- nuclei input: JSONL {"url": "..."}; output: nuclei.findings.jsonl + nuclei.findings.json (umano)

Compatibilità: Python 3.11+ (ok 3.13)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ----------------------------- Paths & Env -------------------------------- #


def _ts_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m.%d-%H.%M.%SZ")


def _ts_local_pretty(tz: str = "Europe/Rome") -> str:
    """Timestamp locale con formato richiesto: 2025.10.20-11.49.34"""
    try:
        from zoneinfo import ZoneInfo

        z = ZoneInfo(tz)
        return datetime.now(timezone.utc).astimezone(z).strftime("%Y.%m.%d-%H.%M.%S")
    except Exception:
        return datetime.now().strftime("%Y.%m.%d-%H.%M.%S")


BBH_ROOT = Path(os.getenv("BBH_ROOT", Path(__file__).resolve().parents[1]))
DATA_DIR = Path(os.getenv("BBH_DATA_DIR", BBH_ROOT / "data"))
LOGS_DIR = BBH_ROOT / "logs"
WF_DIR = BBH_ROOT / "filtered_output" / "workflows"
RUNS_DIR = BBH_ROOT / "results" / "runs"

for d in (DATA_DIR, LOGS_DIR, WF_DIR, RUNS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ------------------------------- Slack ----------------------------------- #

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - opzionale
    requests = None


def slack_send(text: str) -> None:
    url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not url or requests is None:
        # console leggera: mock minimo
        print(f"[SLACK] {text}")
        return
    try:
        requests.post(url, json={"text": text}, timeout=10)
    except Exception:
        pass


# Emoji per severità nuclei
_SEV_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟦",
    "info": "⬜",
}


# --------------------------- Runner Config -------------------------------- #

DEFAULTS = {
    "subfinder_cmd": ["subfinder", "-dL", "{in}", "-o", "{out}"],
    # httpx: vogliamo solo URL pulite (no [200]); -silent/-no-color per output “grezzo”
    "httpx_cmd": [
        "httpx",
        "-l",
        "{in}",
        "-o",
        "{out}",
        "-silent",
        "-follow-redirects",
        "-no-color",
        "-timeout",
        "10",
    ],
    # katana headless, zero limiti espliciti di depth (massima discovery)
    "katana_cmd": ["katana", "-list", "{in}", "-o", "{out}", "-headless"],
    # nuclei: -l file, -jsonl out; altre opzioni via CLI pass-through se servono
    "nuclei_cmd": ["nuclei", "-l", "{in}", "-jsonl", "-o", "{out}"],
}


def load_config() -> Dict[str, List[str]]:
    """Carica bbh_code/runner_config.py se presente e merge con DEFAULTS."""
    cfg = dict(DEFAULTS)
    module_path = BBH_ROOT / "bbh_code" / "runner_config.py"
    if module_path.exists():
        ns: Dict[str, object] = {}
        try:
            code = module_path.read_text(encoding="utf-8")
            exec(compile(code, str(module_path), "exec"), ns, ns)
            user_cfg = ns.get("CONFIG")
            if isinstance(user_cfg, dict):
                for k, v in user_cfg.items():
                    if isinstance(v, list):
                        cfg[k] = v
        except Exception:
            pass
    return cfg


# ------------------------------- Utils ----------------------------------- #


def log_line(level: str, msg: str) -> None:
    # console leggera: niente timestamp rumorosi
    if level in ("INFO", "WARN", "ERROR"):
        print(f"[{level}] {msg}", flush=True)
    # crea/tocca un file giornaliero per i log (solo come placeholder)
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    (LOGS_DIR / f"bbh_runner_{date_str}.log").touch()


def info(m: str) -> None:
    log_line("INFO", m)


def warn(m: str) -> None:
    log_line("WARN", m)


def err(m: str) -> None:
    log_line("ERROR", m)


def read_lines(p: Path) -> List[str]:
    if not p.exists():
        return []
    return [
        x.strip()
        for x in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if x.strip()
    ]


def write_lines(p: Path, items: Iterable[str]) -> None:
    uniq = list(dict.fromkeys(s.strip() for s in items if s and s.strip()))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")


def write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or ""
    except Exception as e:
        return 1, "", str(e)


# helper per comandi con placeholder {in}/{out}


def fmt_cmd(tmpl: List[str], **kw) -> List[str]:
    kw = {k: str(v) for k, v in kw.items()}
    return [str(x).format_map(kw) for x in tmpl]


# ------------------------ Denylist & Reduce rules ------------------------ #

SKIP_EXT = {
    ".css",
    ".map",
    ".less",
    ".sass",
    ".scss",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".mp4",
    ".mp3",
    ".wav",
    ".avi",
    ".mov",
    ".mkv",
    ".webm",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
}
TRACKING_QS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
}


def normalize_url(u: str) -> str:
    u = u.strip()
    u = re.sub(r"#.*$", "", u)
    if "?" in u:
        base, qs = u.split("?", 1)
        params = [
            p
            for p in qs.split("&")
            if p and p.split("=", 1)[0].lower() not in TRACKING_QS
        ]
        u = base if not params else base + "?" + "&".join(params)
    return u


def is_static_asset(u: str) -> bool:
    low = u.lower().split("?", 1)[0]
    return any(low.endswith(ext) for ext in SKIP_EXT)


def apply_denylist(urls: Iterable[str], denylist_file: Path) -> List[str]:
    deny = set(read_lines(denylist_file)) if denylist_file.exists() else set()
    if not deny:
        return list(urls)
    have = set(urls)
    remain = sorted(have - deny)
    return remain


# ------------------------------- Steps ----------------------------------- #


@dataclass
class StepResult:
    name: str
    executed: bool
    skipped: bool
    rc: int
    in_count: int
    out_count: int
    seconds: float
    sig: str
    cmd: str


def _build_sig(inputs: List[Path], params: Dict) -> str:
    h = hashlib.sha256()
    for p in inputs:
        if p.exists():
            h.update(sha256_file(p).encode())
        else:
            h.update(b"<missing>")
    h.update(json.dumps(params, sort_keys=True).encode())
    return h.hexdigest()


def _should_skip(
    manifest: Dict, step: str, sig: str, skip_enabled: bool, force: set[str]
) -> bool:
    if step in force:
        return False
    if not skip_enabled:
        return False
    last = ((manifest.get("steps") or {}).get(step) or {}).get("sig")
    return last == sig


def _record_step(manifest: Dict, step: str, res: StepResult) -> None:
    manifest.setdefault("steps", {})
    manifest["steps"][step] = {
        "executed": res.executed,
        "skipped": res.skipped,
        "rc": res.rc,
        "in_count": res.in_count,
        "out_count": res.out_count,
        "seconds": round(res.seconds, 3),
        "sig": res.sig,
        "cmd": res.cmd,
        "finished_at": _ts_utc(),
    }


# --------------------------- Pipeline helpers ---------------------------- #


def domains_to_root_urls(domains_path: Path, dst: Path) -> None:
    out = []
    for d in read_lines(domains_path):
        d = d.strip().lstrip(".")
        if not d:
            continue
        out.append(f"https://{d}/")
    write_lines(dst, out)


def sanitize_httpx_file(path: Path) -> None:
    clean = []
    for s in read_lines(path):
        s = s.split("[", 1)[0].split(None, 1)[0].strip()
        if s:
            clean.append(s)
    write_lines(path, clean)


def reduce_urls(
    sources: List[Path], denylist: Optional[Path], dst: Path
) -> Tuple[int, int]:
    raw: List[str] = []
    for p in sources:
        raw.extend(read_lines(p))
    before = len(raw)
    normalized = []
    for u in raw:
        u = normalize_url(u)
        if not u or is_static_asset(u):
            continue
        normalized.append(u)
    deduped = list(dict.fromkeys(normalized))
    if denylist:
        deduped = apply_denylist(deduped, denylist)
    write_lines(dst, deduped)
    return before, len(deduped)


def write_jsonl_urls(src: Path, jsonl_dst: Path) -> int:
    urls = read_lines(src)
    with jsonl_dst.open("w", encoding="utf-8") as f:
        for u in urls:
            f.write(json.dumps({"url": u}) + "\n")
    return len(urls)


def jsonl_to_json(jsonl_path: Path, json_path: Path) -> int:
    items: List[dict] = []
    if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
        with jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    continue
    json_path.write_text(json.dumps(items, indent=2), encoding="utf-8")
    return len(items)


# ------------------------------- CLI ------------------------------------- #

ALL_STEPS = ("subfinder", "httpx", "katana", "reduce", "nuclei")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="BBH-Scanner — Runner (Fase 3)")
    ap.add_argument(
        "--only-handles", type=str, default=None, help="CSV di handle da processare"
    )
    ap.add_argument("--skip-unchanged", action="store_true", default=True)
    ap.add_argument("--no-skip-unchanged", action="store_false", dest="skip_unchanged")
    ap.add_argument(
        "--force-step",
        type=str,
        default="",
        help="CSV: subfinder,httpx,katana,reduce,nuclei",
    )
    ap.add_argument("--steps", type=str, default=",".join(ALL_STEPS))
    ap.add_argument("--progress", type=int, default=0)
    ap.add_argument(
        "--max-workers", type=int, default=1, help="placeholder per futuro parallelismo"
    )
    ap.add_argument(
        "--list-handles",
        action="store_true",
        help="Elenca handle disponibili e termina",
    )
    ap.add_argument(
        "--ensure-seeds",
        action="store_true",
        default=True,
        help="Lancia il Filterer prima del Runner (default on)",
    )
    ap.add_argument("--no-ensure-seeds", action="store_false", dest="ensure_seeds")
    ap.add_argument(
        "--nuclei-args",
        type=str,
        default="",
        help="argomenti extra pass-through per nuclei",
    )
    return ap.parse_args()


# ------------------------------- Main run -------------------------------- #


def run_filterer(only_handles: Optional[str], progress: int = 0) -> int:
    """Esegue il Filterer per preparare/aggiornare i workflow seeds."""
    cmd = [sys.executable, "-m", "bbh_code.filterer", "--skip-unchanged"]
    if only_handles:
        cmd += ["--only-handles", only_handles]
    if progress:
        cmd += ["--progress", str(progress)]
    info("Filterer: " + " ".join(shlex.quote(x) for x in cmd))
    rc, out, err = run_cmd(cmd)
    if err.strip():
        warn(f"[filterer-err] {err.splitlines()[-1]}")
    return rc


@dataclass
class _RunContext:
    total: int
    processed: int = 0


def _slack_per_finding(handle: str, jsonl_path: Path, tz: str = "Europe/Rome") -> int:
    """Invia un messaggio Slack per ciascun finding medium/high/critical."""
    count = 0
    if not jsonl_path.exists() or jsonl_path.stat().st_size == 0:
        return 0
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            info_ = o.get("info") or {}
            sev = (info_.get("severity") or "").lower()
            if sev not in ("medium", "high", "critical"):
                continue
            name = info_.get("name") or o.get("templateID") or "Finding"
            emoji = _SEV_EMOJI.get(sev, "🟨")
            url = o.get("matched-at") or o.get("host") or ""
            slack_send(
                f"{emoji} [{handle}] {sev.upper()} — {name} — {url} — {_ts_local_pretty(tz)}"
            )
            count += 1
    return count


def run_handle(
    handle: str, args: argparse.Namespace, cfg: Dict[str, List[str]], ctx: _RunContext
) -> Dict:
    # timestamp per la cartella: formato richiesto
    ts = _ts_local_pretty()
    run_dir = RUNS_DIR / handle / ts
    meta_dir = run_dir / ".meta"
    meta_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = meta_dir / "runner_manifest.json"
    manifest = {"handle": handle, "run_started_at": _ts_utc(), "steps": {}}
    write_json(manifest_path, manifest)

    wf = WF_DIR / handle
    denylist_file = wf / "denylist.txt"  # opzionale

    # input seeds
    subfinder_seeds = wf / "subfinder_seeds.txt"
    katana_seeds = wf / "katana_seeds.txt"
    httpx_seeds = wf / "httpx_seeds.txt"
    nuclei_urls_txt = wf / "nuclei_urls.txt"
    nuclei_urls_jsonl_from_filterer = wf / "nuclei_urls.jsonl"

    # --- short-circuit: skip dell'intero handle se invariato e già completata l'ultima run ---
    seed_inputs: List[Path] = [
        p
        for p in (
            subfinder_seeds,
            httpx_seeds,
            katana_seeds,
            nuclei_urls_txt,
            nuclei_urls_jsonl_from_filterer,
        )
        if p.exists() and p.stat().st_size > 0
    ]
    h = hashlib.sha256()
    for p in seed_inputs:
        h.update(sha256_file(p).encode())
    # includi anche gli args di nuclei (parametri che possono cambiare il risultato)
    h.update((args.nuclei_args or "").encode("utf-8"))
    HANDLE_SIG = h.hexdigest()

    # prova a leggere l'ultima manifest precedente per confrontare la firma
    prev_sig = None
    prev_completed = False
    prev_handle_dir_candidates = list((RUNS_DIR / handle).glob("*"))
    if prev_handle_dir_candidates:
        prev_dir = sorted(prev_handle_dir_candidates)[-1]
        prev_manifest_path = prev_dir / ".meta" / "runner_manifest.json"
        if prev_manifest_path.exists():
            try:
                prev_manif = json.loads(prev_manifest_path.read_text(encoding="utf-8"))
                prev_sig = prev_manif.get("handle_sig")
                prev_completed = bool(prev_manif.get("run_finished_at"))
            except Exception:
                prev_sig = None
                prev_completed = False

    manifest["handle_sig"] = HANDLE_SIG
    write_json(manifest_path, manifest)

    if args.skip_unchanged and prev_completed and prev_sig == HANDLE_SIG:
        manifest["skipped_whole_handle"] = True
        manifest["run_finished_at"] = _ts_utc()
        write_json(manifest_path, manifest)
        slack_send(f"⏭️ [{handle}] skip (invariato) — {_ts_local_pretty()}")
        # progress ogni 10 anche per gli skip
        ctx.processed += 1
        if ctx.total > 0 and ctx.processed % 10 == 0:
            remaining = max(0, ctx.total - ctx.processed)
            slack_send(
                f"⏩ [{ctx.processed}:{ctx.total}] restanti:{remaining} — {_ts_local_pretty()}"
            )
        return manifest

    # output per step
    p_subfinder_out = run_dir / "subfinder.out.txt"
    p_httpx_in = run_dir / "httpx.in.txt"
    p_httpx_out = run_dir / "httpx.out.txt"
    katana_dir = run_dir / "katana"
    katana_dir.mkdir(parents=True, exist_ok=True)
    p_katana_in = katana_dir / "in.txt"
    p_katana_out = katana_dir / "raw.txt"
    p_katana_urls = katana_dir / "urls.txt"  # filtrato
    p_reduce_out = run_dir / "reduce.out.txt"
    p_nuclei_in = run_dir / "nuclei.in.jsonl"
    p_nuclei_out = run_dir / "nuclei.findings.jsonl"

    force = {x.strip() for x in (args.force_step or "").split(",") if x.strip()}
    requested_steps = [s for s in (args.steps or "").split(",") if s in ALL_STEPS]

    # --- SUBFINDER ---
    if (
        "subfinder" in requested_steps
        and subfinder_seeds.exists()
        and subfinder_seeds.stat().st_size > 0
    ):
        params = {"cmd": cfg["subfinder_cmd"]}
        sig = _build_sig([subfinder_seeds], params)
        if _should_skip(manifest, "subfinder", sig, args.skip_unchanged, force):
            res = StepResult(
                "subfinder",
                False,
                True,
                0,
                len(read_lines(subfinder_seeds)),
                len(read_lines(p_subfinder_out)),
                0.0,
                sig,
                " ".join(shlex.quote(x) for x in cfg["subfinder_cmd"]),
            )
        else:
            t0 = time.perf_counter()
            cmd = fmt_cmd(
                cfg["subfinder_cmd"], **{"in": subfinder_seeds, "out": p_subfinder_out}
            )
            rc, out, err = run_cmd(cmd)
            dt = time.perf_counter() - t0
            if rc != 0:
                warn(f"[{handle}] subfinder rc={rc} tail: {err.splitlines()[-1:]} ")
            res = StepResult(
                "subfinder",
                True,
                False,
                rc,
                len(read_lines(subfinder_seeds)),
                len(read_lines(p_subfinder_out)),
                dt,
                sig,
                " ".join(shlex.quote(x) for x in cmd),
            )
        _record_step(manifest, "subfinder", res)
        write_json(manifest_path, manifest)

    # Prepara httpx.in
    httpx_in_sources: List[Path] = []
    if httpx_seeds.exists() and httpx_seeds.stat().st_size > 0:
        httpx_in_sources.append(httpx_seeds)
    if p_subfinder_out.exists() and p_subfinder_out.stat().st_size > 0:
        domains_to_root_urls(p_subfinder_out, p_httpx_in)
        httpx_in_sources.append(p_httpx_in)

    # --- HTTPX ---
    if "httpx" in requested_steps and httpx_in_sources:
        tmp_httpx_union = run_dir / ".httpx.union.txt"
        union_list: List[str] = []
        for s in httpx_in_sources:
            union_list.extend(read_lines(s))
        write_lines(tmp_httpx_union, union_list)

        params = {"cmd": cfg["httpx_cmd"]}
        sig = _build_sig([tmp_httpx_union], params)
        if _should_skip(manifest, "httpx", sig, args.skip_unchanged, force):
            res = StepResult(
                "httpx",
                False,
                True,
                0,
                len(read_lines(tmp_httpx_union)),
                len(read_lines(p_httpx_out)),
                0.0,
                sig,
                " ".join(shlex.quote(x) for x in cfg["httpx_cmd"]),
            )
        else:
            t0 = time.perf_counter()
            cmd = fmt_cmd(
                cfg["httpx_cmd"], **{"in": tmp_httpx_union, "out": p_httpx_out}
            )
            rc, out, err = run_cmd(cmd)
            sanitize_httpx_file(p_httpx_out)
            dt = time.perf_counter() - t0
            if rc != 0:
                warn(f"[{handle}] httpx rc={rc} tail: {err.splitlines()[-1:]} ")
            res = StepResult(
                "httpx",
                True,
                False,
                rc,
                len(read_lines(tmp_httpx_union)),
                len(read_lines(p_httpx_out)),
                dt,
                sig,
                " ".join(shlex.quote(x) for x in cmd),
            )
        _record_step(manifest, "httpx", res)
        write_json(manifest_path, manifest)

    # --- KATANA ---
    katana_input: Optional[Path] = None
    if katana_seeds.exists() and katana_seeds.stat().st_size > 0:
        write_lines(p_katana_in, read_lines(katana_seeds))
        katana_input = p_katana_in
    elif p_httpx_out.exists() and p_httpx_out.stat().st_size > 0:
        katana_input = p_httpx_out

    if "katana" in requested_steps and katana_input is not None:
        params = {"cmd": cfg["katana_cmd"]}
        sig = _build_sig([katana_input], params)
        if _should_skip(manifest, "katana", sig, args.skip_unchanged, force):
            res = StepResult(
                "katana",
                False,
                True,
                0,
                len(read_lines(katana_input)),
                len(read_lines(p_katana_out)),
                0.0,
                sig,
                " ".join(shlex.quote(x) for x in cfg["katana_cmd"]),
            )
        else:
            t0 = time.perf_counter()
            cmd = fmt_cmd(
                cfg["katana_cmd"], **{"in": katana_input, "out": p_katana_out}
            )
            rc, out, err = run_cmd(cmd)
            dt = time.perf_counter() - t0
            if rc != 0:
                warn(f"[{handle}] katana rc={rc} tail: {err.splitlines()[-1:]} ")
            # filtra in katana/urls.txt
            _ = reduce_urls([p_katana_out], None, p_katana_urls)
            res = StepResult(
                "katana",
                True,
                False,
                rc,
                len(read_lines(katana_input)),
                len(read_lines(p_katana_out)),
                dt,
                sig,
                " ".join(shlex.quote(x) for x in cmd),
            )
        _record_step(manifest, "katana", res)
        write_json(manifest_path, manifest)

    # --- REDUCE ---
    if "reduce" in requested_steps:
        sources: List[Path] = []
        if p_katana_urls.exists():
            sources.append(p_katana_urls)
        if p_httpx_out.exists():
            sources.append(p_httpx_out)
        if nuclei_urls_txt.exists():
            sources.append(nuclei_urls_txt)
        params = {
            "filters": "static_assets+tracking_qs+dedup",
            "denylist": str(denylist_file if denylist_file.exists() else ""),
        }
        sig = _build_sig(
            sources + ([denylist_file] if denylist_file.exists() else []), params
        )
        if _should_skip(manifest, "reduce", sig, args.skip_unchanged, force):
            res = StepResult(
                "reduce",
                False,
                True,
                0,
                sum(len(read_lines(s)) for s in sources),
                len(read_lines(p_reduce_out)),
                0.0,
                sig,
                "internal",
            )
        else:
            t0 = time.perf_counter()
            before, after = reduce_urls(
                sources, denylist_file if denylist_file.exists() else None, p_reduce_out
            )
            dt = time.perf_counter() - t0
            res = StepResult(
                "reduce", True, False, 0, before, after, dt, sig, "internal"
            )
        _record_step(manifest, "reduce", res)
        write_json(manifest_path, manifest)

        # nuclei.in + merge con nuclei_urls.jsonl del filterer
        write_jsonl_urls(p_reduce_out, p_nuclei_in)
        if (
            nuclei_urls_jsonl_from_filterer.exists()
            and nuclei_urls_jsonl_from_filterer.stat().st_size > 0
        ):
            existing = set(read_lines(p_reduce_out))
            with (
                nuclei_urls_jsonl_from_filterer.open("r", encoding="utf-8") as f,
                p_nuclei_in.open("a", encoding="utf-8") as out,
            ):
                for line in f:
                    try:
                        u = json.loads(line).get("url", "")
                    except Exception:
                        u = ""
                    if u and u not in existing:
                        out.write(json.dumps({"url": u}) + "\n")

    # --- NUCLEI ---
    if (
        "nuclei" in requested_steps
        and p_nuclei_in.exists()
        and p_nuclei_in.stat().st_size > 0
    ):
        base_cmd = [x for x in cfg["nuclei_cmd"]]
        extra = shlex.split(args.nuclei_args) if args.nuclei_args else []
        params = {"cmd": base_cmd, "extra": extra}
        sig = _build_sig([p_nuclei_in], params)
        if _should_skip(manifest, "nuclei", sig, args.skip_unchanged, force):
            res = StepResult(
                "nuclei",
                False,
                True,
                0,
                sum(1 for _ in p_nuclei_in.open("r", encoding="utf-8")),
                (
                    sum(1 for _ in p_nuclei_out.open("r", encoding="utf-8"))
                    if p_nuclei_out.exists()
                    else 0
                ),
                0.0,
                sig,
                " ".join(shlex.quote(x) for x in base_cmd + extra),
            )
        else:
            t0 = time.perf_counter()
            cmd = fmt_cmd(base_cmd, **{"in": p_nuclei_in, "out": p_nuclei_out}) + extra
            rc, out, err = run_cmd(cmd)
            dt = time.perf_counter() - t0
            if rc != 0:
                warn(f"[{handle}] nuclei rc={rc} tail: {err.splitlines()[-1:]} ")
            out_count = 0
            if p_nuclei_out.exists():
                with p_nuclei_out.open("r", encoding="utf-8") as f:
                    for _ in f:
                        out_count += 1
            res = StepResult(
                "nuclei",
                True,
                False,
                rc,
                sum(1 for _ in p_nuclei_in.open("r", encoding="utf-8")),
                out_count,
                dt,
                sig,
                " ".join(shlex.quote(x) for x in cmd),
            )
        _record_step(manifest, "nuclei", res)
        write_json(manifest_path, manifest)

        # Slack: stream per-finding + sommario e JSON "umano"
        _slack_per_finding(handle, p_nuclei_out)
        slack_send(_nuclei_summary(handle, p_nuclei_out))
        jsonl_to_json(p_nuclei_out, run_dir / "nuclei.findings.json")

    # cleanup: httpx output non necessario a fine pipeline
    try:
        if p_httpx_out.exists():
            p_httpx_out.unlink()
    except Exception:
        pass

    manifest["run_finished_at"] = _ts_utc()
    write_json(manifest_path, manifest)

    # Slack: completamento singolo programma
    slack_send(f"☑️ [{handle}] scan completata — {_ts_local_pretty()}")

    # progress ogni 10
    ctx.processed += 1
    if ctx.total > 0 and ctx.processed % 10 == 0:
        remaining = max(0, ctx.total - ctx.processed)
        slack_send(
            f"⏩ [{ctx.processed}:{ctx.total}] restanti:{remaining} — {_ts_local_pretty()}"
        )

    return manifest


def _nuclei_summary(handle: str, jsonl_path: Path) -> str:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    if jsonl_path.exists() and jsonl_path.stat().st_size > 0:
        with jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                sev = ((obj.get("info") or {}).get("severity") or "").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
    # emoji in base alla severità più alta presente
    emoji = (
        "🟥"
        if sev_counts["critical"]
        else (
            "🟧"
            if sev_counts["high"]
            else "🟨" if sev_counts["medium"] else "🟦" if sev_counts["low"] else "⬜"
        )
    )
    return f"{emoji} [{handle}] findings:{total} (crit:{sev_counts['critical']} high:{sev_counts['high']} med:{sev_counts['medium']} low:{sev_counts['low']} info:{sev_counts['info']}) — {_ts_local_pretty()}"


def main() -> int:
    args = parse_args()
    cfg = load_config()

    # Step 0: assicura i seeds
    if getattr(args, "ensure_seeds", True):
        run_filterer(args.only_handles, args.progress)

    # selezione handle (dopo il filterer)
    info(f"Workflow dir: {WF_DIR}")
    handles: List[str] = []
    if WF_DIR.exists():
        for d in WF_DIR.iterdir():
            if d.is_dir():
                seed_files = [
                    d / "subfinder_seeds.txt",
                    d / "httpx_seeds.txt",
                    d / "katana_seeds.txt",
                    d / "nuclei_urls.jsonl",
                    d / "nuclei_urls.txt",
                ]
                if any(p.exists() and p.stat().st_size > 0 for p in seed_files):
                    handles.append(d.name)
    handles.sort()

    if args.list_handles:
        info("Handle disponibili: " + ", ".join(handles) if handles else "<none>")
        return 0

    if args.only_handles:
        wanted = {x.strip() for x in args.only_handles.split(",") if x.strip()}
        original = set(handles)
        handles = [h for h in handles if h in wanted]
        missing = sorted(wanted - original)
        if missing:
            warn(
                "Handle richiesti ma non trovati (o senza seeds): " + ", ".join(missing)
            )

    if not handles:
        info(
            "Nessun handle da processare: assicurati che il DB contenga programmi e che il Filterer generi seeds."
        )
        return 0

    # Slack: start con timestamp formattato
    slack_send(f"▶️ Runner start — handles:{len(handles)} — {_ts_local_pretty()}")

    ctx = _RunContext(total=len(handles))
    t0 = time.perf_counter()

    for h in handles:
        info(f"[{h}] start")
        _ = run_handle(h, args, cfg, ctx)

    dt = time.perf_counter() - t0
    m, s = int(dt // 60), int(dt % 60)
    slack_send(
        f"✅ Runner done — handles:{ctx.processed} — durata:{m}m{s:02d}s — {_ts_local_pretty()}"
    )
    info(f"Done: {ctx.processed} handle in {m}m{s:02d}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
