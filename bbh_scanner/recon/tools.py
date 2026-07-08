"""Rilevazione dei tool ProjectDiscovery e runner subprocess con timeout/nice.

Ogni step del recon è guardato dalla disponibilità del tool: se manca, lo step viene
saltato e loggato invece di far crashare la pipeline.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

RECON_TOOLS = ("subfinder", "dnsx", "httpx")


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: Optional[str]


def check_tools(tools: Tuple[str, ...] = RECON_TOOLS) -> Dict[str, ToolStatus]:
    status: Dict[str, ToolStatus] = {}
    for t in tools:
        path = shutil.which(t)
        status[t] = ToolStatus(name=t, available=path is not None, path=path)
    return status


def _preexec(nice: int):
    def _apply():
        try:
            os.nice(nice)
        except Exception:
            pass

    return _apply


def run_tool(cmd: List[str], timeout: Optional[int] = None,
             nice: int = 10) -> Tuple[int, str, str]:
    """Esegue un comando con priorità ridotta (nice) e timeout. (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            preexec_fn=_preexec(nice) if os.name == "posix" else None,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or ""
    except FileNotFoundError:
        return 127, "", f"tool non trovato: {cmd[0] if cmd else '?'}"
    except Exception as e:  # pragma: no cover - difensivo
        return 1, "", str(e)
