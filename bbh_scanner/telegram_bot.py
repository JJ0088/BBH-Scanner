"""Bot Telegram a comandi — interroga/controlla lo scanner dal vivo mentre lavora.

Comandi: /status /findings /logs /jobs /sensors /mode /pause /resume /help

- `handle_command` è testabile senza rete (prende testo + Store + Config → risposta).
- `TelegramPoller` fa long-polling di `getUpdates` in un thread dedicato, con una
  **propria connessione** al DB (WAL → letture concorrenti col loop principale).
- **Sicurezza**: risponde solo ai messaggi provenienti dal `TELEGRAM_CHAT_ID` configurato.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from bbh_scanner.config import MODE_OVERRIDE_KEY, Config
from bbh_scanner.db.store import Store

OFFSET_KEY = "telegram:update_offset"
_MODES = ("auto", "turbo", "powersave", "paused")

# Menu comandi mostrato da Telegram quando digiti "/" (registrato via setMyCommands).
BOT_COMMANDS = [
    ("status", "dashboard live"),
    ("findings", "ultimi findings (es. /findings high)"),
    ("logs", "ultimi eventi"),
    ("jobs", "stato della coda"),
    ("sensors", "temperature e regime"),
    ("mode", "auto | turbo | powersave | paused"),
    ("pause", "sospendi lo scanner"),
    ("resume", "riprendi (auto)"),
    ("help", "elenco comandi"),
]

HELP = (
    "🤖 BBH-Scanner — comandi:\n"
    "/status — dashboard live\n"
    "/findings [sev] — ultimi findings (es. /findings high)\n"
    "/logs [n] — ultimi n eventi (default 10)\n"
    "/jobs — stato della coda\n"
    "/sensors — temperature e regime\n"
    "/mode <auto|turbo|powersave|paused> — imposta il regime\n"
    "/pause — sospendi · /resume — riprendi (auto)\n"
    "/help — questo messaggio"
)


# --- Formattatori (puri) --------------------------------------------------- #

def format_status(store: Store, config: Config) -> str:
    s = store.summary()
    st = s["stats"]
    override = store.get_state(MODE_OVERRIDE_KEY) or "auto"
    mode_line = f"regime: {override}"
    try:
        from bbh_scanner.resources.governor import decide
        from bbh_scanner.resources.sensors import sample_sensors
        r = sample_sensors(monitor_nvidia=config.governor.monitor_nvidia)
        plan = decide(r, config.governor, override)
        cpu = f"{r.cpu_temp}°C" if r.cpu_temp is not None else "n/d"
        mode_line = f"regime: {plan.mode.value} (CPU {cpu})"
    except Exception:
        pass
    vulns = ", ".join(f"{k}:{v}" for k, v in s["vuln_severities"].items()) or "0"
    jobs = ", ".join(f"{k}:{v}" for k, v in sorted(s["jobs"].items())) or "vuota"
    last = (s["last_sync_at"] or "mai")[:19].replace("T", " ")
    return (
        f"📊 BBH-Scanner\n"
        f"{mode_line}\n"
        f"programmi: {st['programs']} ({s['programs_enabled']} attivi)\n"
        f"asset: {st['assets']} (host vivi: {s['alive_hosts']})\n"
        f"findings: {st['findings']} · vuln[{vulns}]\n"
        f"coda: {jobs}\n"
        f"ultima sync: {last}"
    )


def format_findings(store: Store, args: list) -> str:
    sev = None
    if args and args[0].lower() in ("info", "low", "medium", "high", "critical"):
        sev = [args[0].lower()]
    rows = store.list_findings(severities=sev, limit=15)
    if not rows:
        return "nessun finding."
    lines = [f"[{(r['severity'] or '?')}] {r['program_handle']}: {r['title']}" for r in rows]
    return "🔎 Findings recenti:\n" + "\n".join(lines)


def format_logs(store: Store, n: int = 10) -> str:
    rows = store.recent_events(min(max(n, 1), 30))
    if not rows:
        return "nessun evento."
    lines = [f"{(e['ts'] or '')[11:19]} {e['level']} [{e['component']}] {e['message']}"
             for e in rows]
    return "📜 Log:\n" + "\n".join(lines)


def format_jobs(store: Store) -> str:
    counts = store.job_counts()
    return "🧰 coda: " + (", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) or "vuota")


def format_sensors(store: Store, config: Config) -> str:
    from bbh_scanner.resources.governor import decide
    from bbh_scanner.resources.sensors import sample_sensors
    override = store.get_state(MODE_OVERRIDE_KEY) or "auto"
    r = sample_sensors(monitor_nvidia=config.governor.monitor_nvidia)
    plan = decide(r, config.governor, override)

    def t(v):
        return f"{v}°C" if v is not None else "n/d"

    return (f"🌡️ CPU {t(r.cpu_temp)} · GPU {t(r.gpu_temp)} · load "
            f"{r.cpu_load if r.cpu_load is not None else 'n/d'}%\n"
            f"regime: {plan.mode.value} ({plan.reason})")


# --- Dispatch dei comandi -------------------------------------------------- #

def handle_command(text: str, store: Store, config: Config) -> Optional[str]:
    """Mappa un messaggio in una risposta. `None` = ignora (non è un comando)."""
    text = (text or "").strip()
    if not text.startswith("/"):
        return None
    parts = text.split()
    cmd = parts[0].lstrip("/").lower().split("@")[0]  # gestisce /cmd@nomebot
    args = parts[1:]

    if cmd in ("start", "help"):
        return HELP
    if cmd == "status":
        return format_status(store, config)
    if cmd == "findings":
        return format_findings(store, args)
    if cmd == "logs":
        n = int(args[0]) if args and args[0].isdigit() else 10
        return format_logs(store, n)
    if cmd == "jobs":
        return format_jobs(store)
    if cmd == "sensors":
        return format_sensors(store, config)
    if cmd == "mode":
        if not args or args[0].lower() not in _MODES:
            return f"uso: /mode <{'|'.join(_MODES)}>"
        store.set_state(MODE_OVERRIDE_KEY, args[0].lower())
        return f"✅ regime → {args[0].lower()} (attivo al prossimo tick)"
    if cmd == "pause":
        store.set_state(MODE_OVERRIDE_KEY, "paused")
        return "⏸️ sospeso."
    if cmd == "resume":
        store.set_state(MODE_OVERRIDE_KEY, "auto")
        return "▶️ ripreso (auto)."
    return "comando sconosciuto — /help"


# --- Poller (rete) --------------------------------------------------------- #

class TelegramPoller:
    def __init__(self, config: Config, db_path, stop_event: Optional[threading.Event] = None,
                 session: Any = None, sleep=time.sleep):
        self.config = config
        self.db_path = db_path
        self._stop = stop_event or threading.Event()
        self._sleep = sleep
        if session is not None:
            self.session = session
        else:
            import requests

            self.session = requests.Session()

    def _api(self, method: str, **params) -> dict:
        url = f"https://api.telegram.org/bot{self.config.telegram.bot_token}/{method}"
        resp = self.session.get(url, params=params, timeout=35)
        return resp.json()

    def _send(self, text: str) -> None:
        self._api("sendMessage", chat_id=self.config.telegram.chat_id, text=text)

    def register_commands(self) -> bool:
        """Registra il menu comandi in Telegram (la lista che appare digitando '/')."""
        import json
        cmds = [{"command": c, "description": d} for c, d in BOT_COMMANDS]
        try:
            self._api("setMyCommands", commands=json.dumps(cmds))
            return True
        except Exception:
            return False

    def poll_once(self, store: Store, offset: int) -> int:
        """Un giro di getUpdates. Ritorna il nuovo offset. Ignora chat non autorizzate."""
        body = self._api("getUpdates", offset=offset, timeout=20)
        new_offset = offset
        for u in body.get("result", []) or []:
            new_offset = u.get("update_id", offset) + 1
            msg = u.get("message") or u.get("channel_post") or {}
            chat_id = str((msg.get("chat") or {}).get("id", ""))
            if chat_id != str(self.config.telegram.chat_id):
                continue  # sicurezza: solo la tua chat
            reply = handle_command(msg.get("text", ""), store, self.config)
            if reply:
                self._send(reply)
        return new_offset

    def run(self) -> None:  # pragma: no cover - loop di rete
        store = Store(self.db_path)  # connessione propria del thread
        self.register_commands()     # popola il menu "/" in Telegram
        try:
            offset = int(store.get_state(OFFSET_KEY) or 0)
            while not self._stop.is_set():
                try:
                    new_offset = self.poll_once(store, offset)
                    if new_offset != offset:
                        offset = new_offset
                        store.set_state(OFFSET_KEY, str(offset))
                except Exception:
                    self._sleep(5)
        finally:
            store.close()

    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="telegram-bot", daemon=True)
        t.start()
        return t
