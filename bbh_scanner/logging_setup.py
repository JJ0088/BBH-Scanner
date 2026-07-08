"""Logging strutturato (JSON opzionale) su file + console."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(logs_dir: Path, level: str = "INFO", json_format: bool = True) -> logging.Logger:
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
    log_file = logs_dir / f"bbh_{ts}.log"

    logger = logging.getLogger("bbh")
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.handlers.clear()

    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    console_handler = logging.StreamHandler()
    if json_format:
        file_handler.setFormatter(JsonFormatter())
    else:
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
    console_handler.setFormatter(
        logging.Formatter("%(levelname)s %(message)s")
    )
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
