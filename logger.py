"""
Alert Logger — writes alerts to .log and .json files.
"""

import logging
import json
import os
from datetime import datetime


class AlertLogger:
    def __init__(self, log_path: str = "alerts/alerts.log"):
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self.log_path  = log_path
        self.json_path = log_path.replace(".log", ".json")
        logging.basicConfig(
            filename=log_path, level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger("IDS")
        self._json_entries: list = []

    def log(self, severity: str, rule: str, src: str, dst: str, detail: str) -> dict:
        now     = datetime.now()
        message = f"[{severity}] Rule={rule} | Src={src} | Dst={dst} | {detail}"
        if severity == "HIGH":     self.logger.error(message)
        elif severity == "MEDIUM": self.logger.warning(message)
        else:                      self.logger.info(message)
        entry = {
            "timestamp": now.isoformat(),
            "time":      now.strftime("%H:%M:%S"),
            "severity":  severity,
            "rule":      rule,
            "src":       src,
            "dst":       dst,
            "detail":    detail,
        }
        self._json_entries.append(entry)
        with open(self.json_path, "w") as f:
            json.dump(self._json_entries, f, indent=2)
        return entry
