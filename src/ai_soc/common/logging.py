"""Configuración de logging estándar y JSON."""

import json
import logging
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Serializa registros con campos estándar y valores extra."""

    _reserved = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        payload.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in self._reserved and not key.startswith("_")
            }
        )
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configura el logger raíz de forma idempotente."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Nivel de logging inválido: {level}")

    root = logging.getLogger()
    root.setLevel(numeric_level)
    handler = logging.StreamHandler()
    handler.setFormatter(
        JSONFormatter()
        if json_format
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    for existing in root.handlers[:]:
        root.removeHandler(existing)
        existing.close()
    root.addHandler(handler)
