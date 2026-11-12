"""Lector de logs con sondeo y detección de rotación."""

import logging
import time
from collections.abc import Generator
from pathlib import Path

LOGGER = logging.getLogger(__name__)


class LogTailer:
    """Sigue un archivo desde su final y reabre archivos rotados."""

    def __init__(self, path: str | Path, poll_interval: float = 0.5) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval debe ser positivo")
        self.path = Path(path)
        self.poll_interval = poll_interval

    def follow(self) -> Generator[str, None, None]:
        """Cede líneas nuevas sin bloquear indefinidamente el proceso."""
        file_handle = None
        identity: tuple[int, int] | None = None
        try:
            while True:
                try:
                    stat = self.path.stat()
                except FileNotFoundError:
                    time.sleep(self.poll_interval)
                    continue

                current_identity = (stat.st_dev, stat.st_ino)
                if file_handle is None or current_identity != identity:
                    if file_handle is not None:
                        file_handle.close()
                    file_handle = self.path.open(encoding="utf-8")
                    file_handle.seek(0, 2)
                    identity = current_identity
                    LOGGER.info("Siguiendo archivo de logs", extra={"path": str(self.path)})

                line = file_handle.readline()
                if line:
                    yield line
                    continue

                time.sleep(self.poll_interval)
        finally:
            if file_handle is not None:
                file_handle.close()
