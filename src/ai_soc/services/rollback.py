"""Worker de rollback de reglas expiradas."""

import logging
from threading import Event, Thread, current_thread

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.firewall.base import FirewallAdapter

LOGGER = logging.getLogger(__name__)


class RollbackWorker:
    """Desbloquea periódicamente IPs expiradas en un hilo daemon."""

    def __init__(
        self,
        database: DatabaseManager,
        firewall: FirewallAdapter,
        interval: float = 60.0,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval debe ser positivo")
        self.database = database
        self.firewall = firewall
        self.interval = interval
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = Thread(target=self._run, name="rollback-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread is not current_thread():
            self._thread.join(timeout=self.interval + 1)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._process_expired()
            self._stop_event.wait(self.interval)

    def _process_expired(self) -> None:
        for ip in self.database.obtener_ips_expiradas():
            if self.firewall.unblock_ip(ip):
                self.database.marcar_desbloqueada(ip)
                LOGGER.info("IP desbloqueada tras expirar", extra={"ip": ip})
            else:
                LOGGER.error("No se pudo desbloquear IP expirada", extra={"ip": ip})
