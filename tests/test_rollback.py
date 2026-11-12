import time
from unittest.mock import MagicMock

import pytest

from ai_soc.services.rollback import RollbackWorker


def test_rollback_processes_success_and_logs_failed_unblock() -> None:
    database = MagicMock()
    database.obtener_ips_expiradas.return_value = ["203.0.113.1", "203.0.113.2"]
    firewall = MagicMock()
    firewall.unblock_ip.side_effect = [True, False]
    worker = RollbackWorker(database, firewall)

    worker._process_expired()

    database.marcar_desbloqueada.assert_called_once_with("203.0.113.1")
    assert firewall.unblock_ip.call_count == 2


def test_rollback_worker_starts_and_stops_daemon() -> None:
    database = MagicMock()
    database.obtener_ips_expiradas.return_value = []
    worker = RollbackWorker(database, MagicMock(), interval=0.01)

    worker.start()
    time.sleep(0.02)
    worker.start()
    worker.stop()
    worker.stop()

    assert database.obtener_ips_expiradas.call_count >= 1


def test_rollback_rejects_non_positive_interval() -> None:
    with pytest.raises(ValueError, match="positivo"):
        RollbackWorker(MagicMock(), MagicMock(), interval=0)
