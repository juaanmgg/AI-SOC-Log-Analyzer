import sqlite3
from unittest.mock import MagicMock

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.firewall.base import FirewallAdapter
from ai_soc.adapters.geo import GeoIPProvider
from ai_soc.domain.models import SeverityEnum, ThreatItem, ThreatReport
from ai_soc.services.analyzer import SOCAnalyzer
from ai_soc.services.heuristic import HeuristicFallbackAnalyzer
from ai_soc.services.rollback import RollbackWorker
from ai_soc.services.sanitizer import LogSanitizer


def test_end_to_end_detection_persistence_and_rollback(tmp_path) -> None:
    log_path = tmp_path / "auth.log"
    events = [
        "Failed password for root from 203.0.113.50\n",
        "Failed password for admin from 203.0.113.50\n",
        "Invalid user guest from 203.0.113.50\n",
    ]
    log_path.write_text("".join(events), encoding="utf-8")

    database = DatabaseManager(str(tmp_path / "threats.db"))
    firewall = MagicMock(spec=FirewallAdapter)
    firewall.block_ip.return_value = True
    firewall.unblock_ip.return_value = True
    geoip = MagicMock(spec=GeoIPProvider)
    geoip.get_country.return_value = "ES"
    detector = MagicMock()
    detector.analyze.return_value = ThreatReport(
        amenazas=[
            ThreatItem(
                ip="203.0.113.50",
                tipo="Fuerza Bruta SSH",
                severidad=SeverityEnum.ALTA,
            )
        ]
    )
    analyzer = SOCAnalyzer(
        detector=detector,
        fallback=HeuristicFallbackAnalyzer(),
        sanitizer=LogSanitizer(),
        database=database,
        firewall=firewall,
        geoip=geoip,
        whitelist=set(),
        ban_time_hours=1,
        auto_block=True,
    )

    result = analyzer.process({"203.0.113.50": log_path.read_text(encoding="utf-8").splitlines()})

    assert result["acciones_ejecutadas"] == ["Bloqueada: 203.0.113.50 (ES) - Fuerza Bruta SSH"]
    with database._connection() as connection:
        active = connection.execute(
            "SELECT activo FROM amenazas WHERE ip = ?", ("203.0.113.50",)
        ).fetchone()[0]
        connection.execute(
            "UPDATE amenazas SET expira_en = ? WHERE ip = ?",
            ("2000-01-01T00:00:00+00:00", "203.0.113.50"),
        )
    assert active == 1

    worker = RollbackWorker(database, firewall, interval=0.01)
    worker._process_expired()

    firewall.unblock_ip.assert_called_once_with("203.0.113.50")
    with sqlite3.connect(tmp_path / "threats.db") as connection:
        inactive = connection.execute(
            "SELECT activo FROM amenazas WHERE ip = ?", ("203.0.113.50",)
        ).fetchone()[0]
    assert inactive == 0


def test_analyzer_processes_firewall_failure_without_persisting() -> None:
    detector = MagicMock()
    detector.analyze.return_value = ThreatReport(
        amenazas=[ThreatItem(ip="198.51.100.8", tipo="Scanner", severidad=SeverityEnum.MEDIA)]
    )
    database = MagicMock()
    firewall = MagicMock(spec=FirewallAdapter)
    firewall.block_ip.return_value = False
    analyzer = SOCAnalyzer(
        detector=detector,
        fallback=HeuristicFallbackAnalyzer(),
        sanitizer=LogSanitizer(),
        database=database,
        firewall=firewall,
        geoip=MagicMock(spec=GeoIPProvider),
        whitelist=set(),
        ban_time_hours=1,
        auto_block=True,
    )

    result = analyzer.process({"198.51.100.8": ["error"]})

    assert result["acciones_ejecutadas"] == ["Error de firewall: 198.51.100.8"]
    database.registrar_amenaza.assert_not_called()
