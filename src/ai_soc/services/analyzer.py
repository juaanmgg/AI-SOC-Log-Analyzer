"""Orquestación del análisis LLM y su fallback heurístico."""

import ipaddress
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.firewall.base import FirewallAdapter
from ai_soc.adapters.geo import GeoIPProvider
from ai_soc.adapters.llm import GroqThreatDetector
from ai_soc.domain.models import SeverityEnum, ThreatItem, ThreatReport
from ai_soc.services.heuristic import HeuristicFallbackAnalyzer
from ai_soc.services.sanitizer import LogSanitizer

LOGGER = logging.getLogger(__name__)


class SOCAnalyzer:
    """Analiza evidencia con LLM y activa fallback ante fallos de inferencia."""

    def __init__(
        self,
        detector: GroqThreatDetector,
        fallback: HeuristicFallbackAnalyzer,
        sanitizer: LogSanitizer,
        database: DatabaseManager,
        firewall: FirewallAdapter,
        geoip: GeoIPProvider,
        whitelist: set[str],
        ban_time_hours: int,
        auto_block: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.detector = detector
        self.fallback = fallback
        self.sanitizer = sanitizer
        self.database = database
        self.firewall = firewall
        self.geoip = geoip
        self.whitelist = whitelist
        self.ban_time_hours = ban_time_hours
        self.auto_block = auto_block
        self.dry_run = dry_run

    def analyze(self, raw_logs: Mapping[str, Sequence[str]]) -> ThreatReport:
        """Sanitiza, agrega y clasifica logs con fallback resiliente."""
        safe_logs = {ip: list(lines) for ip, lines in raw_logs.items()}
        evidence = self.sanitizer.wrap_untrusted_content(safe_logs)
        try:
            return self.detector.analyze(evidence)
        except Exception as error:
            LOGGER.warning(
                "LLM inaccesible o cuota excedida. Activando motor heurístico de contingencia.",
                extra={"error": str(error)},
            )
            return self.fallback.analyze(raw_logs)

    def process(self, raw_logs: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
        """Procesa amenazas validadas y aplica la respuesta configurada."""
        actions: list[str] = []
        for threat in self.analyze(raw_logs).amenazas:
            ip = str(threat.ip)
            if ip in self.whitelist:
                actions.append(f"Ignorada (Whitelist): {ip}")
                continue
            if self.dry_run or not self.auto_block:
                actions.append(f"Simulada: {ip} - {threat.tipo}")
                LOGGER.info("Acción simulada", extra={"ip": ip, "tipo": threat.tipo})
                continue

            country = self.geoip.get_country(ip)
            if not self.firewall.block_ip(ip):
                actions.append(f"Error de firewall: {ip}")
                continue
            self.database.registrar_amenaza(
                ip,
                country,
                threat.tipo,
                threat.severidad.value,
                self.ban_time_hours,
            )
            actions.append(f"Bloqueada: {ip} ({country}) - {threat.tipo}")
            LOGGER.info(
                "IP bloqueada",
                extra={"ip": ip, "country": country, "severity": threat.severidad.value},
            )
        return {"acciones_ejecutadas": actions}


AnalyzerService = SOCAnalyzer


def normalize_threats(result: Any) -> list[ThreatItem]:
    """Normaliza respuestas parciales para consumidores legacy."""
    if not isinstance(result, dict):
        raise TypeError("La respuesta del LLM debe ser un objeto JSON")
    threats = result.get("amenazas", [])
    if not isinstance(threats, list):
        raise TypeError("'amenazas' debe ser una lista")
    normalized: list[ThreatItem] = []
    for threat in threats:
        if not isinstance(threat, dict) or not isinstance(threat.get("ip"), str):
            continue
        try:
            ipaddress.ip_address(threat["ip"])
            severity = threat.get("severidad", SeverityEnum.MEDIA.value)
            if severity not in {item.value for item in SeverityEnum}:
                severity = SeverityEnum.MEDIA.value
            normalized.append(
                ThreatItem(
                    ip=threat["ip"],
                    tipo=str(threat.get("tipo", "Desconocido")),
                    severidad=severity,
                )
            )
        except (ValueError, ValidationError):
            continue
    return normalized
