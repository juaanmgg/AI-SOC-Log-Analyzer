"""Servicio de análisis y respuesta táctica."""

import ipaddress
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from pydantic import ValidationError

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.firewall.base import FirewallAdapter
from ai_soc.adapters.geo import GeoIPProvider
from ai_soc.domain.models import SeverityEnum, ThreatItem, ThreatReport

LOGGER = logging.getLogger(__name__)


class AnalyzerService:
    """Orquesta clasificación LLM, GeoIP, firewall y persistencia."""

    def __init__(
        self,
        llm: Any,
        database: DatabaseManager,
        firewall: FirewallAdapter,
        geoip: GeoIPProvider,
        whitelist: set[str],
        ban_time_hours: int,
        auto_block: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.database = database
        self.firewall = firewall
        self.geoip = geoip
        self.whitelist = whitelist
        self.ban_time_hours = ban_time_hours
        self.auto_block = auto_block
        self.dry_run = dry_run
        prompt = PromptTemplate(
            template=(
                "Analiza estos logs y devuelve únicamente JSON con la clave "
                '"amenazas" y los campos ip, tipo y severidad:\n{logs}'
            ),
            input_variables=["logs"],
        )
        self._chain = prompt | llm | JsonOutputParser()

    def analyze(self, raw_logs: Mapping[str, Sequence[str]]) -> list[ThreatItem]:
        summary = "\n".join(
            f"\n--- IP: {ip} ---\n" + "\n".join(lines[:10]) for ip, lines in raw_logs.items()
        )
        try:
            result = self._chain.invoke({"logs": summary})
            report = ThreatReport(amenazas=normalize_threats(result))
        except (TypeError, ValueError, ValidationError) as error:
            raise RuntimeError("Respuesta inválida del LLM") from error
        return report.amenazas

    def process(self, raw_logs: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
        actions: list[str] = []
        for threat in self.analyze(raw_logs):
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


def normalize_threats(result: Any) -> list[ThreatItem]:
    """Normaliza respuestas parciales del LLM para compatibilidad de datos."""
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
