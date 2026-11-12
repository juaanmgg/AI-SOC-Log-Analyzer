"""Motor local de contingencia para señales de alta certeza."""

import ipaddress
import re
from collections.abc import Mapping, Sequence

from ai_soc.domain.models import SeverityEnum, ThreatItem, ThreatReport


class HeuristicFallbackAnalyzer:
    """Clasifica firmas de ataque sin depender de un proveedor externo."""

    _ssh_signature = re.compile(r"(failed password|invalid user)", re.IGNORECASE)
    _web_signature = re.compile(r"(403 forbidden|404 not found)", re.IGNORECASE)

    def __init__(self, ssh_threshold: int = 3) -> None:
        if ssh_threshold <= 0:
            raise ValueError("ssh_threshold debe ser positivo")
        self.ssh_threshold = ssh_threshold

    def analyze(self, logs_by_ip: Mapping[str, Sequence[str]]) -> ThreatReport:
        threats: list[ThreatItem] = []
        for ip, lines in logs_by_ip.items():
            ssh_count = sum(bool(self._ssh_signature.search(line)) for line in lines)
            web_count = sum(bool(self._web_signature.search(line)) for line in lines)
            if ssh_count:
                severity = (
                    SeverityEnum.ALTA if ssh_count >= self.ssh_threshold else SeverityEnum.MEDIA
                )
                try:
                    parsed_ip = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                threats.append(
                    ThreatItem(ip=parsed_ip, tipo="Fuerza Bruta SSH", severidad=severity)
                )
            elif web_count:
                try:
                    parsed_ip = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                threats.append(
                    ThreatItem(
                        ip=parsed_ip,
                        tipo="Web Scanner / Probing",
                        severidad=SeverityEnum.MEDIA,
                    )
                )
        return ThreatReport(amenazas=threats)
