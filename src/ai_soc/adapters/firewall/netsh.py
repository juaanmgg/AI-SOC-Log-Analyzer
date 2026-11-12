"""Adaptador seguro para Windows netsh."""

import ipaddress
import logging
import subprocess

from ai_soc.adapters.firewall.base import FirewallAdapter

LOGGER = logging.getLogger(__name__)


class NetshAdapter(FirewallAdapter):
    """Ejecuta reglas netsh sin pasar por una shell."""

    @staticmethod
    def _run(command: list[str]) -> bool:
        try:
            subprocess.run(
                command,
                check=True,
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            LOGGER.exception("No se pudo ejecutar el comando netsh")
            return False
        return True

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        return True

    def block_ip(self, ip: str) -> bool:
        if not self._valid_ip(ip):
            return False
        return self._run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=SOC_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
        )

    def unblock_ip(self, ip: str) -> bool:
        if not self._valid_ip(ip):
            return False
        return self._run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SOC_{ip}"]
        )
