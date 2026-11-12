"""Adaptador seguro para UFW en Linux."""

import ipaddress
import logging
import subprocess

from ai_soc.adapters.firewall.base import FirewallAdapter

LOGGER = logging.getLogger(__name__)


class UfwAdapter(FirewallAdapter):
    """Ejecuta reglas UFW sin pasar por una shell."""

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
            LOGGER.exception("No se pudo ejecutar el comando UFW")
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
        return self._run(["ufw", "deny", "from", ip, "to", "any"])

    def unblock_ip(self, ip: str) -> bool:
        if not self._valid_ip(ip):
            return False
        return self._run(["ufw", "delete", "deny", "from", ip, "to", "any"])
