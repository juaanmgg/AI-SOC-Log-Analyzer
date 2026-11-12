"""Contrato común para adaptadores de firewall."""

from abc import ABC, abstractmethod


class FirewallAdapter(ABC):
    """Interfaz para bloquear y desbloquear direcciones IP."""

    @abstractmethod
    def block_ip(self, ip: str) -> bool:
        """Bloquea una IP y devuelve si la operación tuvo éxito."""

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Desbloquea una IP y devuelve si la operación tuvo éxito."""
