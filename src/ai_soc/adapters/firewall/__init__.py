"""Adaptadores de firewall soportados."""

from ai_soc.adapters.firewall.base import FirewallAdapter
from ai_soc.adapters.firewall.netsh import NetshAdapter
from ai_soc.adapters.firewall.ufw import UfwAdapter

__all__ = ["FirewallAdapter", "NetshAdapter", "UfwAdapter"]
