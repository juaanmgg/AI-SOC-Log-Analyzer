import subprocess
from unittest.mock import patch

from ai_soc.adapters.firewall.netsh import NetshAdapter
from ai_soc.adapters.firewall.ufw import UfwAdapter


def test_ufw_block_and_unblock_commands() -> None:
    with patch("ai_soc.adapters.firewall.ufw.subprocess.run") as run:
        assert UfwAdapter().block_ip("203.0.113.10") is True
        run.assert_called_once_with(
            ["ufw", "deny", "from", "203.0.113.10", "to", "any"],
            check=True,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run.reset_mock()
        assert UfwAdapter().unblock_ip("203.0.113.10") is True
        run.assert_called_once_with(
            ["ufw", "delete", "deny", "from", "203.0.113.10", "to", "any"],
            check=True,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def test_ufw_returns_false_for_execution_errors() -> None:
    with patch(
        "ai_soc.adapters.firewall.ufw.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "ufw"),
    ):
        assert UfwAdapter().block_ip("203.0.113.10") is False
    with patch(
        "ai_soc.adapters.firewall.ufw.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        assert UfwAdapter().unblock_ip("203.0.113.10") is False
    assert UfwAdapter().block_ip("not-an-ip") is False


def test_netsh_block_and_unblock_commands() -> None:
    with patch("ai_soc.adapters.firewall.netsh.subprocess.run") as run:
        assert NetshAdapter().block_ip("198.51.100.10") is True
        run.assert_called_once_with(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=SOC_198.51.100.10",
                "dir=in",
                "action=block",
                "remoteip=198.51.100.10",
            ],
            check=True,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run.reset_mock()
        assert NetshAdapter().unblock_ip("198.51.100.10") is True
        run.assert_called_once_with(
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=SOC_198.51.100.10"],
            check=True,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def test_netsh_returns_false_for_execution_errors() -> None:
    with patch(
        "ai_soc.adapters.firewall.netsh.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "netsh"),
    ):
        assert NetshAdapter().block_ip("198.51.100.10") is False
    with patch(
        "ai_soc.adapters.firewall.netsh.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        assert NetshAdapter().unblock_ip("198.51.100.10") is False
    assert NetshAdapter().unblock_ip("not-an-ip") is False
