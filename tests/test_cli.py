import signal
from unittest.mock import MagicMock, patch

import pytest

from ai_soc import cli


def test_cli_defaults_and_exclusive_modes() -> None:
    args = cli.build_parser().parse_args(["--log", "auth.log"])

    assert args.ban_time == 24
    assert args.threshold == 3
    assert args.window_seconds == 60
    assert args.auto_block is False
    assert args.dry_run is False
    assert args.json_logs is False
    assert cli.build_parser().parse_args(["--log", "auth.log", "--dry-run"]).dry_run is True
    assert cli.build_parser().parse_args(["--log", "auth.log", "--auto-block"]).auto_block is True
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--log", "auth.log", "--dry-run", "--auto-block"])


@pytest.mark.parametrize("argument", ["--threshold", "--ban-time", "--window-seconds"])
def test_cli_rejects_non_positive_values(argument: str) -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--log", "auth.log", argument, "0"])


def test_cli_json_logs_configures_structured_logging() -> None:
    with (
        patch("ai_soc.cli.setup_logging") as setup_logging,
        pytest.raises(SystemExit, match="Falta GROQ_API_KEY"),
    ):
        cli.main(["--log", "auth.log", "--json-logs"])

    setup_logging.assert_called_once_with(json_format=True)


def test_cli_signal_handler_stops_rollback_worker() -> None:
    worker = MagicMock()

    with pytest.raises(cli.GracefulShutdown):
        cli._shutdown_handler(signal.SIGINT, None, worker)

    worker.stop.assert_called_once_with()


def test_cli_installs_and_restores_signal_handlers() -> None:
    worker = MagicMock()
    previous_handler = MagicMock()
    with patch("ai_soc.cli.signal.signal", return_value=previous_handler) as signal_call:
        previous = cli.install_signal_handlers(worker)
        cli.restore_signal_handlers(previous)

    assert previous == {signal.SIGINT: previous_handler, signal.SIGTERM: previous_handler}
    assert signal_call.call_count == 4


def test_cli_collects_only_suspicious_ipv4_lines() -> None:
    result = cli._collect_logs(
        [
            "Failed password from 203.0.113.8",
            "Successful login from 203.0.113.8",
            "Invalid user from 198.51.100.4",
        ]
    )

    assert result == {
        "203.0.113.8": ["Failed password from 203.0.113.8"],
        "198.51.100.4": ["Invalid user from 198.51.100.4"],
    }


def test_cli_main_stops_cleanly_after_shutdown() -> None:
    tailer = MagicMock()
    tailer.follow.side_effect = cli.GracefulShutdown
    with (
        patch("ai_soc.cli.setup_logging"),
        patch("ai_soc.cli.DatabaseManager"),
        patch("ai_soc.cli.UfwAdapter"),
        patch("ai_soc.cli.HTTPXGeoIPAdapter"),
        patch("ai_soc.cli.GroqThreatDetector"),
        patch("ai_soc.cli.SOCAnalyzer"),
        patch("ai_soc.cli.RollbackWorker") as worker_class,
        patch("ai_soc.cli.LogTailer", return_value=tailer),
        patch("ai_soc.cli.install_signal_handlers", return_value={}),
        patch("ai_soc.cli.restore_signal_handlers"),
    ):
        result = cli.main(["--log", "auth.log", "--groq-key", "test-key"])

    assert result == 0
    worker_class.return_value.start.assert_called_once_with()
    worker_class.return_value.stop.assert_called_once_with()
