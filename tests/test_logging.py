import json
import logging

import pytest

from ai_soc.common.logging import JSONFormatter, setup_logging


def test_json_formatter_includes_standard_and_extra_fields() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    record.request_id = "abc"

    payload = json.loads(JSONFormatter().format(record))

    assert payload["logger"] == "test"
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "abc"
    assert "timestamp" in payload


def test_setup_logging_supports_standard_and_json_formats() -> None:
    setup_logging("WARNING", json_format=False)
    root = logging.getLogger()
    assert root.level == logging.WARNING
    assert isinstance(root.handlers[0].formatter, logging.Formatter)

    setup_logging("INFO", json_format=True)
    assert isinstance(root.handlers[0].formatter, JSONFormatter)


def test_setup_logging_rejects_unknown_level() -> None:
    with pytest.raises(ValueError, match="inválido"):
        setup_logging("NOT_A_LEVEL")
