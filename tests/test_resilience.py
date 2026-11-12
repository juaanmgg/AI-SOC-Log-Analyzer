import threading
import time

import httpx

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.geo import HTTPXGeoIPAdapter
from ai_soc.services.tailer import LogTailer


def test_geoip_cache_uses_one_http_request() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"country": "ES"}, request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = HTTPXGeoIPAdapter(client=client)

    assert adapter.get_country("8.8.8.8") == "ES"
    assert adapter.get_country("8.8.8.8") == "ES"
    assert calls == 1
    client.close()


def test_geoip_timeout_degrades_after_retries() -> None:
    calls = 0

    def fail(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("timeout", request=request)

    client = httpx.Client(transport=httpx.MockTransport(fail))
    adapter = HTTPXGeoIPAdapter(client=client)
    assert adapter.get_country("8.8.8.8") == "Desconocido"
    assert calls == 3
    client.close()


def test_log_tailer_reads_new_lines_and_rotated_file(tmp_path) -> None:
    path = tmp_path / "auth.log"
    path.touch()
    tailer = LogTailer(path, poll_interval=0.01)
    lines = tailer.follow()

    def append_line(text: str) -> None:
        time.sleep(0.03)
        with path.open("a", encoding="utf-8") as file:
            file.write(text)

    writer = threading.Thread(target=append_line, args=("first\n",))
    writer.start()
    assert next(lines) == "first\n"
    writer.join()

    rotated = tmp_path / "auth.log.1"
    path.rename(rotated)
    path.touch()
    writer = threading.Thread(target=append_line, args=("after-rotation\n",))
    writer.start()
    assert next(lines) == "after-rotation\n"
    writer.join()
    lines.close()


def test_database_wal_allows_concurrent_writes(tmp_path) -> None:
    database = DatabaseManager(str(tmp_path / "threats.db"))
    errors: list[Exception] = []

    def write_records(offset: int) -> None:
        try:
            for index in range(10):
                database.registrar_amenaza(
                    f"192.0.2.{offset + index}",
                    "TEST",
                    "Scanner",
                    "Media",
                    1,
                )
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=write_records, args=(offset,)) for offset in (1, 21)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    with database._connection() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
