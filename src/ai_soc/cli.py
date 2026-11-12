"""Punto de entrada CLI del analizador modular."""

import argparse
import logging
import os
import time
from collections import defaultdict, deque
from collections.abc import Iterable

from langchain_groq import ChatGroq

from ai_soc.adapters.database import DatabaseManager
from ai_soc.adapters.firewall import NetshAdapter, UfwAdapter
from ai_soc.adapters.geo import HTTPXGeoIPAdapter
from ai_soc.common.logging import setup_logging
from ai_soc.services.analyzer import AnalyzerService
from ai_soc.services.rollback import RollbackWorker
from ai_soc.services.tailer import LogTailer

LOGGER = logging.getLogger(__name__)


def _positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("debe ser un entero positivo")
    return number


def _collect_logs(lines: Iterable[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for line in lines:
        if any(keyword in line.lower() for keyword in ("failed", "invalid", "error", "denied")):
            parts = line.split()
            for part in parts:
                if part.count(".") == 3 and all(item.isdigit() for item in part.split(".")):
                    grouped[part].append(line.strip())
                    break
    return grouped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOC Log Analyzer modular")
    parser.add_argument("--log", required=True)
    parser.add_argument("--groq-key", default=os.getenv("GROQ_API_KEY"))
    parser.add_argument("--whitelist", default="whitelist.txt")
    parser.add_argument("--ban-time", type=_positive_integer, default=24)
    parser.add_argument("--threshold", type=_positive_integer, default=3)
    parser.add_argument("--auto-block", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-logs", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(json_format=args.json_logs)
    if not args.groq_key:
        raise SystemExit("Falta GROQ_API_KEY. Configura la variable de entorno.")

    database = DatabaseManager()
    firewall = NetshAdapter() if os.name == "nt" else UfwAdapter()
    geoip = HTTPXGeoIPAdapter()
    llm = ChatGroq(  # type: ignore[call-arg]
        model="openai/gpt-oss-20b", groq_api_key=args.groq_key, temperature=0
    )
    whitelist = {"127.0.0.1", "localhost"}
    if os.path.exists(args.whitelist):
        with open(args.whitelist, encoding="utf-8") as file:
            whitelist.update(line.strip() for line in file if line.strip())

    analyzer = AnalyzerService(
        llm,
        database,
        firewall,
        geoip,
        whitelist,
        args.ban_time,
        auto_block=args.auto_block,
        dry_run=args.dry_run,
    )
    rollback = RollbackWorker(database, firewall)
    tailer = LogTailer(args.log)
    recent: deque[tuple[float, str]] = deque()
    last_analysis = time.monotonic()
    rollback.start()
    LOGGER.info("Vigilando archivo de logs", extra={"path": args.log})
    try:
        for line in tailer.follow():
            now = time.monotonic()
            recent.append((now, line))
            while recent and now - recent[0][0] > 60:
                recent.popleft()
            if now - last_analysis >= 10:
                grouped = _collect_logs(item for _, item in recent)
                grouped = {ip: logs for ip, logs in grouped.items() if len(logs) >= args.threshold}
                if grouped:
                    analyzer.process(grouped)
                last_analysis = now
    except KeyboardInterrupt:
        LOGGER.info("SOC desconectado")
    finally:
        rollback.stop()
        geoip.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
