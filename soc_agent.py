"""Fachada retrocompatible para la CLI modular de AI-SOC."""

from typing import Any, Protocol

from ai_soc import compat as _compat
from ai_soc.cli import main

ChatGroq: Any = _compat.ChatGroq
DatabaseManager: Any = _compat.DatabaseManager
SOCAnalyzer: Any = _compat.SOCAnalyzer
ahora_utc: Any = _compat.ahora_utc
cargar_whitelist: Any = _compat.cargar_whitelist
hilo_rollback: Any = _compat.hilo_rollback
recolectar_logs: Any = _compat.recolectar_logs
entero_positivo: Any = _compat.entero_positivo
requests: Any = _compat.requests
subprocess: Any = _compat.subprocess


def crear_llm(groq_key: str | None) -> Any:
    """Mantiene el constructor legacy sincronizado con el módulo compat."""
    _compat.ChatGroq = ChatGroq  # type: ignore[misc]
    return _compat.crear_llm(groq_key)


class LegacyArguments(Protocol):
    """Argumentos mínimos aceptados por la entrada legacy."""

    log: str
    threshold: int
    window_seconds: int
    ban_time: int
    groq_key: str | None
    whitelist: str | None
    auto_block: bool
    dry_run: bool


def iniciar_soc(args: LegacyArguments, es_windows: bool) -> int:
    """Redirige consumidores legacy al entrypoint modular."""
    del es_windows
    arguments = [
        "--log",
        args.log,
        "--threshold",
        str(args.threshold),
        "--window-seconds",
        str(args.window_seconds),
        "--ban-time",
        str(args.ban_time),
    ]
    if args.groq_key:
        arguments.extend(["--groq-key", args.groq_key])
    if args.whitelist:
        arguments.extend(["--whitelist", args.whitelist])
    if getattr(args, "auto_block", False):
        arguments.append("--auto-block")
    if getattr(args, "dry_run", False):
        arguments.append("--dry-run")
    return main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
