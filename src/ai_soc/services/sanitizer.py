"""Sanitización y compactación de evidencia no confiable."""

import html
import re


class LogSanitizer:
    """Neutraliza contenido de logs antes de entregarlo a un modelo."""

    _ansi_escape = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    _variable_tokens = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d+\b")

    def __init__(self, max_length: int = 300) -> None:
        if max_length <= 0:
            raise ValueError("max_length debe ser positivo")
        self.max_length = max_length

    def sanitize_line(self, line: str) -> str:
        """Elimina controles, escapes y exceso de longitud."""
        sanitized = self._ansi_escape.sub("", line)
        sanitized = "".join(
            character for character in sanitized if character in "\n\r\t" or character.isprintable()
        )
        return sanitized[: self.max_length]

    def aggregate_logs(self, logs: list[str]) -> list[str]:
        """Agrupa líneas iguales o con el mismo patrón variable."""
        grouped: dict[str, tuple[str, int]] = {}
        order: list[str] = []
        for raw_line in logs:
            line = self.sanitize_line(raw_line)
            key = self._variable_tokens.sub("<variable>", line)
            if key not in grouped:
                grouped[key] = (line, 0)
                order.append(key)
            representative, count = grouped[key]
            grouped[key] = (representative, count + 1)

        result: list[str] = []
        for key in order:
            representative, count = grouped[key]
            result.append(f"[Repetido {count}x] {representative}" if count > 1 else representative)
        return result

    def wrap_untrusted_content(self, logs_by_ip: dict[str, list[str]]) -> str:
        """Envuelve evidencia escapada en bloques XML delimitados."""
        blocks: list[str] = []
        for ip, logs in logs_by_ip.items():
            safe_ip = html.escape(ip, quote=True)
            safe_logs = "\n".join(
                html.escape(line, quote=False) for line in self.aggregate_logs(logs)
            )
            blocks.append(
                f'<untrusted_evidence ip="{safe_ip}">\n{safe_logs}\n</untrusted_evidence>'
            )
        return "\n".join(blocks)
