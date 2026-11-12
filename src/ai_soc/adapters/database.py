"""Persistencia SQLite de amenazas."""

import sqlite3
from datetime import datetime, timedelta, timezone


class DatabaseManager:
    """Gestiona el ciclo de vida de amenazas en SQLite."""

    def __init__(self, db_path: str = "threat_intel.db") -> None:
        self.db_path = db_path
        self._inicializar_db()

    def _inicializar_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS amenazas
                (id INTEGER PRIMARY KEY, fecha TEXT, ip TEXT, pais TEXT,
                 tipo TEXT, severidad TEXT, expira_en TEXT, activo INTEGER)"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_amenazas_expiracion "
                "ON amenazas (activo, expira_en)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_amenazas_ip_activa "
                "ON amenazas (ip, activo)"
            )

    @staticmethod
    def _ahora_utc() -> datetime:
        return datetime.now(timezone.utc)

    def registrar_amenaza(
        self, ip: str, pais: str, tipo: str, severidad: str, ban_time_hours: int
    ) -> None:
        fecha = self._ahora_utc()
        expiracion = fecha + timedelta(hours=ban_time_hours)
        with sqlite3.connect(self.db_path) as conn:
            actualizado = conn.execute(
                """UPDATE amenazas SET fecha = ?, pais = ?, tipo = ?, severidad = ?,
                expira_en = ?, activo = 1 WHERE ip = ? AND activo = 1""",
                (fecha.isoformat(), pais, tipo, severidad, expiracion.isoformat(), ip),
            ).rowcount
            if not actualizado:
                conn.execute(
                    "INSERT INTO amenazas "
                    "(fecha, ip, pais, tipo, severidad, expira_en, activo) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (fecha.isoformat(), ip, pais, tipo, severidad, expiracion.isoformat()),
                )

    def obtener_ips_expiradas(self) -> list[str]:
        ahora = self._ahora_utc().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """SELECT DISTINCT amenaza.ip FROM amenazas AS amenaza
                WHERE amenaza.activo = 1 AND amenaza.expira_en <= ?
                AND NOT EXISTS (
                    SELECT 1 FROM amenazas AS vigente
                    WHERE vigente.ip = amenaza.ip AND vigente.activo = 1
                    AND vigente.expira_en > ?
                )""",
                (ahora, ahora),
            )
            return [fila[0] for fila in cursor.fetchall()]

    def marcar_desbloqueada(self, ip: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE amenazas SET activo = 0 "
                "WHERE ip = ? AND activo = 1 AND expira_en <= ?",
                (ip, self._ahora_utc().isoformat()),
            )
