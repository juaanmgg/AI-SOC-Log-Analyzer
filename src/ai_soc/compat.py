"""Compatibilidad temporal para consumidores del módulo ``soc_agent``."""

import argparse
import ipaddress
import logging
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import requests
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_groq import ChatGroq

from ai_soc.adapters.database import DatabaseManager

LOGGER = logging.getLogger(__name__)
__all__ = [
    "ChatGroq",
    "DatabaseManager",
    "SOCAnalyzer",
    "ahora_utc",
    "cargar_whitelist",
    "crear_llm",
    "entero_positivo",
    "hilo_rollback",
    "recolectar_logs",
    "requests",
    "subprocess",
]
PALABRAS_CLAVE = re.compile(r"(?i)(failed|invalid|error|unauthorized|denied|403|404)")
REGEX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SEVERIDADES_VALIDAS = {"Baja", "Media", "Alta", "Crítica"}


def ahora_utc() -> datetime:
    return datetime.now(timezone.utc)


class SOCAnalyzer:
    """Adaptador de la API histórica hacia los servicios actuales."""

    def __init__(
        self,
        llm: Any,
        db_manager: DatabaseManager | None,
        whitelist: set[str],
        es_windows: bool,
        ban_time: int,
        auto_block: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.llm = llm
        self.db = db_manager
        self.whitelist = whitelist
        self.es_windows = es_windows
        self.ban_time = ban_time
        self.auto_block = auto_block
        self.dry_run = dry_run
        self._geo_cache: dict[str, tuple[float, str]] = {}
        self.parser = JsonOutputParser()
        self.prompt = PromptTemplate(
            template=(
                "Eres un Analista SOC Nivel 3. Analiza los logs y determina si son ataques "
                "(Fuerza Bruta, etc.) o falsos positivos.\nLogs a analizar:\n{logs}\n"
                'Devuelve ÚNICAMENTE un objeto JSON con la clave "amenazas" conteniendo: '
                '"ip", "tipo", "severidad". Si no hay ataques, devuelve la lista vacía.'
            ),
            input_variables=["logs"],
        )
        self.analyst_chain = self.prompt | self.llm | self.parser

    def analizar(self, datos_crudos: dict[str, list[str]]) -> list[dict[str, str]]:
        resumen = "\n".join(
            f"\n--- IP: {ip} ---\n" + "\n".join(lineas[:10]) for ip, lineas in datos_crudos.items()
        )
        try:
            return self._normalizar_amenazas(self.analyst_chain.invoke({"logs": resumen}))
        except (TypeError, ValueError, KeyError) as error:
            raise RuntimeError("Respuesta inválida del LLM") from error
        except Exception as error:
            LOGGER.exception("Error inesperado durante el análisis LLM")
            raise RuntimeError("No se pudo completar el análisis LLM") from error

    @staticmethod
    def _normalizar_amenazas(resultado: Any) -> list[dict[str, str]]:
        if not isinstance(resultado, dict):
            raise TypeError("La respuesta del LLM debe ser un objeto JSON")
        amenazas = resultado.get("amenazas", [])
        if not isinstance(amenazas, list):
            raise TypeError("'amenazas' debe ser una lista")
        normalizadas: list[dict[str, str]] = []
        for amenaza in amenazas:
            if not isinstance(amenaza, dict):
                continue
            ip = amenaza.get("ip")
            if not isinstance(ip, str):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            severidad = amenaza.get("severidad", "Media")
            if severidad not in SEVERIDADES_VALIDAS:
                severidad = "Media"
            normalizadas.append(
                {
                    "ip": ip,
                    "tipo": str(amenaza.get("tipo", "Desconocido")),
                    "severidad": severidad,
                }
            )
        return normalizadas

    def ejecutar(self, amenazas: list[dict[str, str]]) -> dict[str, list[str]]:
        acciones: list[str] = []
        for amenaza in amenazas:
            ip = amenaza.get("ip")
            if not ip or ip in self.whitelist or not self._es_ip_valida(ip):
                acciones.append(f"Ignorada (Whitelist/Inválida): {ip}")
                continue
            tipo = amenaza.get("tipo", "Desconocido")
            severidad = amenaza.get("severidad", "Media")
            if self.dry_run or not self.auto_block:
                acciones.append(f"Simulada: {ip} - {tipo}")
                LOGGER.info("Acción simulada: bloquear %s (%s)", ip, tipo)
                continue
            pais = self._obtener_geolocalizacion(ip)
            if not self._ejecutar_bloqueo(ip):
                acciones.append(f"Error de firewall: {ip}")
                continue
            if self.db is None:
                raise RuntimeError("La base de datos es obligatoria para bloquear")
            self.db.registrar_amenaza(ip, pais, tipo, severidad, self.ban_time)
            acciones.append(f"Bloqueada: {ip} ({pais}) - {tipo}")
            LOGGER.info(
                "Acción táctica: IP bloqueada",
                extra={"ip": ip, "country": pais, "ttl_hours": self.ban_time},
            )
        return {"acciones_ejecutadas": acciones}

    def procesar(self, datos_crudos: dict[str, list[str]]) -> dict[str, list[str]]:
        return self.ejecutar(self.analizar(datos_crudos))

    def _obtener_geolocalizacion(self, ip: str) -> str:
        cacheada = self._geo_cache.get(ip)
        if cacheada and time.monotonic() - cacheada[0] < 3600:
            return cacheada[1]
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=3)
            payload = response.json() if response.status_code == 200 else {}
            pais = (
                payload.get("country", "Desconocido")
                if isinstance(payload, dict)
                else "Desconocido"
            )
        except (requests.RequestException, ValueError):
            LOGGER.warning("No se pudo geolocalizar %s", ip)
            pais = "Desconocido"
        self._geo_cache[ip] = (time.monotonic(), pais)
        return pais

    def _ejecutar_bloqueo(self, ip: str) -> bool:
        command = (
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=SOC_{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ]
            if self.es_windows
            else ["ufw", "deny", "from", ip, "to", "any"]
        )
        try:
            subprocess.run(
                command,
                check=True,
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            LOGGER.exception("No se pudo ejecutar el bloqueo de firewall para %s", ip)
            return False
        return True

    @staticmethod
    def _es_ip_valida(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return True


def recolectar_logs(lineas: Iterable[str]) -> defaultdict[str, list[str]]:
    datos: defaultdict[str, list[str]] = defaultdict(list)
    for linea in lineas:
        if PALABRAS_CLAVE.search(linea):
            match = REGEX_IP.search(linea)
            if match:
                datos[match.group()].append(linea.strip())
    return datos


def hilo_rollback(
    db: DatabaseManager,
    es_windows: bool,
    stop_event: threading.Event | None = None,
    intervalo: float = 60,
) -> None:
    event = stop_event or threading.Event()
    while not event.is_set():
        for ip in db.obtener_ips_expiradas():
            command = (
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SOC_{ip}"]
                if es_windows
                else ["ufw", "delete", "deny", "from", ip]
            )
            try:
                subprocess.run(
                    command,
                    check=True,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                LOGGER.exception("No se pudo ejecutar el rollback de firewall para %s", ip)
                continue
            db.marcar_desbloqueada(ip)
            LOGGER.info("Rollback: IP desbloqueada", extra={"ip": ip, "reason": "ttl_expired"})
        event.wait(intervalo)


def cargar_whitelist(ruta: str | None) -> set[str]:
    whitelist = {"127.0.0.1", "localhost"}
    if ruta and os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as file:
            whitelist.update(line.strip() for line in file if line.strip())
    return whitelist


def crear_llm(groq_key: str | None) -> Any:
    if not groq_key:
        raise ValueError("Falta GROQ_API_KEY. Configura la variable de entorno o usa --groq-key.")
    return ChatGroq(  # type: ignore[call-arg]
        model="openai/gpt-oss-20b", groq_api_key=groq_key, temperature=0
    )


def entero_positivo(valor: str) -> int:
    numero = int(valor)
    if numero <= 0:
        raise argparse.ArgumentTypeError("debe ser un entero positivo")
    return numero
