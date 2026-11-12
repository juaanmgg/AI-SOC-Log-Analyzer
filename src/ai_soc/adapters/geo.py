"""Proveedor GeoIP HTTPS con reintentos y caché concurrente."""

import ipaddress
import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

LOGGER = logging.getLogger(__name__)


class GeoIPProvider(ABC):
    """Interfaz para resolver el país de una dirección IP."""

    @abstractmethod
    def get_country(self, ip: str) -> str:
        """Devuelve el país o ``Desconocido`` si no se puede resolver."""


class HTTPXGeoIPAdapter(GeoIPProvider):
    """Consulta un proveedor GeoIP sobre HTTPS y cachea resultados."""

    def __init__(
        self,
        base_url: str = "https://ipwhois.app/json",
        ttl_seconds: float = 3600.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("El proveedor GeoIP debe usar HTTPS")
        if ttl_seconds < 0:
            raise ValueError("El TTL debe ser no negativo")
        self.base_url = base_url.rstrip("/")
        self.ttl_seconds = ttl_seconds
        self._client = client or httpx.Client(timeout=3.0, verify=True)
        self._owns_client = client is None
        self._cache: dict[str, tuple[float, str]] = {}
        self._cache_lock = threading.Lock()

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _fetch_country(self, ip: str) -> str:
        response = self._client.get(f"{self.base_url}/{ip}")
        response.raise_for_status()
        payload: Any = response.json()
        if not isinstance(payload, dict):
            raise ValueError("La respuesta GeoIP no es un objeto JSON")
        country = payload.get("country")
        return country if isinstance(country, str) and country else "Desconocido"

    def get_country(self, ip: str) -> str:
        try:
            normalized_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            LOGGER.warning("IP inválida para GeoIP: %s", ip)
            return "Desconocido"

        now = time.monotonic()
        with self._cache_lock:
            cached = self._cache.get(normalized_ip)
            if cached and now - cached[0] < self.ttl_seconds:
                return cached[1]

        try:
            country = self._fetch_country(normalized_ip)
        except (httpx.HTTPError, ValueError):
            LOGGER.warning("No se pudo resolver GeoIP para %s tras los reintentos", normalized_ip)
            country = "Desconocido"

        with self._cache_lock:
            self._cache[normalized_ip] = (time.monotonic(), country)
        return country

    def close(self) -> None:
        """Cierra el cliente HTTP creado por el adaptador."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "HTTPXGeoIPAdapter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        self.close()
