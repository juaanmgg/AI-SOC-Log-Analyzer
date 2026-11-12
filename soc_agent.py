import argparse
import ipaddress
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import requests
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_groq import ChatGroq

LOGGER = logging.getLogger(__name__)
PALABRAS_CLAVE = re.compile(r"(?i)(failed|invalid|error|unauthorized|denied|403|404)")
REGEX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SEVERIDADES_VALIDAS = {"Baja", "Media", "Alta", "Crítica"}
UTC_TZ = timezone.utc  # noqa: UP017


def ahora_utc():
    return datetime.now(UTC_TZ)


# ==========================================
# MOTOR DE BBDD Y ROLLBACK
# ==========================================
class DatabaseManager:
    def __init__(self, db_path="threat_intel.db"):
        self.db_path = db_path
        self._inicializar_db()

    def _inicializar_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS amenazas
                            (id INTEGER PRIMARY KEY, fecha TEXT, ip TEXT, pais TEXT, 
                             tipo TEXT, severidad TEXT, expira_en TEXT, activo INTEGER)""")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_amenazas_expiracion ON amenazas (activo, expira_en)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_amenazas_ip_activa ON amenazas (ip, activo)"
            )

    def registrar_amenaza(self, ip, pais, tipo, severidad, ban_time_hours):
        fecha = ahora_utc()
        expiracion = (fecha + timedelta(hours=ban_time_hours)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            actualizado = conn.execute(
                """
                UPDATE amenazas
                SET fecha = ?, pais = ?, tipo = ?, severidad = ?, expira_en = ?, activo = 1
                WHERE ip = ? AND activo = 1
                """,
                (fecha.isoformat(), pais, tipo, severidad, expiracion, ip),
            ).rowcount
            if not actualizado:
                conn.execute(
                    "INSERT INTO amenazas (fecha, ip, pais, tipo, severidad, expira_en, activo) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (fecha.isoformat(), ip, pais, tipo, severidad, expiracion),
                )

    def obtener_ips_expiradas(self):
        ahora = ahora_utc().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT DISTINCT amenaza.ip
                FROM amenazas AS amenaza
                WHERE amenaza.activo = 1
                  AND amenaza.expira_en <= ?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM amenazas AS vigente
                      WHERE vigente.ip = amenaza.ip
                        AND vigente.activo = 1
                        AND vigente.expira_en > ?
                  )
                """,
                (ahora, ahora),
            )
            return [fila[0] for fila in cursor.fetchall()]

    def marcar_desbloqueada(self, ip):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE amenazas SET activo = 0 WHERE ip = ? AND activo = 1 AND expira_en <= ?",
                (ip, ahora_utc().isoformat()),
            )


# ==========================================
# PIPELINE DE ANÁLISIS Y RESPUESTA
# ==========================================
class SOCAnalyzer:
    def __init__(
        self, llm, db_manager, whitelist, es_windows, ban_time, auto_block=False, dry_run=False
    ):
        self.llm = llm
        self.db = db_manager
        self.whitelist = whitelist
        self.es_windows = es_windows
        self.ban_time = ban_time
        self.auto_block = auto_block
        self.dry_run = dry_run
        self._geo_cache = {}

        self.parser = JsonOutputParser()
        self.prompt = PromptTemplate(
            template="""Eres un Analista SOC Nivel 3. Analiza los logs y determina si son ataques (Fuerza Bruta, etc.) o falsos positivos.
            Logs a analizar:
            {logs}
            Devuelve ÚNICAMENTE un objeto JSON con la clave "amenazas" conteniendo: "ip", "tipo", "severidad". Si no hay ataques, devuelve la lista vacía.""",
            input_variables=["logs"],
        )
        self.analyst_chain = self.prompt | self.llm | self.parser

    def analizar(self, datos_crudos):
        """Evalúa el lote de logs con el LLM y devuelve las amenazas."""
        resumen = ""
        for ip, lineas in datos_crudos.items():
            resumen += f"\n--- IP: {ip} ---\n" + "\n".join(lineas[:10])

        try:
            resultado = self.analyst_chain.invoke({"logs": resumen})
            return self._normalizar_amenazas(resultado)
        except (TypeError, ValueError, KeyError) as error:
            raise RuntimeError("Respuesta inválida del LLM") from error
        except Exception as error:
            LOGGER.exception("Error inesperado durante el análisis LLM")
            raise RuntimeError("No se pudo completar el análisis LLM") from error

    @staticmethod
    def _normalizar_amenazas(resultado):
        if not isinstance(resultado, dict):
            raise TypeError("La respuesta del LLM debe ser un objeto JSON")

        amenazas = resultado.get("amenazas", [])
        if not isinstance(amenazas, list):
            raise TypeError("'amenazas' debe ser una lista")

        normalizadas = []
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

    def ejecutar(self, amenazas):
        """Aplica las acciones tácticas para las amenazas confirmadas."""
        acciones = []
        for amenaza in amenazas:
            ip = amenaza.get("ip")
            if not ip or ip in self.whitelist or not self._es_ip_valida(ip):
                acciones.append(f"Ignorada (Whitelist/Inválida): {ip}")
                continue

            tipo = amenaza.get("tipo", "Desconocido")
            sev = amenaza.get("severidad", "Media")

            if self.dry_run or not self.auto_block:
                acciones.append(f"Simulada: {ip} - {tipo}")
                LOGGER.info("Acción simulada: bloquear %s (%s)", ip, tipo)
                continue

            pais = self._obtener_geolocalizacion(ip)
            if not self._ejecutar_bloqueo(ip):
                acciones.append(f"Error de firewall: {ip}")
                continue

            self.db.registrar_amenaza(ip, pais, tipo, sev, self.ban_time)
            acciones.append(f"Bloqueada: {ip} ({pais}) - {tipo}")
            LOGGER.info(
                "Acción táctica: IP bloqueada",
                extra={"ip": ip, "country": pais, "ttl_hours": self.ban_time},
            )

        return {"acciones_ejecutadas": acciones}

    def procesar(self, datos_crudos):
        """Ejecuta secuencialmente el análisis y la respuesta para un lote."""
        amenazas = self.analizar(datos_crudos)
        return self.ejecutar(amenazas)

    def _obtener_geolocalizacion(self, ip):
        cacheada = self._geo_cache.get(ip)
        if cacheada and time.monotonic() - cacheada[0] < 3600:
            return cacheada[1]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=3)
            payload = r.json() if r.status_code == 200 else {}
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

    def _ejecutar_bloqueo(self, ip):
        cmd = (
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
                cmd,
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
    def _es_ip_valida(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except (TypeError, ValueError):
            return False


# ==========================================
# RECOLECCIÓN EN TIEMPO REAL & ORQUESTACIÓN
# ==========================================
def recolectar_logs(lineas):
    """Filtra y extrae datos crudos para el pipeline."""
    datos = defaultdict(list)
    for linea in lineas:
        if PALABRAS_CLAVE.search(linea):
            match = REGEX_IP.search(linea)
            if match:
                datos[match.group()].append(linea.strip())
    return datos


def hilo_rollback(db: DatabaseManager, es_windows: bool, stop_event=None, intervalo=60):
    """Demonio que libera IPs cuyo TTL ha expirado."""
    stop_event = stop_event or threading.Event()
    while not stop_event.is_set():
        expiradas = db.obtener_ips_expiradas()
        for ip in expiradas:
            cmd = (
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SOC_{ip}"]
                if es_windows
                else ["ufw", "delete", "deny", "from", ip]
            )
            try:
                subprocess.run(
                    cmd,
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
        stop_event.wait(intervalo)


def cargar_whitelist(ruta):
    wl = {"127.0.0.1", "localhost"}
    if ruta and os.path.exists(ruta):
        with open(ruta) as f:
            wl.update(linea.strip() for linea in f if linea.strip())
    return wl


def crear_llm(groq_key):
    if not groq_key:
        raise ValueError("Falta GROQ_API_KEY. Configura la variable de entorno o usa --groq-key.")
    return ChatGroq(
        model="openai/gpt-oss-20b",
        groq_api_key=groq_key,
        temperature=0,
    )


def entero_positivo(valor):
    numero = int(valor)
    if numero <= 0:
        raise argparse.ArgumentTypeError("debe ser un entero positivo")
    return numero


def iniciar_soc(args, es_windows):
    whitelist = cargar_whitelist(args.whitelist)
    db = DatabaseManager()

    try:
        llm = crear_llm(args.groq_key)
    except ValueError as error:
        raise SystemExit(f"[-] {error}") from error

    analyzer = SOCAnalyzer(
        llm,
        db,
        whitelist,
        es_windows,
        args.ban_time,
        auto_block=args.auto_block,
        dry_run=args.dry_run,
    )

    rollback_stop = threading.Event()
    threading.Thread(
        target=hilo_rollback,
        args=(db, es_windows, rollback_stop),
        daemon=True,
    ).start()

    LOGGER.info(
        "Vigilando archivo de logs",
        extra={"path": args.log, "model": "openai/gpt-oss-20b", "ttl_hours": args.ban_time},
    )
    eventos_recientes = deque()
    alertas_emitidas = {}
    tiempo_ultimo_analisis = time.monotonic()

    try:
        while True:
            with open(args.log) as archivo:
                archivo.seek(0, 2)
                identidad_archivo = (
                    os.fstat(archivo.fileno()).st_dev,
                    os.fstat(archivo.fileno()).st_ino,
                )

                while True:
                    linea = archivo.readline()
                    ahora = time.monotonic()
                    if linea:
                        eventos_recientes.append((ahora, linea))

                    while (
                        eventos_recientes and ahora - eventos_recientes[0][0] > args.window_seconds
                    ):
                        eventos_recientes.popleft()

                    if ahora - tiempo_ultimo_analisis >= 10 and eventos_recientes:
                        datos = recolectar_logs(linea for _, linea in eventos_recientes)
                        ips_criticas = {}
                        for ip, logs in datos.items():
                            ultima_alerta = alertas_emitidas.get(ip, 0)
                            if (
                                len(logs) >= args.threshold
                                and ahora - ultima_alerta >= args.window_seconds
                            ):
                                ips_criticas[ip] = logs
                                alertas_emitidas[ip] = ahora
                        if ips_criticas:
                            analyzer.procesar(ips_criticas)
                        tiempo_ultimo_analisis = ahora

                    nueva_identidad = (os.stat(args.log).st_dev, os.stat(args.log).st_ino)
                    if nueva_identidad != identidad_archivo:
                        eventos_recientes.clear()
                        alertas_emitidas.clear()
                        break

                    if not linea:
                        time.sleep(1)
    except KeyboardInterrupt:
        rollback_stop.set()
        LOGGER.info("SOC desconectado")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Log Analyzer con pipeline secuencial")
    parser.add_argument("--log", type=str, required=True, help="Ruta al log")
    parser.add_argument("--threshold", type=entero_positivo, default=3, help="Eventos mínimos")
    parser.add_argument("--groq-key", type=str, default=os.getenv("GROQ_API_KEY"))
    parser.add_argument(
        "--whitelist", type=str, default="whitelist.txt", help="Archivo de IPs exentas"
    )
    parser.add_argument(
        "--ban-time", type=entero_positivo, default=24, help="Horas de bloqueo (TTL)"
    )
    parser.add_argument(
        "--window-seconds",
        type=entero_positivo,
        default=60,
        help="Ventana temporal para contar eventos por IP",
    )
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument(
        "--auto-block",
        action="store_true",
        help="Permite modificar el firewall; por defecto solo se simulan las acciones",
    )
    modo.add_argument(
        "--dry-run",
        action="store_true",
        help="Analiza y muestra acciones sin consultar geolocalización ni modificar el firewall",
    )

    args = parser.parse_args()
    iniciar_soc(args, os.name == "nt")
