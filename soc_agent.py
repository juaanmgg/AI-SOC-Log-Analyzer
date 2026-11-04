import argparse
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, TypedDict

import requests
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph


# ==========================================
# CONFIGURACIÓN Y ESTADO (LangGraph)
# ==========================================
class AgentState(TypedDict):
    datos_crudos: dict[str, list[str]]
    amenazas_evaluadas: list[dict[str, Any]]
    acciones_ejecutadas: list[str]


PALABRAS_CLAVE = re.compile(r"(?i)(failed|invalid|error|unauthorized|denied|403|404)")
REGEX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ==========================================
# MOTOR DE BBDD Y ROLLBACK
# ==========================================
class DatabaseManager:
    def __init__(self, db_path="threat_intel.db"):
        self.db_path = db_path
        self._inicializar_db()

    def _inicializar_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS amenazas
                            (id INTEGER PRIMARY KEY, fecha TEXT, ip TEXT, pais TEXT, 
                             tipo TEXT, severidad TEXT, expira_en TEXT, activo INTEGER)''')

    def registrar_amenaza(self, ip, pais, tipo, severidad, ban_time_hours):
        expiracion = (datetime.now() + timedelta(hours=ban_time_hours)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO amenazas (fecha, ip, pais, tipo, severidad, expira_en, activo) VALUES (?, ?, ?, ?, ?, ?, 1)",
                (datetime.now().isoformat(), ip, pais, tipo, severidad, expiracion),
            )

    def obtener_ips_expiradas(self):
        ahora = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT ip FROM amenazas WHERE activo = 1 AND expira_en <= ?", (ahora,))
            return [fila[0] for fila in cursor.fetchall()]

    def marcar_desbloqueada(self, ip):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE amenazas SET activo = 0 WHERE ip = ?", (ip,))


# ==========================================
# MULTI-AGENT WORKFLOW (LangGraph Nodes)
# ==========================================
class SOCWorkflow:
    def __init__(self, llm, db_manager, whitelist, es_windows, ban_time):
        self.llm = llm
        self.db = db_manager
        self.whitelist = whitelist
        self.es_windows = es_windows
        self.ban_time = ban_time

        self.parser = JsonOutputParser()
        self.prompt = PromptTemplate(
            template="""Eres un Analista SOC Nivel 3. Analiza los logs y determina si son ataques (Fuerza Bruta, etc.) o falsos positivos.
            Logs a analizar:
            {logs}
            Devuelve ÚNICAMENTE un objeto JSON con la clave "amenazas" conteniendo: "ip", "tipo", "severidad". Si no hay ataques, devuelve la lista vacía.""",
            input_variables=["logs"],
        )
        self.analyst_chain = self.prompt | self.llm | self.parser
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("analyst_agent", self.analyst_node)
        workflow.add_node("executor_agent", self.executor_node)

        workflow.add_edge(START, "analyst_agent")
        workflow.add_edge("analyst_agent", "executor_agent")
        workflow.add_edge("executor_agent", END)
        return workflow.compile()

    def analyst_node(self, state: AgentState):
        """Agente 2: Evalúa contexto con LLM."""
        resumen = ""
        for ip, lineas in state["datos_crudos"].items():
            resumen += f"\n--- IP: {ip} ---\n" + "\n".join(lineas[:10])

        try:
            resultado = self.analyst_chain.invoke({"logs": resumen})
            return {"amenazas_evaluadas": resultado.get("amenazas", [])}
        except Exception as e:  # noqa: BLE001
            print(f"[-] Error en Analyst Agent: {e}")
            return {"amenazas_evaluadas": []}

    def executor_node(self, state: AgentState):
        """Agente 3: Orquesta bloqueo, Threat Intel y Persistencia."""
        acciones = []
        for amenaza in state["amenazas_evaluadas"]:
            ip = amenaza.get("ip")
            if not ip or ip in self.whitelist:
                acciones.append(f"Ignorada (Whitelist/Inválida): {ip}")
                continue

            pais = self._obtener_geolocalizacion(ip)
            tipo = amenaza.get("tipo", "Desconocido")
            sev = amenaza.get("severidad", "Media")

            self._ejecutar_bloqueo(ip)
            self.db.registrar_amenaza(ip, pais, tipo, sev, self.ban_time)
            acciones.append(f"Bloqueada: {ip} ({pais}) - {tipo}")
            print(f"  [+] ACCIÓN TÁCTICA: Bloqueada {ip} | País: {pais} | TTL: {self.ban_time}h")

        return {"acciones_ejecutadas": acciones}

    def _obtener_geolocalizacion(self, ip):
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=3)
            return r.json().get("country", "Desconocido") if r.status_code == 200 else "Desconocido"
        except requests.RequestException:
            return "Desconocido"

    def _ejecutar_bloqueo(self, ip):
        cmd = (
            f'netsh advfirewall firewall add rule name="SOC_{ip}" dir=in action=block remoteip={ip}'
            if self.es_windows
            else f"sudo ufw deny from {ip} to any"
        )
        subprocess.run(cmd, check=False, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ==========================================
# AGENTE 1: PARSER EN TIEMPO REAL & ORQUESTADOR
# ==========================================
def recolectar_logs(lineas):
    """Filtra y extrae datos crudos (Agente 1)."""
    datos = defaultdict(list)
    for linea in lineas:
        if PALABRAS_CLAVE.search(linea):
            match = REGEX_IP.search(linea)
            if match:
                datos[match.group()].append(linea.strip())
    return datos


def hilo_rollback(db: DatabaseManager, es_windows: bool):
    """Demonio que libera IPs cuyo TTL ha expirado."""
    while True:
        expiradas = db.obtener_ips_expiradas()
        for ip in expiradas:
            cmd = (
                f'netsh advfirewall firewall delete rule name="SOC_{ip}"'
                if es_windows
                else f"sudo ufw delete deny from {ip}"
            )
            subprocess.run(cmd, check=False, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            db.marcar_desbloqueada(ip)
            print(f"  [~] ROLLBACK: IP {ip} desbloqueada (TTL expirado).")
        time.sleep(60)  # Chequeo cada minuto


def cargar_whitelist(ruta):
    wl = {"127.0.0.1", "localhost"}
    if ruta and os.path.exists(ruta):
        with open(ruta) as f:
            wl.update(linea.strip() for linea in f if linea.strip())
    return wl


def iniciar_soc(args, es_windows):
    whitelist = cargar_whitelist(args.whitelist)
    db = DatabaseManager()

    # Iniciar motor LLM
    if args.ai == "groq":
        llm = ChatGroq(model="llama-3.1-8b-instant", groq_api_key=args.groq_key, temperature=0)
    else:
        llm = ChatOllama(model="llama3.1-local", temperature=0, format="json")

    workflow = SOCWorkflow(llm, db, whitelist, es_windows, args.ban_time)

    # Iniciar hilo de rollback
    threading.Thread(target=hilo_rollback, args=(db, es_windows), daemon=True).start()

    print(f"[*] Vigilando '{args.log}'. Motor: {args.ai.upper()}. TTL: {args.ban_time}h")
    with open(args.log) as archivo:
        archivo.seek(0, 2)
        lineas_nuevas = []
        tiempo_ultimo = time.time()

        try:
            while True:
                linea = archivo.readline()
                if not linea:
                    time.sleep(1)
                    if lineas_nuevas and (time.time() - tiempo_ultimo > 10):
                        datos = recolectar_logs(lineas_nuevas)
                        ips_criticas = {ip: logs for ip, logs in datos.items() if len(logs) >= args.threshold}
                        if ips_criticas:
                            workflow.graph.invoke({"datos_crudos": ips_criticas})
                        lineas_nuevas.clear()
                        tiempo_ultimo = time.time()
                    continue

                lineas_nuevas.append(linea)
        except KeyboardInterrupt:
            print("\n[*] SOC desconectado.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Agent SOC Framework usando LangGraph")
    parser.add_argument("--log", type=str, required=True, help="Ruta al log")
    parser.add_argument("--threshold", type=int, default=3, help="Eventos mínimos")
    parser.add_argument("--ai", type=str, choices=["ollama", "groq"], default="ollama")
    parser.add_argument("--groq-key", type=str, default=os.getenv("GROQ_API_KEY"))
    parser.add_argument("--whitelist", type=str, default="whitelist.txt", help="Archivo de IPs exentas")
    parser.add_argument("--ban-time", type=int, default=24, help="Horas de bloqueo (TTL)")

    args = parser.parse_args()
    iniciar_soc(args, os.name == "nt")