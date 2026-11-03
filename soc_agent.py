import re
import os
import time
import csv
import argparse
import requests
import subprocess
from collections import defaultdict

# --- LIBRERÍAS DE LANGCHAIN ---
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_community.chat_models import ChatOllama
from langchain_groq import ChatGroq

# ==========================================
# AGENTE 1: RECOLECTOR (Filtro Ancho)
# ==========================================
# Ahora detecta SSH, errores web (403, 404), accesos denegados, etc.
PALABRAS_CLAVE = re.compile(r"(?i)(failed|invalid|error|unauthorized|denied|403|404)")
REGEX_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def recolectar_logs_sospechosos(lineas):
    """Filtra líneas ruidosas y extrae IPs y el contexto del error."""
    datos = defaultdict(list)
    for linea in lineas:
        if PALABRAS_CLAVE.search(linea):
            ip_match = REGEX_IP.search(linea)
            if ip_match:
                ip = ip_match.group()
                # Guardamos la línea entera para que la IA tenga contexto completo
                datos[ip].append(linea.strip())
    return datos

# ==========================================
# AGENTE 2: INTELIGENCIA (GeoIP)
# ==========================================
def obtener_geolocalizacion(ip):
    """Consulta una API gratuita para obtener el país de origen."""
    try:
        respuesta = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=3)
        if respuesta.status_code == 200:
            return respuesta.json().get("country", "Desconocido")
    except:
        pass
    return "Desconocido"

# ==========================================
# AGENTE 3 & 4: ANALISTA SOC (IA) Y RESPUESTA (Táctico)
# ==========================================
class SOCAgent:
    def __init__(self, proveedor_ia, groq_api_key=None):
        self.archivo_csv = "threat_intel.csv"
        self._inicializar_csv()
        
        # 1. Seleccionamos el "Cerebro" (Local o Nube)
        print(f"[*] Inicializando Motor de IA: {proveedor_ia.upper()}")
        if proveedor_ia == 'groq':
            if not groq_api_key:
                raise ValueError("Se requiere GROQ_API_KEY para usar Groq.")
            self.llm = ChatGroq(model="llama-3.1-8b-instant", groq_api_key=groq_api_key, temperature=0)
        else:
            # Temperatura 0 para que sea analítico y no creativo. format="json" obliga a estructura de datos.
            self.llm = ChatOllama(model="llama3.1-local", temperature=0, format="json")

        # 2. Definimos el Parser (El molde de salida)
        self.parser = JsonOutputParser()

        # 3. Diseñamos el Prompt Template (LangChain rellenará la variable {logs})
        self.prompt = PromptTemplate(
            template="""
            Eres un Analista SOC Nivel 3. Analiza los siguientes logs de sistema y determina si son ataques (Fuerza Bruta, Escaneo de Directorios, Password Spraying, etc.) o falsos positivos.
            
            Logs a analizar:
            {logs}

            Devuelve ÚNICAMENTE un objeto JSON con una lista llamada "amenazas" que contenga: "ip", "tipo", "severidad" (Alta, Media, Baja). Si no hay ataques, devuelve la lista vacía.
            """,
            input_variables=["logs"]
        )

        # 4. Construimos la CADENA LANGCHAIN (Prompt -> Modelo -> Parser)
        self.cadena_analisis = self.prompt | self.llm | self.parser

    def _inicializar_csv(self):
        """Crea el archivo de Threat Intelligence si no existe."""
        if not os.path.exists(self.archivo_csv):
            with open(self.archivo_csv, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Fecha", "IP", "País", "Tipo de Ataque", "Severidad"])

    def registrar_y_bloquear(self, ip, tipo, severidad, pais, es_windows):
        """Agente Táctico: Guarda en CSV y aplica reglas de Firewall."""
        fecha = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Guardar en CSV (Persistencia)
        with open(self.archivo_csv, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([fecha, ip, pais, tipo, severidad])
        
        # Bloqueo (Multiplataforma)
        if es_windows:
            comando = f'netsh advfirewall firewall add rule name="SOC_{ip}" dir=in action=block remoteip={ip}'
        else:
            comando = f'sudo ufw deny from {ip} to any'

        try:
            subprocess.run(comando, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  [+] BLOQUEADA: {ip} | País: {pais} | Ataque: {tipo} | Severidad: {severidad}")
        except subprocess.CalledProcessError:
            print(f"  [-] ERROR: No se pudo bloquear {ip} (Faltan permisos).")

    def analizar_y_responder(self, datos_sospechosos, es_windows):
        """Orquesta el flujo: IA -> GeoIP -> Bloqueo."""
        if not datos_sospechosos:
            return

        # Preparamos el texto para la IA
        resumen_logs = ""
        for ip, lineas in datos_sospechosos.items():
            resumen_logs += f"\n--- IP: {ip} (Total eventos: {len(lineas)}) ---\n"
            resumen_logs += "\n".join(lineas[:10]) # Pasamos un máximo de 10 líneas por IP para no saturar tokens

        print("\n[!] Anomalías detectadas. Iniciando cadena de análisis LangChain...")
        
        try:
            # Ejecutamos la cadena LangChain (hace la magia del Prompt -> LLM -> JSON)
            resultado = self.cadena_analisis.invoke({"logs": resumen_logs})
            amenazas = resultado.get("amenazas", [])
            
            if amenazas:
                print(f"[*] LangChain Agent: {len(amenazas)} amenazas confirmadas. Respondiendo:")
                for amenaza in amenazas:
                    ip = amenaza.get("ip")
                    tipo = amenaza.get("tipo", "Desconocido")
                    severidad = amenaza.get("severidad", "Media")
                    
                    if ip:
                        # Llamamos al Agente de Inteligencia (GeoIP)
                        pais = obtener_geolocalizacion(ip)
                        # Llamamos al Agente Táctico
                        self.registrar_y_bloquear(ip, tipo, severidad, pais, es_windows)
        except Exception as e:
            print(f"[-] Error en la cadena de LangChain: {e}")

# ==========================================
# MONITORIZACIÓN EN TIEMPO REAL
# ==========================================
def iniciar_soc(archivo_log, umbral, proveedor_ia, groq_api_key, es_windows):
    agente_soc = SOCAgent(proveedor_ia, groq_api_key)
    print(f"[*] Vigilando '{archivo_log}'. Presiona Ctrl+C para detener...\n")
    
    with open(archivo_log, 'r') as archivo:
        archivo.seek(0, 2)
        lineas_nuevas = []
        tiempo_ultimo = time.time()
        
        try:
            while True:
                linea = archivo.readline()
                if not linea:
                    time.sleep(1)
                    if lineas_nuevas and (time.time() - tiempo_ultimo > 10):
                        datos = recolectar_logs_sospechosos(lineas_nuevas)
                        # Solo analizamos IPs que superen el umbral de ruido
                        ips_criticas = {ip: logs for ip, logs in datos.items() if len(logs) >= umbral}
                        agente_soc.analizar_y_responder(ips_criticas, es_windows)
                        lineas_nuevas = []
                        tiempo_ultimo = time.time()
                    continue
                
                lineas_nuevas.append(linea)
                if len(lineas_nuevas) >= 50:
                    datos = recolectar_logs_sospechosos(lineas_nuevas)
                    ips_criticas = {ip: logs for ip, logs in datos.items() if len(logs) >= umbral}
                    agente_soc.analizar_y_responder(ips_criticas, es_windows)
                    lineas_nuevas = []
                    tiempo_ultimo = time.time()
                    
        except KeyboardInterrupt:
            print("\n[*] SOC desconectado.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Multi-Agent SOC Framework usando LangChain")
    parser.add_argument('--log', type=str, required=True, help="Ruta al log")
    parser.add_argument('--threshold', type=int, default=3, help="Eventos mínimos")
    parser.add_argument('--ai', type=str, choices=['ollama', 'groq'], default='ollama', help="Motor LLM a usar")
    # Para usar Groq, puedes pasar la API Key por consola o tenerla como variable de entorno
    parser.add_argument('--groq-key', type=str, default=os.getenv('GROQ_API_KEY'), help="API Key de Groq")
    
    args = parser.parse_args()
    es_windows = os.name == 'nt'
    
    iniciar_soc(args.log, args.threshold, args.ai, args.groq_key, es_windows)