import re
import json
import ollama
import subprocess
import argparse
import time
import os
from collections import defaultdict

# Regex global (fuera de las funciones para no recompilar en cada vuelta)
REGEX_FALLOS = re.compile(r"(?:Failed password for|Invalid user) (?:invalid user )?(\w+) from ([\d\.]+)")

def extraer_ips_sospechosas(lineas):
    """Extrae y cuenta los intentos fallidos de una lista de líneas de log."""
    intentos = defaultdict(lambda: {'usuarios': set(), 'conteo': 0})
    
    for linea in lineas:
        coincidencia = REGEX_FALLOS.search(linea)
        if coincidencia:
            usuario = coincidencia.group(1)
            ip = coincidencia.group(2)
            intentos[ip]['usuarios'].add(usuario)
            intentos[ip]['conteo'] += 1
            
    return intentos

def analizar_con_ia(datos_sospechosos):
    """Envía el resumen estructurado a Llama 3.1 aplicando Few-Shot Prompting."""
    resumen = ""
    for ip, datos in datos_sospechosos.items():
        resumen += f"- IP: {ip} | Intentos: {datos['conteo']} | Usuarios atacados: {', '.join(datos['usuarios'])}\n"

    try:
        respuesta = ollama.chat(model='llama3.1-local', messages=[
            {
                'role': 'system', 
                'content': 'Eres un analizador SOC. Recibes un texto con IPs y devuelves UNICAMENTE un JSON estricto con la clave "amenazas". Clasifica como "Fuerza Bruta" o "Password Spraying".'
            },
            {
                'role': 'user', 
                'content': '- IP: 8.8.8.8 | Intentos: 15 | Usuarios atacados: root\n- IP: 9.9.9.9 | Intentos: 4 | Usuarios atacados: admin, test'
            },
            {
                'role': 'assistant', 
                'content': '{"amenazas": [{"ip": "8.8.8.8", "tipo": "Fuerza Bruta", "severidad": "Alta"}, {"ip": "9.9.9.9", "tipo": "Password Spraying", "severidad": "Alta"}]}'
            },
            {
                'role': 'user', 
                'content': resumen
            }
        ], format='json')
        
        json_limpio = respuesta['message']['content'].strip()
        if json_limpio.startswith("```json"): json_limpio = json_limpio[7:]
        if json_limpio.endswith("```"): json_limpio = json_limpio[:-3]
        
        return json.loads(json_limpio.strip())
    except Exception as e:
        print(f"[-] Error en el análisis de IA: {e}")
        return {"amenazas": []}

def bloquear_ip(ip, es_windows):
    """Ejecuta el bloqueo en Windows o en Linux de forma inteligente."""
    if es_windows:
        regla_nombre = f"SOC_{ip}"
        comando = f'netsh advfirewall firewall add rule name="{regla_nombre}" dir=in action=block remoteip={ip}'
    else:
        # Comando para servidores Linux comunes (UFW)
        comando = f'sudo ufw deny from {ip} to any'

    try:
        subprocess.run(comando, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  [+] ÉXITO: IP {ip} bloqueada a nivel de red.")
    except subprocess.CalledProcessError:
        print(f"  [-] ERROR: No se pudo bloquear {ip}. ¿Faltan permisos de Administrador/Root?")

def modo_monitorizacion_viva(archivo_log, umbral, es_windows):
    """Monitoriza el archivo en tiempo real (similar a 'tail -f') y procesa en lotes."""
    print(f"[*] Iniciando vigilancia de '{archivo_log}'...")
    print("[*] Presiona Ctrl+C para detener el sistema SOC.\n")
    
    with open(archivo_log, 'r') as archivo:
        # Vamos directamente al final del archivo
        archivo.seek(0, 2)
        
        lineas_nuevas = []
        tiempo_ultimo_analisis = time.time()
        
        try:
            while True:
                linea = archivo.readline()
                if not linea:
                    time.sleep(1) # Esperamos si no hay nada nuevo
                    
                    # Si han pasado más de 10 segundos y hay líneas acumuladas, analizamos el lote
                    if lineas_nuevas and (time.time() - tiempo_ultimo_analisis > 10):
                        procesar_lote(lineas_nuevas, umbral, es_windows)
                        lineas_nuevas = []
                        tiempo_ultimo_analisis = time.time()
                    continue
                
                # Si hay línea nueva, la guardamos
                lineas_nuevas.append(linea)
                
                # Si acumulamos 50 líneas, analizamos rápido por seguridad (ataque denso)
                if len(lineas_nuevas) >= 50:
                    procesar_lote(lineas_nuevas, umbral, es_windows)
                    lineas_nuevas = []
                    tiempo_ultimo_analisis = time.time()
                    
        except KeyboardInterrupt:
            print("\n[*] Vigilancia detenida por el usuario. SOC desconectado.")

def procesar_lote(lineas, umbral, es_windows):
    """Filtra el lote, llama a la IA y ejecuta las acciones."""
    datos = extraer_ips_sospechosas(lineas)
    
    # Filtramos IPs que no superen el umbral para no molestar a la IA con fallos normales
    ips_a_analizar = {ip: d for ip, d in datos.items() if d['conteo'] >= umbral}
    
    if not ips_a_analizar:
        return # Si nadie pasó del umbral de intentos, no hacemos nada

    print(f"\n[!] Detectada actividad inusual. Solicitando análisis táctico a Llama 3.1...")
    
    resultado = analizar_con_ia(ips_a_analizar)
    amenazas = resultado.get("amenazas", [])
    
    if amenazas:
        print(f"[*] IA: {len(amenazas)} amenazas confirmadas. Ejecutando respuesta:")
        for amenaza in amenazas:
            ip = amenaza.get("ip", amenaza.get("IP"))
            tipo = amenaza.get("tipo", "Desconocido")
            if ip:
                print(f"  -> Bloqueando {ip} [{tipo}]")
                bloquear_ip(ip, es_windows)

if __name__ == '__main__':
    # Configuración de los parámetros por línea de comandos
    parser = argparse.ArgumentParser(description="AI SOC Log Analyzer: Detector y mitigador de ataques en tiempo real usando LLMs locales.")
    parser.add_argument('--log', type=str, required=True, help="Ruta al archivo de log (ej: dummy_auth.log)")
    parser.add_argument('--threshold', type=int, default=3, help="Intentos mínimos para considerarlo ataque (default: 3)")
    
    args = parser.parse_args()
    es_windows = os.name == 'nt'
    
    modo_monitorizacion_viva(args.log, args.threshold, es_windows)