# 🛡️ Multi-Agent AI SOC Framework

Un sistema avanzado de Detección y Prevención de Intrusiones (IPS/IDS) basado en una arquitectura Multi-Agente orquestada con **LangChain**. Analiza en tiempo real registros del sistema (SSH, Apache, Nginx), clasifica amenazas utilizando Inteligencia Artificial (Llama 3.1) y ejecuta contramedidas de bloqueo automatizadas (SOAR).

## 🚀 Características Principales

* **Arquitectura LangChain:** Flujo de análisis avanzado que extrae contexto, clasifica el tipo de ataque y estructura la salida para la toma de decisiones automatizada.
* **Motor LLM Híbrido:**
* **Local (Ollama):** Máxima privacidad de datos (Data Privacy) procesando logs confidenciales 100% en local.
* **Nube (Groq API):** Despliegue optimizado para entornos de bajos recursos (como Honeypots en VPS gratuitos de Azure/AWS) con latencia ultrabaja.


* **Inteligencia de Amenazas (Threat Intel):** Enriquecimiento de datos con geolocalización IP en tiempo real y persistencia de eventos en un registro CSV (preparado para integrarse con herramientas SIEM como Grafana o Splunk).
* **Respuesta Autónoma (SOAR):** Bloqueo dinámico en milisegundos. Soporte multiplataforma nativo (`netsh` en Windows, `ufw` en Linux).
* **Monitorización en Tiempo Real:** Análisis de logs en vivo (`tail -f`) con agrupamiento por lotes temporales para no saturar las llamadas al LLM.

## 🛠️ Stack Tecnológico

* **Core:** Python 3.10+
* **IA & Orquestación:** LangChain, Ollama (Llama 3.1), Groq (Llama 3.1 8B)
* **Infraestructura:** Integración con Firewall de SO (Windows/Linux) y APIs REST de Geolocalización.

## ⚙️ Instalación

1. Clona este repositorio:
`git clone https://github.com/juaanmgg/AI-SOC-Log-Analyzer.git`
`cd AI-SOC-Log-Analyzer`
2. (Opcional - Uso Local) Instala Ollama y descarga el modelo:
`ollama run llama3.1`
3. Configura el entorno e instala las dependencias:
`python -m venv venv`
`source venv/bin/activate` *(En Windows: `.\venv\Scripts\activate`)*
`pip install -r requirements.txt`

## 💻 Uso de la CLI

El framework se ejecuta a través de la terminal y requiere privilegios de Administrador/Root para modificar las reglas del Firewall.

**Modo Privacidad Total (IA Local vía Ollama):**
`python soc_agent.py --log /var/log/auth.log --threshold 3 --ai ollama`

**Modo Honeypot VPS (Bajo consumo RAM vía Groq):**
`python soc_agent.py --log /var/log/auth.log --threshold 5 --ai groq --groq-key "TU_API_KEY_AQUI"`

### Argumentos Disponibles

* `--log`: [Requerido] Ruta absoluta o relativa al archivo de registro del sistema.
* `--threshold`: Número de intentos anómalos desde una misma IP para considerarlo ataque (Default: 3).
* `--ai`: Selecciona el proveedor del LLM (`ollama` o `groq`).
* `--groq-key`: Clave API para usar Groq (también puede leerse como variable de entorno `GROQ_API_KEY`).

## 📊 Salida de Datos (Threat Intel)

El sistema generará automáticamente un archivo `threat_intel.csv` en la raíz del proyecto, registrando cada incidente mitigado con el siguiente formato:
`Fecha | IP Atacante | País de Origen | Tipo de Ataque (ej. Fuerza Bruta) | Severidad`