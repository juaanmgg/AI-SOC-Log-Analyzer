# AI SOC Log Analyzer

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Build](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)
![Architecture](https://img.shields.io/badge/architecture-sequential%20pipeline-orange?style=for-the-badge)

</div>

Analizador de logs para un SOC que detecta patrones sospechosos, consulta un LLM para clasificar amenazas y ejecuta respuestas de firewall con rollback automático por TTL.

## Arquitectura

El proyecto utiliza un pipeline secuencial explícito, no una arquitectura multiagente:

```mermaid
flowchart LR
    A[Archivo de logs] --> B[Recolectar y agrupar por IP]
    B --> C[Filtrar por umbral]
    C --> D[Analizar con Groq<br/>openai/gpt-oss-20b]
    D --> E[Validar whitelist]
    E --> F[Bloquear IP]
    F --> G[(SQLite)]
    G --> H[Rollback al expirar TTL]
```

La separación entre recolección, análisis y ejecución mantiene el flujo fácil de probar sin introducir agentes autónomos ni una capa de orquestación innecesaria.

## Características

- Monitorización de logs tipo syslog, SSH, Apache y Nginx.
- Clasificación estructurada mediante Groq y `openai/gpt-oss-20b`.
- Bloqueo con `netsh` en Windows o `ufw` en Linux.
- Whitelist para evitar bloqueos accidentales.
- Persistencia de amenazas y expiración en SQLite.
- Hilo de rollback que elimina automáticamente los bloqueos expirados.
- Despliegue posible en una máquina virtual de Azure como honeypot.

> **Demostración:** Base de datos SQLite tras un despliegue como honeypot en Azure capturando ataques reales.
>
> ![Captura de ataques reales en Azure](threat_intel_screenshot.png)

## Requisitos

- Python 3.10 o superior.
- Una clave `GROQ_API_KEY`.
- Permisos suficientes para modificar el firewall.

## Instalación local

```bash
git clone https://github.com/juaanmgg/AI-SOC-Log-Analyzer.git
cd AI-SOC-Log-Analyzer
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Configura la clave:

```bash
export GROQ_API_KEY="TU_API_KEY"
# PowerShell:
# $env:GROQ_API_KEY = "TU_API_KEY"
```

Añade las IP protegidas a `whitelist.txt`, una por línea.

## Uso

```bash
python soc_agent.py \
  --log /var/log/auth.log \
  --threshold 3 \
  --ban-time 12 \
  --whitelist whitelist.txt
```

Argumentos:

- `--log`: ruta del archivo de log que se monitoriza.
- `--threshold`: número mínimo de eventos por IP antes de consultar el LLM (por defecto: `3`).
- `--ban-time`: duración del bloqueo en horas (por defecto: `24`).
- `--whitelist`: archivo de IPs exentas (por defecto: `whitelist.txt`).
- `--groq-key`: clave Groq; si no se proporciona, se usa `GROQ_API_KEY`.

El modelo usado es fijo: `openai/gpt-oss-20b`. Ollama y LangGraph no forman parte del runtime.

## Docker

Construye la imagen:

```bash
docker build -t ai-soc .
```

Ejecuta el analizador pasando la clave sin incluirla en la imagen:

```bash
docker run --privileged --network host \
  -e GROQ_API_KEY="TU_API_KEY" \
  -v /var/log/auth.log:/app/auth.log:ro \
  -v "$(pwd)/threat_intel.db:/app/threat_intel.db" \
  ai-soc --log /app/auth.log --whitelist /app/whitelist.txt
```

## Desarrollo y pruebas

```bash
ruff check .
pytest test_soc_agent.py
```

Las pruebas mockean el LLM, la geolocalización y los comandos de firewall; no necesitan una API key ni modificar el firewall real.
