# 🛡️ AI SOC Log Analyzer (Blue Team Tool)

Un sistema de Detección y Prevención de Intrusiones (IPS/IDS) impulsado por Inteligencia Artificial. Analiza en tiempo real los registros de autenticación del sistema, clasifica los ataques utilizando Llama 3.1 y ejecuta contramedidas de bloqueo automatizadas a nivel de red (Firewall).

## 🚀 Características Principales

    Análisis en Tiempo Real: Monitorización viva (tail -f) de archivos de registro con procesamiento por lotes temporales.

    IA Local y Privacidad de Datos: Utiliza modelos LLM locales mediante Ollama, garantizando que los registros sensibles (IPs, usuarios) nunca salgan de la infraestructura (o adaptativo vía API para la nube).

    Clasificación Inteligente (Few-Shot Prompting): Discrimina entre ataques de Fuerza Bruta y Password Spraying, reduciendo los falsos positivos.

    Respuesta Automatizada (SOAR): Bloqueo dinámico e instantáneo de IPs atacantes. Soporte multiplataforma (netsh para Windows Defender Firewall y ufw para Linux).

## 🛠️ Arquitectura y Tecnologías

    Lenguaje: Python 3.10+

    Motor de IA: Ollama (Llama 3.1)

    Expresiones Regulares (Regex): Filtrado previo de ruido para optimizar el procesamiento.

## ⚙️ Instalación

    Clona el repositorio: git clone [https://github.com/TU_USUARIO/AI-SOC-Log-Analyzer.git](https://github.com/TU_USUARIO/AI-SOC-Log-Analyzer.git)

    Descarga el modelo: ollama run llama3.1

    Instala dependencias: pip install -r requirements.txt

## 💻 Uso
Ejecutar en modo vigilancia (requiere privilegios de Administrador/Root):python analyzer.py --log dummy_auth.log --threshold 3