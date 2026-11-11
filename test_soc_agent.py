import sqlite3
import subprocess
from unittest.mock import MagicMock, patch

from langchain_core.language_models import FakeListChatModel

from soc_agent import (
    DatabaseManager,
    SOCAnalyzer,
    cargar_whitelist,
    crear_llm,
    recolectar_logs,
)


def test_extraccion_ips_y_ruido_avanzado():
    """Prueba la recolección con múltiples patrones de logs (SSH, Nginx, etc.)."""
    logs = [
        "Oct 22 10:12:32 Failed password for root from 203.0.113.45 port 54321 ssh2",
        "Oct 22 10:15:02 Invalid user test from 198.51.100.22 port 49111",
        "nginx: 192.168.1.50 - - [error] 403 Forbidden access",
        "Successful login for admin from 10.0.0.1"  # Ruido normal, debe ignorarse
    ]
    resultado = recolectar_logs(logs)

    assert "203.0.113.45" in resultado
    assert "198.51.100.22" in resultado
    assert "192.168.1.50" in resultado
    assert "10.0.0.1" not in resultado
    assert len(resultado) == 3


def test_whitelist_comportamiento(tmp_path):
    """Valida que la whitelist cargue IPs correctamente e ignore líneas vacías."""
    archivo_wl = tmp_path / "whitelist.txt"
    archivo_wl.write_text("192.168.1.100\n10.0.0.5\n\n  \n")  # Espacios y saltos de línea basura

    wl = cargar_whitelist(str(archivo_wl))

    assert "127.0.0.1" in wl
    assert "localhost" in wl
    assert "192.168.1.100" in wl
    assert "10.0.0.5" in wl
    assert len(wl) == 4


def test_database_manager_ciclo_completo(tmp_path):
    """Valida persistencia usando un archivo temporal destructible que imita producción."""
    db_file = tmp_path / "test_threat_intel.db"
    db = DatabaseManager(str(db_file))

    # Insertamos amenazas con diferentes tiempos de vida (TTL)
    db.registrar_amenaza("1.1.1.1", "ES", "Fuerza Bruta", "Alta", ban_time_hours=1)
    db.registrar_amenaza("2.2.2.2", "US", "DDoS", "Media", ban_time_hours=-1)  # Ya expirado
    db.registrar_amenaza("3.3.3.3", "RU", "Scanner", "Baja", ban_time_hours=-5)  # Ya expirado

    expiradas = db.obtener_ips_expiradas()

    assert "1.1.1.1" not in expiradas
    assert "2.2.2.2" in expiradas
    assert "3.3.3.3" in expiradas

    # Simulamos el rollback marcando una como desbloqueada
    db.marcar_desbloqueada("2.2.2.2")
    expiradas_actualizadas = db.obtener_ips_expiradas()

    assert "2.2.2.2" not in expiradas_actualizadas
    assert "3.3.3.3" in expiradas_actualizadas


@patch("soc_agent.requests.get")
def test_geolocalizacion_api_mock(mock_get):
    """Mockea la red para probar la geolocalización sin consumir cuota de API."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"country": "Japón"}
    mock_get.return_value = mock_response

    # Usamos un modelo LLM falso para que LangChain pueda construir su cadena sin errores
    fake_llm = FakeListChatModel(responses=['{"amenazas": []}'])
    
    analyzer = SOCAnalyzer(llm=fake_llm, db_manager=None, whitelist=set(), es_windows=True, ban_time=24)
    pais = analyzer._obtener_geolocalizacion("8.8.8.8")

    assert pais == "Japón"
    mock_get.assert_called_once_with("http://ip-api.com/json/8.8.8.8?fields=country", timeout=3)


@patch("soc_agent.subprocess.run")
def test_ejecucion_comandos_firewall(mock_subprocess):
    """Asegura que el orquestador genere los binarios correctos de Windows y Linux sin ejecutarlos."""
    fake_llm = FakeListChatModel(responses=['{"amenazas": []}'])
    
    analyzer_win = SOCAnalyzer(llm=fake_llm, db_manager=None, whitelist=set(), es_windows=True, ban_time=24)
    analyzer_lin = SOCAnalyzer(llm=fake_llm, db_manager=None, whitelist=set(), es_windows=False, ban_time=24)

    analyzer_win._ejecutar_bloqueo("5.5.5.5")
    mock_subprocess.assert_called_with(
        ["netsh", "advfirewall", "firewall", "add", "rule", "name=SOC_5.5.5.5",
         "dir=in", "action=block", "remoteip=5.5.5.5"],
        check=True,
        shell=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    analyzer_lin._ejecutar_bloqueo("6.6.6.6")
    mock_subprocess.assert_called_with(
        ["ufw", "deny", "from", "6.6.6.6", "to", "any"],
        check=True,
        shell=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_pipeline_analiza_y_ejecuta_en_orden():
    fake_llm = FakeListChatModel(
        responses=['{"amenazas": [{"ip": "5.5.5.5", "tipo": "Fuerza Bruta", "severidad": "Alta"}]}']
    )
    analyzer = SOCAnalyzer(
        llm=fake_llm,
        db_manager=MagicMock(),
        whitelist=set(),
        es_windows=True,
        ban_time=24,
        auto_block=True,
    )

    with patch.object(analyzer, "_obtener_geolocalizacion", return_value="ES"), patch.object(
        analyzer, "_ejecutar_bloqueo"
    ) as bloquear:
        resultado = analyzer.procesar({"5.5.5.5": ["Failed password from 5.5.5.5"]})

    bloquear.assert_called_once_with("5.5.5.5")
    assert resultado["acciones_ejecutadas"] == ["Bloqueada: 5.5.5.5 (ES) - Fuerza Bruta"]


@patch("soc_agent.ChatGroq")
def test_crear_llm_usa_modelo_configurado(mock_chat_groq):
    crear_llm("test-key")
    mock_chat_groq.assert_called_once_with(
        model="openai/gpt-oss-20b",
        groq_api_key="test-key",
        temperature=0,
    )


def test_normalizacion_descarta_ips_invalidas():
    resultado = SOCAnalyzer._normalizar_amenazas(
        {
            "amenazas": [
                {"ip": "8.8.8.8", "tipo": "Scanner", "severidad": "Media"},
                {"ip": "999.999.999.999", "tipo": "Fuerza Bruta"},
                {"ip": "no-es-una-ip", "tipo": "DDoS", "severidad": "Crítica"},
                {"ip": "9.9.9.9", "tipo": "DDoS", "severidad": "desconocida"},
            ]
        }
    )

    assert resultado == [
        {"ip": "8.8.8.8", "tipo": "Scanner", "severidad": "Media"},
        {"ip": "9.9.9.9", "tipo": "DDoS", "severidad": "Media"},
    ]


def test_rollback_no_expira_ip_con_bloqueo_vigente(tmp_path):
    db = DatabaseManager(str(tmp_path / "threats.db"))
    db.registrar_amenaza("1.1.1.1", "US", "Scanner", "Media", ban_time_hours=-1)
    db.registrar_amenaza("1.1.1.1", "US", "Scanner", "Alta", ban_time_hours=1)

    assert db.obtener_ips_expiradas() == []


def test_modo_simulacion_no_ejecuta_firewall():
    fake_llm = FakeListChatModel(responses=['{"amenazas": []}'])
    analyzer = SOCAnalyzer(
        llm=fake_llm,
        db_manager=MagicMock(),
        whitelist=set(),
        es_windows=True,
        ban_time=24,
        dry_run=True,
    )

    with patch.object(analyzer, "_ejecutar_bloqueo") as bloquear:
        resultado = analyzer.ejecutar(
            [{"ip": "8.8.8.8", "tipo": "Scanner", "severidad": "Media"}]
        )

    bloquear.assert_not_called()
    analyzer.db.registrar_amenaza.assert_not_called()
    assert resultado["acciones_ejecutadas"] == ["Simulada: 8.8.8.8 - Scanner"]


def test_registrar_amenaza_renueva_bloqueo_activo(tmp_path):
    db = DatabaseManager(str(tmp_path / "threats.db"))
    db.registrar_amenaza("8.8.8.8", "US", "Scanner", "Media", 1)
    db.registrar_amenaza("8.8.8.8", "US", "Scanner", "Alta", 2)

    with sqlite3.connect(tmp_path / "threats.db") as conn:
        total, severidad = conn.execute(
            "SELECT COUNT(*), MAX(severidad) FROM amenazas WHERE ip = ? AND activo = 1",
            ("8.8.8.8",),
        ).fetchone()

    assert total == 1
    assert severidad == "Alta"


@patch("soc_agent.subprocess.run", side_effect=subprocess.CalledProcessError(1, "ufw"))
def test_fallo_firewall_no_se_reporta_como_exito(mock_subprocess):
    fake_llm = FakeListChatModel(responses=['{"amenazas": []}'])
    analyzer = SOCAnalyzer(fake_llm, MagicMock(), set(), False, 24, auto_block=True)

    assert analyzer._ejecutar_bloqueo("8.8.8.8") is False
    mock_subprocess.assert_called_once()