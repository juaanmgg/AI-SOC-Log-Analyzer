# Arquitectura

El analizador mantiene un pipeline secuencial y separa el dominio de los efectos
externos. `soc_agent.py` continúa siendo una fachada retrocompatible durante la
migración.

```mermaid
flowchart LR
    Logs[Archivo de logs] --> Services[Servicios]
    Services --> Domain[Modelos de dominio]
    Services --> Firewall[FirewallAdapter]
    Services --> Database[Adaptador SQLite]
    Firewall --> UFW[UfwAdapter]
    Firewall --> Netsh[NetshAdapter]
```

## Capas

- **Dominio** (`src/ai_soc/domain`): contratos y validación de amenazas; no
  conoce infraestructura.
- **Adaptadores** (`src/ai_soc/adapters`): SQLite y comandos de firewall,
  aislando efectos externos.
- **Servicios** (`src/ai_soc/services`): casos de uso y orquestación.
- **Compatibilidad** (`soc_agent.py`): API existente y CLI hasta completar la
  migración.

## Contratos de datos

- `ThreatItem`: `ip` es una dirección IP válida, `tipo` es texto y `severidad`
  pertenece a `Baja`, `Media`, `Alta` o `Crítica`.
- `ThreatReport`: contiene una lista de `ThreatItem` bajo `amenazas`.
- `DatabaseRecord`: representa una amenaza persistida con `id` opcional,
  expiración, estado activo y los mismos datos de clasificación.
- `FirewallAdapter.block_ip` y `unblock_ip` devuelven `True` solo si el comando
  del sistema termina correctamente.
