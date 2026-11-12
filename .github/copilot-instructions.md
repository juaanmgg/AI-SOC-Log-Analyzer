# Instrucciones de ingeniería

## Arquitectura

- Mantener la separación por capas: dominio sin infraestructura, adaptadores para
  integraciones externas y servicios para la orquestación.
- Las dependencias deben apuntar hacia el dominio; el dominio no importa SQLite,
  subprocess, HTTP ni proveedores LLM.
- Mantener `soc_agent.py` como fachada de compatibilidad hasta completar una
  migración explícita de consumidores.

## Seguridad

- Validar todas las IP con `ipaddress` o Pydantic antes de ejecutar acciones.
- Ejecutar comandos del sistema con listas de argumentos y `shell=False`; nunca
  interpolar comandos en una shell.
- No registrar secretos, claves API ni datos sensibles.
- El bloqueo automático debe permanecer opt-in y los fallos de infraestructura
  deben ser explícitos y registrarse.

## Calidad y estilo

- Usar Python 3.10+ con type hints y Pydantic para contratos externos.
- Mantener Ruff y Mypy sin errores nuevos y añadir pruebas para cada comportamiento
  nuevo.
- Preferir funciones pequeñas, nombres descriptivos en español cuando ya formen
  parte de la API pública y cambios quirúrgicos.
- Ejecutar `ruff check .` y `pytest` antes de entregar cambios.
