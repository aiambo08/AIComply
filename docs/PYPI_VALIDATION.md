# Validación de AIComply para un piloto y publicación PyPI

Revisión: 20 de septiembre de 2026. Repositorio: `aiambo08/AIComply`.

## Veredicto

AIComply permite localizar ciertos usos peligrosos de IA y producir evidencia
revisable dentro del repositorio del cliente. La CLI puede servir para un
piloto supervisado; todavía no debe ser un control único de seguridad ni una
certificación de cumplimiento. No recomendar la publicación nueva hasta
resolver el falso negativo de validadores descrito abajo.

El repositorio y PyPI difieren: PyPI sirve **0.1.0**, cuya instalación, ayuda,
dependencias y hashes de wheel/sdist se comprobaron en un entorno nuevo.
La distribución preparada aquí es **2.0.0a0**: se construye, valida e instala,
pero **no se ha subido a PyPI**. Una subida histórica mediante Trusted
Publishing y su procedencia pública no prueban que la siguiente vaya a pasar.

## Problema empresarial y utilidad comprobada

El primer caso de uso es revisar un cambio de código antes de permitir que un
asistente ejecute herramientas, publique texto o intervenga en decisiones.
Un responsable técnico puede priorizar hallazgos por archivo, seguir una traza
origen→destino en SARIF, corregirla y conservar los hashes del código, reglas y
configuración junto con el informe. El responsable de privacidad o cumplimiento
debe aportar el contexto y revisar la evaluación y el borrador del Anexo IV.

| Situación | Comprobación reproducible | Límite de la conclusión |
|---|---|---|
| Asistente que convierte una respuesta de IA en un comando shell | Traza de taint y finding `EUAIA-ART14-002` | La revisión debe comprobar privilegios y ejecución real |
| Respuesta generada enviada a un endpoint de usuario | Traza hasta `jsonify` y señal de transparencia | No determina qué excepciones del Art. 50 aplican |
| Acción fija seleccionada por la respuesta del modelo | No confundir texto del modelo con argumentos constantes | Otros riesgos de la acción siguen requiriendo revisión |
| Procesamiento de solicitudes de crédito o candidaturas | Contexto de perfilado/decisión significativa conserva `requires_review` | La finalidad y el impacto son declarados, no inferidos del código |
| Datos personales ficticios o TLS desactivado | Señales de privacidad y seguridad | No inventaría todos los datos ni verifica controles desplegados |
| Informe que cambia después de la revisión | Firma alterada rechazada; cambio de fuente modifica hash | La firma no acredita identidad, legalidad ni tiempo confiable |

El piloto debe medir tiempo de revisión, hallazgos confirmados, falsos positivos,
falsos negativos conocidos y correcciones realizadas sobre repositorios
representativos autorizados. No se han medido reducción de multas, eficacia
en clientes reales ni cobertura universal. El benchmark sintético no sustituye
esa evaluación.

## Defecto corregido: APIs actuales no reconocidas

La nueva matriz añade 41 comprobaciones sintéticas: 26 flujos a destinos
sensibles, 13 contrapartes con acciones constantes y dos clientes no relacionados
con IA. **22 fallaban antes de ampliar las fuentes y ahora pasan**.

La corrección cubre Responses de OpenAI, clientes asíncronos OpenAI/Anthropic,
Azure OpenAI síncrono/asíncrono y Google GenAI síncrono/asíncrono. Conserva los
casos de Chat Completions y Anthropic existentes. Se comprueban aliases de
importación, trazas en SARIF, remediación y ausencia de logging.
No se importaron SDK ni ejecutaron llamadas a proveedores: son pruebas del
análisis estático de esos patrones. No cubren streaming, wrappers arbitrarios,
resolución entre funciones ni comportamiento runtime.

## Defecto pendiente: nombres de validadores tratados como garantías

La regla `art14_tool_call_taint.yaml` acepta, entre otros, `model_validate`,
`model_validate_json`, `pydantic`, `is_safe_command` y `human_gate` como
sanitizadores por nombre. Se reprodujo un resultado de **cero findings Art. 14**
cuando la salida de `openai.responses.create()` atraviesa
`ToolSchema.model_validate`, `ToolSchema.model_validate_json` o `human_gate`
y después llega a `os.system`.

Un esquema con `command: str` no limita los comandos aceptables. Tampoco el
nombre de una función prueba aprobación humana efectiva. El benchmark
`TN-02` espera actualmente que ese esquema elimine la señal; por eso el
benchmark puede pasar aunque exista este falso negativo.

Corrección propuesta para aprobación del responsable:

1. Quitar esos nombres genéricos del conjunto de sanitizadores de ejecución.
2. Mantener taint a través de validaciones de tipo y funciones nominales.
3. Cambiar `TN-02` a un caso positivo y añadir regresiones de esos flujos.
4. Mantener los negativos de acciones constantes/permitidas y el umbral 0,95.
5. Repetir ambos gates completos antes de crear un tag de publicación.

No se modificó esa expectativa existente sin autorización. Las 577 pruebas
correctas no resuelven este problema; no se ocultó con una exclusión o un
umbral menos exigente.

## Resultados de distribución

Se ejecutó `scripts/check_quality.py` en Linux con CPython 3.11.13 y 3.13.7:

| Gate | Resultado |
|---|---|
| Lockfile, Ruff y mypy configurado | Correctos; mypy estricto cubre el clasificador, no todo el repositorio |
| Suite completa por intérprete | **577 correctas** |
| Wheel y sdist mediante el backend declarado | Correctos; wheel construido desde sdist |
| `twine check --strict` sobre ambos | Correcto; metadata, descripción y licencia aceptadas |
| Comparación de recursos YAML/UI | Correcta |
| Wheel con dependencias fijadas y hashes | Instalado fuera del checkout; `pip check` correcto |
| Sdist con pip y resolución desde PyPI sin caché | Instalado fuera del checkout; `pip check` correcto |
| Escenarios de `smoke_distribution.py` en ambas instalaciones | Correctos |
| Hashes del wheel/sdist **publicados 0.1.0** | Coinciden con la metadata pública de PyPI |
| Publicación real de **2.0.0a0** | Pendiente; ningún tag de publicación creado |
| Navegador/Windows/macOS/Python distintos de 3.11 y 3.13 | No probados en esta revisión |

El smoke instalado comprueba ambos entry points, versión, procedencia de imports,
assets locales, código cliente no ejecutado, escaneo limpio/peligroso/acotado,
JSON/Markdown/SARIF, manifest, Anexo IV, firma válida y manipulada, datos personales,
TLS, configuración/sintaxis inválidas y contexto de decisiones automatizadas.

La suite existente añade contratos de aliases/merges/duplicados YAML,
symlinks/hardlinks/archivos especiales, límites, sintaxis/codificación, supresiones,
Docker/Compose, dependencias, CFG/finally, firmas y API local. No equivale a una
auditoría formal o pruebas exhaustivas de carga.

## Procedimiento de publicación

Primero cerrar el defecto pendiente, aprobar la PR y revisar los gates del commit
que se vaya a publicar. El autoescaneo del repositorio tiene hallazgos y su
política de tratamiento requiere una decisión independiente; no se han silenciado.

1. Mantener el Trusted Publisher del proyecto `aicomply-cli` con el repositorio
   `aiambo08/AIComply`, workflow `publish.yml` y entorno `pypi`.
   El permiso `id-token: write` existe solo en el job de publicación.
2. Revisar versión, changelog y `uv.lock`. El tag debe ser canónico:
   `v2.0.0a0`, no `v2.0.0-alpha`. Comprobar que esa versión no exista en PyPI.
3. Ejecutar el gate local y, si se desea, `workflow_dispatch` en la rama:
   la ejecución manual solo comprueba calidad, incluso si se selecciona un tag.
4. **Con autorización de publicación**, crear y enviar el tag sobre el commit
   revisado. Un push `v*` ejecuta calidad en 3.11/3.13 y publica únicamente los
   artefactos producidos y probados por el job de 3.11. No reconstruye en el
   job que recibe permisos de publicación.
5. El job `verify-pypi` compara los SHA-256 de ambos archivos con la API pública
   de PyPI (reintentos acotados por propagación), instala la versión exacta con
   pip desde PyPI, ejecuta `pip check` y repite los escenarios fuera del checkout.
   Ese job solo tiene permiso de lectura del repositorio.
6. Verificar también la procedencia pública y guardar el enlace al workflow.
   Si falla la comprobación posterior, la subida podría haber ocurrido:
   investigar antes de reintentar. PyPI no permite reemplazar los mismos archivos;
   no reutilizar versiones o tags para distribuir contenido diferente.

Tras confirmar la publicación de esta alpha:

```bash
python3.11 -m venv .venv-aicomply
.venv-aicomply/bin/python -m pip install --index-url https://pypi.org/simple 'aicomply-cli==2.0.0a0'
.venv-aicomply/bin/python -m pip check
.venv-aicomply/bin/aicomply --help
```

Este comando **todavía no instala la versión preparada**, porque no está
publicada. `pip install aicomply-cli` sin versión puede seleccionar la estable
0.1.0; usar la versión alpha explícita o una política consciente de `--pre`.

Referencias: [Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
[GitHub Actions](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[API JSON de PyPI](https://docs.pypi.org/api/json/),
[preversiones de pip](https://pip.pypa.io/en/stable/cli/pip_install/#pre-release-versions).

## Condiciones que siguen pendientes

Además del falso negativo, faltan validación jurídica del contexto, corpus
representativo de clientes, umbrales operativos medidos y pruebas de carga
exhaustivas. La consola sigue siendo local y carece de autenticación, RBAC,
aislamiento multiempresa y retención administrada. La propuesta es un piloto
local/CI supervisado, no un SaaS público listo para producción.
