# Validación de AIComply para un piloto y publicación PyPI

Revisión: 20 de septiembre de 2026; validadores, gates y publicación actualizados el
21 de septiembre de 2026. Repositorio: `aiambo08/AIComply`.

## Veredicto

AIComply permite localizar ciertos usos peligrosos de IA y producir evidencia
revisable dentro del repositorio del cliente. La CLI puede servir para un
piloto supervisado; todavía no debe ser un control único de seguridad ni una
certificación de cumplimiento. La corrección autorizada de los cinco validadores
nominales pasa los gates completos. El responsable autorizó la fusión y la
publicación de la alpha; Trusted Publishing y la verificación posterior terminaron
correctamente el 21 de septiembre de 2026.

PyPI sirve [**2.0.0a0**](https://pypi.org/project/aicomply-cli/2.0.0a0/),
correspondiente al [tag v2.0.0a0](https://github.com/aiambo08/AIComply/tree/v2.0.0a0)
y al commit `ea1afdb56124c89d465f70923a184add0f4a3095` de la PR #2 fusionada.
La estable **0.1.0** sigue disponible; pip puede preferirla si no se selecciona
la alpha explícitamente.

## Publicación verificada

El [workflow 35587531905](https://github.com/aiambo08/AIComply/actions/runs/35587531905)
pasó los gates en Python 3.11/3.13, publicó los artefactos verificados y completó
el job de instalación desde PyPI. Una instalación local nueva fuera del checkout
también pasó `pip check`, ambos entry points y los escenarios de
`smoke_distribution.py`.

Los artefactos descargados del job de calidad coinciden con la API pública de PyPI:

| Archivo | SHA-256 |
|---|---|
| `aicomply_cli-2.0.0a0-py3-none-any.whl` | `3553a99979f4a75d912684593f14517c10b3e15b0830458cbb22f01be0cd51f5` |
| `aicomply_cli-2.0.0a0.tar.gz` | `d899c75411c82dd0bee20e64a88d1ce93c54807611e7de77a5953074ee79c509` |

La procedencia pública del
[wheel](https://pypi.org/integrity/aicomply-cli/2.0.0a0/aicomply_cli-2.0.0a0-py3-none-any.whl/provenance)
y del
[sdist](https://pypi.org/integrity/aicomply-cli/2.0.0a0/aicomply_cli-2.0.0a0.tar.gz/provenance)
identifica `aiambo08/AIComply`, `publish.yml` y el entorno `pypi`, con los mismos
hashes. Ningún archivo está retirado mediante `yanked`.

El primer intento local inmediatamente posterior a la subida solo encontró
0.1.0. Tras aparecer los nuevos archivos en el índice simple, el mismo comando
de instalación exacta funcionó sin cambios. Este retraso de propagación no
requirió otra subida ni cambiar la versión.

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

## Defecto corregido: cinco nombres de validadores tratados como garantías

La regla `art14_tool_call_taint.yaml` aceptaba `model_validate`,
`model_validate_json`, `pydantic`, `is_safe_command` y `human_gate` como
sanitizadores por nombre. Se había reproducido **cero findings Art. 14**
cuando la salida de `openai.responses.create()` atraviesa
`ToolSchema.model_validate`, `ToolSchema.model_validate_json` o `human_gate`
y después llega a `os.system`.

Un esquema con `command: str` no limita los comandos aceptables. Tampoco el
nombre de una función prueba aprobación humana efectiva. Con autorización del
responsable, se retiraron esos cinco nombres del catálogo de sanitizadores de
ejecución y se convirtió `TN-02` en el positivo `TP-17`, conservando el flujo
original. No se modificó el motor: las llamadas ordinarias ya propagan taint
desde sus argumentos; ahora esos nombres dejan de borrarlo.

Las 48 regresiones nuevas comprueban 35 combinaciones de los cinco validadores
con los siete destinos de ejecución, tres flujos con ramas/cadenas y diez
contrapartes con acciones constantes o reasignación limpia. Se verifican trazas
origen→propagación→destino y su exportación SARIF. **Antes de corregir la regla
fallaban los 38 casos peligrosos; ahora pasan los 48.** El smoke instalado
también exige un finding Art. 14 y su traza para los cinco validadores.

El benchmark actualizado fallaba antes de la corrección: 16/17 positivos,
14/14 negativos, recall 94,12%. Después detecta 17/17 positivos y conserva
14/14 negativos (precisión, recall y F1 del 100% en este corpus sintético).
Los tres umbrales siguen en **0,95**; no se añadieron exclusiones ni xfails.
Este resultado no estima la exactitud sobre código real de clientes.

**Límite de la corrección:** `guardrails.validate` continúa como sanitizador
explícito del catálogo. El motor reconoce su nombre, pero no comprueba su
implementación ni los validadores configurados; podría ocultar un flujo inseguro
si esa política no corresponde a un control efectivo. Las reglas personalizadas
también pueden declarar sanitizadores. Revisar esas políticas es obligatorio
en el piloto; esta corrección no demuestra seguridad de todos los validadores
ni implementa análisis entre funciones o verificación runtime.

## Resultados de distribución

Se ejecutó `scripts/check_quality.py` en Linux con CPython 3.11.13 y 3.13.7:

| Gate | Resultado |
|---|---|
| Lockfile, Ruff y mypy configurado | Correctos; mypy estricto cubre el clasificador, no todo el repositorio |
| Suite completa por intérprete | **625 correctas** |
| Wheel y sdist mediante el backend declarado | Correctos; wheel construido desde sdist |
| `twine check --strict` sobre ambos | Correcto; metadata, descripción y licencia aceptadas |
| Comparación de recursos YAML/UI | Correcta |
| Wheel con dependencias fijadas y hashes | Instalado fuera del checkout; `pip check` correcto |
| Sdist con pip y resolución desde PyPI sin caché | Instalado fuera del checkout; `pip check` correcto |
| Escenarios de `smoke_distribution.py` en ambas instalaciones | Correctos |
| Hashes del wheel/sdist **publicados 0.1.0** | Coinciden con la metadata pública de PyPI |
| Publicación real de **2.0.0a0** | Correcta desde `v2.0.0a0`; hashes, procedencia pública e instalación exacta comprobados |
| Intento manual previo de `publish.yml` | La integración devolvió HTTP 403; la publicación autorizada se activó posteriormente mediante push del tag |
| Consola en Chrome | Cinco validadores nominales, acciones constantes, reasignación limpia y descarga SARIF comprobados |
| Windows/macOS/Python distintos de 3.11 y 3.13 | No probados en esta revisión |

El smoke instalado comprueba ambos entry points, versión, procedencia de imports,
assets locales, código cliente no ejecutado, escaneo limpio/peligroso/acotado,
JSON/Markdown/SARIF, manifest, Anexo IV, firma válida y manipulada, datos personales,
TLS, configuración/sintaxis inválidas, los cinco validadores nominales y contexto
de decisiones automatizadas.

La primera ejecución local simultánea de ambas suites ocupó el mismo puerto
8991 del fixture de consola: seis errores de arranque en 3.11. Se repitió el
gate 3.11 después de finalizar 3.13, sin modificar ni omitir pruebas, y pasó
completo. Ejecutar las matrices en máquinas separadas, como en CI, o en serie
si comparten máquina. Mypy adicional de los tres scripts de release también
pasa con `MYPYPATH=src uv run --frozen mypy --follow-imports=silent
scripts/check_quality.py scripts/smoke_distribution.py scripts/verify_pypi.py`.

La suite existente añade contratos de aliases/merges/duplicados YAML,
symlinks/hardlinks/archivos especiales, límites, sintaxis/codificación, supresiones,
Docker/Compose, dependencias, CFG/finally, firmas y API local. No equivale a una
auditoría formal o pruebas exhaustivas de carga.

## Procedimiento de publicación

Primero aprobar la PR y revisar los gates del commit que se vaya a publicar,
incluidos los límites de sanitizadores descritos arriba. El autoescaneo del
repositorio tiene hallazgos y su
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

Instalación de la alpha publicada (Linux/macOS, con Python 3.11 disponible):

```bash
python3.11 -m venv .venv-aicomply
.venv-aicomply/bin/python -m pip install --index-url https://pypi.org/simple 'aicomply-cli==2.0.0a0'
.venv-aicomply/bin/python -m pip check
.venv-aicomply/bin/aicomply --help
```

Este comando selecciona la alpha verificada. `pip install aicomply-cli` sin versión puede seleccionar la estable
0.1.0; usar la versión alpha explícita o una política consciente de `--pre`.

Referencias: [Trusted Publishing](https://docs.pypi.org/trusted-publishers/),
[GitHub Actions](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[API JSON de PyPI](https://docs.pypi.org/api/json/),
[preversiones de pip](https://pip.pypa.io/en/stable/cli/pip_install/#pre-release-versions).

## Condiciones que siguen pendientes

Además de la revisión de sanitizadores declarados, faltan validación jurídica del
contexto, corpus representativo de clientes, umbrales operativos medidos y pruebas de carga
exhaustivas. La consola sigue siendo local y carece de autenticación, RBAC,
aislamiento multiempresa y retención administrada. La propuesta es un piloto
local/CI supervisado, no un SaaS público listo para producción.
