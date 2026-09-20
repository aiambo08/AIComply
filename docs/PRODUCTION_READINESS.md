# AIComply: análisis del repositorio y condiciones de lanzamiento

Fecha de revisión: **2026-09-20**. Alcance: CLI, motores de análisis,
configuración/reglas, evidencia, reportes, clasificación contextual, consola,
distribución, documentación y CI del repositorio.

## Decisión

**No autorizar todavía un lanzamiento general ni un SaaS multiempresa.**
Esta propuesta refuerza un producto local alpha y deja una base verificable
para revisión. No se ha publicado en PyPI, desplegado un servicio ni realizado
una evaluación jurídica de un cliente.

El responsable autorizó actualizar las siete expectativas incompatibles con
los contratos de seguridad y prudencia jurídica. La suite completa pasa
**502 pruebas** y el gate integrado local de distribución termina correctamente.
No se han desactivado pruebas, rebajado umbrales ni añadido `|| true`.
Quedan la comprobación remota de esta revisión, la decisión de política del
autoescaneo y las condiciones operativas y regulatorias detalladas abajo.

El [system prompt especializado](AGENT_SYSTEM_PROMPT.md) fue aplicado a la
implementación: evidencia antes que afirmaciones, revisión normativa contextual,
lecturas confinadas, errores explícitos y validación del paquete instalable.

## Arquitectura y fronteras

```text
CLI / Action / hook
  -> configuración estricta + catálogo validado
  -> descubrimiento y copia de bytes autorizados
  -> AST Python / CFG-taint / regex aislada / manifests / Docker
  -> findings + inventario + fingerprints + límites/exclusiones
  -> terminal / Markdown / JSON / SARIF / firma Ed25519

Consola loopback
  -> Host/Origin + límites de petición y concurrencia
  -> descriptor de raíz + worker con límites POSIX
  -> snapshot privado -> mismo ScanEngine

Contexto declarado -> assess_context -> evaluación provisional + pendientes
ScanReport capturado -> Anexo IV de nueve secciones -> borrador para completar
```

El código del cliente es entrada no confiable. El analizador no lo importa,
ejecuta, instala ni transmite. Los subprocess ejecutan herramientas de
AIComply, no código del objetivo. Las reglas y configuraciones son políticas:
deben ser aprobadas por el operador; no debe aceptarse la supresión de controles
de un cliente como prueba de ausencia de riesgo.

## Revisión por componente

| Componente | Hallazgo / riesgo de diseño | Cambio y evidencia |
|---|---|---|
| `config.py`, `rules/loader.py` | Defaults silenciosos, políticas ambiguas y reglas malformadas | Tipos/claves/IDs/regex estrictos, límites, YAML sin duplicados/aliases, error explícito |
| `scanner/engine.py` | Escaneo parcial presentado como completo, lectura no acotada, falta de procedencia | Snapshots de bytes, límites, rechazo de entradas inválidas, hashes de fuente/reglas/config y exclusiones |
| `scanner/ast_parser.py` | Resolución incompleta de alias y coincidencias demasiado amplias | Resolución de importaciones; targets completos en logging; `fer` no coincide dentro de `transfer` |
| `dataflow/cfg_builder.py`, `taint_engine.py` | Flujos de control y propagación que podían perder señales; nombres de variables aceptados como control humano | Asignaciones fuertes, joins, contenedores/expresiones, bucles, excepciones y terminación; compuertas nominales no suprimen hallazgos |
| `scanner/regex_matcher.py` | Regex inválidas o costosas podían fallar silenciosamente/bloquear | Validación, subprocess aislado, presupuesto temporal y de coincidencias |
| `infra/` | Errores de manifests/lectura confundidos con ausencia de resultados | Lectura acotada y confinada, parseo y fallos explícitos; formatos Python y Docker |
| `evidence/signer.py` | Envelope ambiguo, normalización, campos no autenticados, claves sobrescritas | JSON canónico estricto, Ed25519 fijo, hashes coherentes, claves sin sobrescritura y permisos restrictivos |
| `classifier/assess.py` | Clasificación binaria sin contexto suficiente | Rol, ámbito, finalidad, Anexos I/III, perfilado, Art. 50, GPAI y RGPD; `requires_review` |
| `reporter/` | Ausencia de findings presentada como conformidad; cifras sancionadoras y salida no confiable | Separación técnica/jurídica, límites y fingerprints; escape HTML/Markdown/Rich y controles Unicode visibles |
| `generator/annex_iv.py` | Dossier incompleto y deducciones no demostradas por imports | Nueve puntos, pendientes explícitos, imports del snapshot y apéndice técnico; ninguna declaración de conformidad inventada |
| `ui/server.py`, `worker.py` | Lectura fuera del proyecto, falta de límites y recursos remotos | Loopback, Host/Origin, CSP, assets locales, snapshot confinado, JSON estricto, tiempo/memoria/concurrencia limitados |
| UI verificación | Parsear JSON en el navegador borraba duplicados antes de verificar | Envío del texto original; la API verifica antes de reconstruir metadata |
| `cli.py` | Umbral reenviado por Action no soportado; firmas descartadas en formatos no JSON | `--enforce-risk-tier`, contrato de salidas 0/1/2, firma JSON obligatoria, escritura atómica |
| Action/CI/publicación | Fallos ocultos, resultados viejos y publicación sin gates de distribución | Comandos sin shell interpolado, reporte fresco, propagación del error, permisos restringidos y gate reutilizable |
| Paquete/hook | Assets/entry points no verificados; tipos del hook combinados como intersección | Validación de wheel/sdist e instalación aislada; `types_or` para activar el hook |
| README y guía | Métricas y garantías no demostradas, calendario incompleto | Documentación de contratos, fuentes oficiales fechadas y condiciones reales de operación |

Las regresiones añadidas cubren límites de rutas, tipos de archivo, parseo,
timeout de regex, flujos de taint, firmas manipuladas, claves, protocolo HTTP,
Action, recursos instalados y evaluación contextual. No constituyen una
prueba formal de ausencia de vulnerabilidades.

## Resultados reproducibles y gates

Entorno local: Linux, CPython 3.11.13, uv 0.8.22 y dependencias de `uv.lock`.

| Verificación | Resultado |
|---|---|
| `uv sync --locked --extra dev`, `uv lock --check` | Correcto |
| `uv run ruff check .` | Correcto; conjunto de reglas configurado en `pyproject.toml` |
| `uv run mypy` | Correcto; clasificador en modo estricto |
| Mypy adicional de consola/clasificador y evidencia con imports silenciosos | Correcto; no implica tipado estricto de todo el producto |
| Suite completa `uv run pytest -q` | **502 correctas, ninguna fallida**; ejecutada dentro del gate integrado |
| `uv run --frozen python scripts/check_quality.py` | Correcto de principio a fin: lint, tipos, tests, build e instalación aislada |
| Build de wheel y sdist | Correcto dentro del gate integrado; sin publicar |
| Comparación de recursos YAML/UI en ambos archivos | Correcta |
| Instalación de wheel fuera del checkout, dependencias con hashes y `pip check` | Correcto |
| Entry points `aicomply`, `aicomply-cli` y smoke SARIF del paquete instalado | Correctos |
| Compilación Tailwind 3.4.17 y sintaxis de JavaScript | Correctas |
| `pre-commit validate-manifest` | Correcto; hook con tipos alternativos |
| API HTTP por tests automatizados | Verificada; no equivale a una prueba visual de navegador |
| Recorrido de consola en Chrome con proyectos sintéticos | Escaneo, detalles/SARIF, evaluación contextual, Anexo IV y verificación de evidencia comprobados; inputs adversariales rechazados |
| Accesibilidad completa, concurrencia y presupuestos exhaustivos | **No verificados** |
| Matriz remota Python 3.11/3.13 | Pendiente de ejecución sobre los contratos actualizados; la revisión anterior reproducía los siete fallos |

Los 126 tests de los módulos modificados también pasaron antes del gate completo.
La validación local del paquete no sustituye los demás controles de lanzamiento
ni la aprobación para publicar.

### Prueba de consola autorizada

Se ejecutó un recorrido grabado en Chrome con proyectos sintéticos y claves
efímeras: ausencia de señales sin prometer conformidad, hallazgos y selección
de detalles, SARIF descargable, contexto desconocido, perfilado, GPAI, Art. 5,
Anexo IV y recuperación tras errores de firma o symlinks. Texto hostil se
mostró literalmente; el marcador sintético de ejecución del código cliente
no apareció.

Se aceptó evidencia válida y se rechazaron manipulación, duplicados, campos
omitidos/adicionales y tamaño excesivo. Los probes HTTP complementarios
comprobaron confinamiento, Host/Origin, esquema y límites de petición.

La prueba detectó que la etiqueta `INVALID` conservaba el verde del resultado
válido. Se separaron los estados visuales: sin verificar neutro, firma válida
verde y firma rechazada rojo. No existen controles de filtrado de hallazgos
en esta revisión, por lo que ese recorrido no se pudo ejecutar.

No se probaron exhaustivamente consumo de recursos, concurrencia, cancelación,
otras plataformas, accesibilidad, impresión/PDF ni todas las ramas regulatorias.

### Siete incompatibilidades resueltas con autorización

Actualización autorizada el 2026-09-20. Se mantienen casos positivos y negativos,
incluido Compose sin aliases, imports inventariados y la traza completa del LLM
al sink aunque exista una variable de aprobación humana.

| Prueba | Expectativa anterior | Contrato aceptado y comprobado |
|---|---|---|
| CLI, proyecto sin findings | Texto `CONFORMIDAD TÉCNICA VALIDADA` | Código 0 conservado; texto sin hallazgos, sin conclusión jurídica |
| Anexo IV, imports de ejemplo | `Conformidad Plena` | Clasificación pendiente y evidencias por aportar |
| Configuración corrupta | Volver silenciosamente a defaults | Error explícito sin generar reporte de éxito |
| Compose con alias (dos casos) | Aceptar anchors/merge aliases | Rechazo uniforme de aliases para evitar expansión/ciclos; copia expandida revisada como entrada alternativa |
| Taint, `is_human_approved` | Suprimir el finding por el nombre de la variable | Mantener señal hasta demostrar validación y supervisión efectiva |
| Benchmark TN-03 | Tratar la misma compuerta nominal como negativo cierto | Conservar su código como TP-16 y exigir `EUAIA-ART14-002`; añadir TN-16 con selección cerrada de comandos constantes |

Se conservan los umbrales del **95%** para precisión, recall y F1. Con las
etiquetas anteriores se obtenían 15/15 positivos y 14/15 negativos: precisión
93,75%, recall 100% y F1 96,77% sobre 30 fixtures. El código de TN-03 no validaba
el comando ni demostraba supervisión efectiva; se conserva sin cambios como
positivo TP-16. TN-16 solo ejecuta comandos literales elegidos mediante dos
opciones explícitas y retorna para cualquier otra entrada.

El corpus revisado tiene **31 fixtures sintéticas**: 16/16 positivos,
15/15 negativos, cero falsos positivos/negativos y precisión/recall/F1 del 100%
en esta ejecución. Se mide presencia de señales por archivo y la regla esperada
en positivos; no exactitud por hallazgo. La variación se debe a corregir la
etiqueta y añadir un caso, no a mejorar el motor entre ambas mediciones.
Estos resultados son regresiones del catálogo, no evaluación independiente,
eficacia normativa o comercial. Los negativos con sanitizadores o supresiones
dependen de los supuestos del catálogo; no verifican su efectividad real.

Otra alternativa para Compose sería diseñar expansión limitada, con límites
de profundidad/nodos y detección de ciclos compartidos por todos los lectores.
No basta quitar el rechazo de aliases en un solo parser.

### Autoescaneo del repositorio

El autoescaneo produce señales sobre el ejemplo deliberadamente riesgoso de
fintech y coincidencias sobre literales del propio catálogo/analizador.
No demuestra infracciones legales ni vulnerabilidades ejecutadas.
El workflow de compliance propagará ese resultado con su política por defecto.

Antes de exigir ese check para merge, el mantenedor debe decidir la política
de revisión para muestras y reglas del escáner: separar explícitamente fixtures
de producto, justificar excepciones por ubicación o mantener el gate estricto.
No se han añadido exclusiones nuevas ni cambiado el umbral para ocultarlo.

## Modelo de operación admisible

El primer candidato es una **herramienta local supervisada por un analista**:

1. Copia autorizada, estable y de solo lectura del repositorio del cliente.
2. Operador con política revisada; directorios privados de fuentes, claves y
   reportes. Revisar configuración del proyecto antes de usarla.
3. Scan local y registro de inventario, catálogo, configuración y exclusiones.
4. Triage humano por señal, finalidad/rol/jurisdicción y evidencia externa.
5. Remediación, nueva ejecución y conservación controlada de ambos estados.
6. Firma opcional y verificación independiente con una clave ya confiable.
7. Revisión jurídica y de producto antes de entregar conclusiones al cliente.

La consola no debe publicarse por túnel o reverse proxy. Loopback no autentica
a otros procesos del mismo host: reservar máquinas/cuentas confiables.
Los subprocess y límites POSIX no son una frontera de tenant o un sandbox
completo contra vulnerabilidades del intérprete.

## Límites y trabajo requerido antes de producción

### Gates del candidato local

- Confirmar la matriz remota de calidad tras los contratos ya aprobados y
  resolver la política del autoescaneo sin exclusiones de emergencia.
- Fijar ground truth del benchmark con datos autorizados, revisión experta,
  versión de reglas y método de medición; añadir repositorios representativos.
- Cotejar con asesoría jurídica el texto consolidado y acto modificativo del
  AI Omnibus, fuentes/fechas, sanciones, excepciones y rol de cada cliente.
- Completar accesibilidad de UI y pruebas de límites/concurrencia; decidir si
  se requieren filtros de hallazgos antes del lanzamiento.
- Validar plataformas realmente soportadas, consumo y concurrencia en
  repositorios grandes; verificar recuperación tras timeout o cancelación.
- Revisar dependencias, licencias, procedencia del paquete, versionado,
  notas de migración, rollback y procedimiento de divulgación de vulnerabilidades.
- Definir custodia/rotación/revocación de claves, retención, borrado, backups,
  confidencialidad de snippets y procedimiento de acceso al código de clientes.

### Para un futuro servicio multiempresa

Requiere un diseño adicional: autenticación y MFA/SSO, autorización por rol,
aislamiento de almacenamiento y ejecución por tenant, ingestión segura, colas
con cuotas, límites y cancelación, cifrado/gestión de claves, registros de
acceso minimizados, monitorización e incidentes, borrado verificable y contratos
de tratamiento/localización de datos. Nada de esto se obtiene publicando
el actual `http.server`.

### Cobertura técnica residual

El taint es intraprocedural y aproximado; no resuelve completamente alias de
objetos, estado global, importación dinámica, metaprogramación, llamadas externas,
concurrencia o semántica del despliegue. Regex puede coincidir con texto que
no representa una acción. Una dependencia declarada puede no ejecutarse.
Los analizadores no inspeccionan datasets, pesos, prompts runtime, contratos,
telemetría real ni controles organizativos.

Los bytes se capturan por archivo con comprobaciones de estabilidad; no se
obtiene un snapshot transaccional de un repositorio que cambia simultáneamente.
El CLI limita bytes/entradas y regex, pero carece del presupuesto global de
CPU/memoria del worker de consola: usar aislamiento del sistema operativo
para análisis automatizado de repositorios hostiles.

Las reglas, sanitizadores y supresiones reducen señales según supuestos
explícitos. Sus nombres no verifican que la implementación real sea segura.
Los rangos de dependencias publicados no fijan todo el entorno; `uv.lock`
sí fija el entorno reproducido en esta revisión.

## Orden de cierre

1. Confirmar los gates remotos y decidir la política del autoescaneo.
2. Completar los casos UI pendientes.
3. Completar revisión jurídica, benchmark representativo y controles operativos.
4. Revisar/mergear PR, aplicar el blueprint compatible y publicar una versión
   solo con autorización y con el gate de distribución superado.

El [README](../README.md) contiene los comandos; la
[guía regulatoria](EU_AI_ACT_ENGINEERS_GUIDE.md) registra fuentes y límites.
