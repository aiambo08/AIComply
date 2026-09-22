# AIComply

Análisis estático local de señales técnicas relacionadas con el Reglamento
europeo de IA y el RGPD. Python 3.11+, CLI, consola local, JSON, Markdown,
SARIF 2.1.0 y evidencia firmada con Ed25519.

**Estado: alpha publicada para pilotos locales supervisados.** No es una certificación, una opinión jurídica
ni una garantía de evitar multas. Sin hallazgos no significa conformidad.

**Distribución:** [aicomply-cli 2.0.0a0](https://pypi.org/project/aicomply-cli/2.0.0a0/)
se publicó el 21 de septiembre de 2026 mediante Trusted Publishing.
El [workflow de publicación y verificación](https://github.com/aiambo08/AIComply/actions/runs/35587531905)
comprobó los hashes del wheel/sdist y la instalación de la versión exacta desde PyPI.
Consulta la [validación de producto y PyPI](docs/PYPI_VALIDATION.md), incluida
la corrección de validadores nominales y sus límites, antes de adoptar el
analizador como gate de seguridad. Las versiones alpha requieren selección
explícita en pip; una instalación sin versión puede conservar la versión estable anterior.
Antes de desplegar, consultar [condiciones de lanzamiento](docs/PRODUCTION_READINESS.md).

## Instalación de la alpha desde PyPI

Dentro de un entorno virtual propio de AIComply, con Python 3.11 o superior:

```bash
python -m pip install --index-url https://pypi.org/simple 'aicomply-cli==2.0.0a0'
python -m pip check
aicomply --help
```

Esta instalación permite ejecutar `aicomply` directamente; los comandos con
`uv run` de las secciones siguientes corresponden al checkout del repositorio.

## Instalación reproducible desde el repositorio

```bash
python3 -m pip install --user uv==0.8.22
uv python install 3.11
uv sync --locked --extra dev --python 3.11
uv run aicomply --help
```

`uv.lock` fija el entorno de desarrollo/CI. Una instalación de la wheel sin
el lock puede resolver otras versiones dentro de los rangos del paquete.
No instales AIComply dentro del entorno de un cliente ni instales sus
dependencias para analizar su código.

## Uso

Ejecutar estos comandos desde el checkout de AIComply; sustituir `/ruta/cliente`
por una copia local autorizada. Guardar reportes fuera del árbol analizado.

```bash
uv run aicomply scan /ruta/cliente
uv run aicomply scan /ruta/cliente --format json --output ../report.json
uv run aicomply scan /ruta/cliente --format markdown --output ../report.md
uv run aicomply scan /ruta/cliente --format sarif --output ../report.sarif
uv run aicomply scan /ruta/cliente --articles 5,12,14,50
uv run aicomply assess
uv run aicomply docgen /ruta/cliente --name "Sistema declarado" \
  --version "1.2.0" --output ../annex-iv.md
```

| Salida de `scan` | Significado |
|---|---|
| 0 | Escaneo completado y política de hallazgos satisfecha; no acredita legalidad |
| 1 | Hallazgos por encima de la tolerancia configurada; por defecto cualquier hallazgo |
| 2 | Error de argumentos, configuración, lectura, análisis, firma o escritura |

En GitHub Actions, `Execute AIComply scan` con código 1 indica hallazgos que
bloquean la política. Revisar el SARIF en **Security → Code scanning** cuando se
haya subido. El [diagnóstico del autoescaneo](docs/PYPI_VALIDATION.md#diagnóstico-del-autoescaneo-en-github-actions)
documenta los casos de prueba del propio repositorio.

`--enforce-risk-tier high_risk` tolera `high_risk`, `limited_risk` y
`minimal_risk`, pero falla con `prohibited`. Son **etiquetas técnicas del
catálogo**, no clasificación jurídica del sistema. La opción CLI tiene
prioridad sobre la configuración del proyecto. Sin umbral se falla con
cualquier hallazgo.

### Configuración y alcance

La configuración se lee de `.aicomply.yaml` en la raíz objetivo (o en el
directorio de un archivo objetivo). Las claves desconocidas, YAML inválido,
duplicados, aliases y tipos incorrectos producen error explícito.

```yaml
exclude_paths:
  - "generated/**"
ignore_rules: []
custom_rules_dir: "review-rules"
enforce_risk_tier: "high_risk"
```

`custom_rules_dir` debe permanecer dentro del objetivo. Las reglas personalizadas
son políticas confiables: revisar sus regex y semántica antes de usarlas.
Las exclusiones y supresiones (`# aicomply:ignore EUAIA-ART12-001`) reducen cobertura:
requieren justificación y revisión; no prueban que el riesgo haya desaparecido.

El análisis incluye AST/taint **intraprocedural de Python**, regex en extensiones
admitidas, manifests/lockfiles de Python y comprobaciones Docker/Compose.
No ejecuta el código objetivo, no instala sus dependencias y no envía el
código a servicios externos. No modela completamente funciones externas,
reflexión, concurrencia, heap, runtime, datasets ni arquitectura desplegada.

Rechaza entradas ilegibles, symlinks, archivos especiales, codificación inválida,
sintaxis Python inválida e inputs excesivos. Compose con aliases/merges requiere
una copia expandida revisada manualmente. Los límites del CLI son 4 MiB por
archivo, 100 MiB totales y 10.000 entradas. Las rutas ignoradas se registran.
Las extensiones no admitidas no se analizan; no hay cobertura universal.

### Procedencia

El JSON contiene:

- `scan_id`: hash del conjunto de hallazgos; dos escaneos sin hallazgos pueden
  compartirlo aunque el código sea distinto.
- `source_manifest`: rutas relativas, tamaños y SHA-256 de los bytes capturados;
  `source_manifest_hash` identifica ese inventario.
- `active_rule_ids`, `rules_fingerprint`, `effective_config`,
  `config_fingerprint` y `exclusions`: política y límites efectivos.
- `analysis_status`, `legal_assessment`, `limitations` e imports observados.

El inventario no es un snapshot atómico del repositorio completo ni cubre
archivos excluidos. Los reportes pueden contener código, datos personales o
secretos presentes en snippets: aplicar acceso restringido, retención y
eliminación acordados con cada cliente. Las salidas CLI a archivo se escriben
atómicamente con permisos POSIX restrictivos; Windows requiere su propia
política de ACL.

## Evidencia Ed25519

```bash
uv run aicomply keygen --out-dir ../private-evidence-keys --name reviewer
uv run aicomply scan /ruta/cliente --format json --sign \
  --key ../private-evidence-keys/reviewer.pem --signer-id "review-service" \
  --output ../signed-report.json
uv run aicomply verify ../signed-report.json \
  --public-key ../private-evidence-keys/reviewer.pub
```

Solo JSON conserva el envelope firmado. La clave privada se crea sin
sobrescritura y con modo POSIX 0600; es PKCS8 **sin cifrar** y no debe
almacenarse en el repositorio. Guardarla en un directorio privado y gestionar
custodia, rotación y backups. `str`/`bytes` en la API de firmas son contenido;
solo un `Path` explícito solicita lectura local.

Una verificación válida prueba integridad del payload canónico respecto de
la clave suministrada. La confianza en esa clave es externa. No prueba
legalidad, identidad acreditada, fecha confiable, revocación ni admisibilidad
judicial. Se rechazan JSON ambiguos, versiones/algoritmos incorrectos y
campos omitidos o normalizados. Bundles anteriores que no incluyan el
schema completo pueden requerir regeneración; nunca reinterpretarlos como
una nueva firma.

## Consola local

```bash
uv run aicomply ui /ruta/cliente --host 127.0.0.1 --port 8080 --no-browser
```

Abrir la URL loopback mostrada por el comando. La consola sirve recursos
locales sin CDN, limita Host/Origin y confina el análisis al objetivo de inicio.
No usar proxies públicos, túneles ni binds a `0.0.0.0`: carece de autenticación,
RBAC y aislamiento multi-tenant.

El worker usa snapshot privado, límites de tiempo/memoria y descriptores POSIX
sin seguir enlaces. Scan/docgen por UI requieren estas capacidades; plataformas
sin ellas fallan explícitamente. Límites adicionales: 32 MiB por snapshot,
10.000 entradas, profundidad 64, 30 s de ejecución, 512 MiB de memoria, un trabajo
activo, ocho conexiones, 2 MiB por petición y 8 MiB por respuesta. El navegador
admite evidencia de hasta 1 MiB.

La evaluación comparte el modelo contextual del CLI y conserva valores
desconocidos. El Anexo IV es un borrador de nueve secciones con información
pendiente; importar una librería no demuestra controles efectivos.

## GitHub Action

Fijar el Action a un commit revisado; sustituir el marcador:

```yaml
- uses: actions/checkout@v4
- uses: aiambo08/AIComply@<reviewed-commit-sha>
  with:
    path: "."
    format: "sarif"
    output: "aicomply-results.sarif"
    upload-sarif: "false"
```

Para subir SARIF, activar `upload-sarif` y conceder `security-events: write`
solo al job correspondiente. Revisar permisos y confidencialidad: subir SARIF
transfiere resultados a GitHub. En forks y Dependabot no se intenta esa subida.
El Action valida un reporte fresco y propaga los errores; no añadir `|| true`.
Las fixtures intencionalmente riesgosas de este repositorio disparan hallazgos:
la política del autoescaneo requiere una decisión del mantenedor, no una
excepción silenciosa en CI.

## Desarrollo y controles

```bash
uv sync --locked --extra dev
uv run ruff check .
uv run mypy
uv run pytest -q
uv run --frozen python scripts/check_quality.py
```

`mypy` comprueba estrictamente el clasificador; no todo el proyecto está
tipado estrictamente. El script de calidad exige tests/lint/tipos, construye
wheel y sdist, verifica recursos, instala en un entorno aislado, comprueba
dependencias y prueba los entry points y un escaneo SARIF instalado.

Para modificar estilos de la consola (Node/npm solo en desarrollo):

```bash
npm exec --yes --package=tailwindcss@3.4.17 -- tailwindcss \
  --config src/aicomply/ui/static/tailwind.config.cjs \
  --input src/aicomply/ui/static/app.source.css \
  --output src/aicomply/ui/static/app.css --minify
node --check src/aicomply/ui/static/app.js
```

No se publican métricas universales de precisión o recall: las pruebas
sintéticas no representan todas las aplicaciones ni determinan infracciones.

## Documentación

- [System prompt del agente](docs/AGENT_SYSTEM_PROMPT.md).
- [Guía regulatoria y registro de fuentes](docs/EU_AI_ACT_ENGINEERS_GUIDE.md).
- [Análisis del repositorio y condiciones de producción](docs/PRODUCTION_READINESS.md).
- [Diseño histórico, con garantías no verificadas](docs/adr_phase2_architecture.md).

Licencia [MIT](LICENSE). La adopción requiere evaluación técnica y jurídica
según finalidad, rol, jurisdicción y operación real del cliente.
