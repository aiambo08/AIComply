# Guía de ingeniería: señales técnicas y obligaciones contextuales

Revisión: **2026-09-20**. Alcance: Reglamento (UE) 2024/1689 y RGPD.
Esta guía orienta la preparación de evidencias; no determina conformidad.

## 1. Recoger contexto antes de clasificar

Registrar finalidad prevista, usuarios y personas afectadas, jurisdicción,
rol de cada organización, versiones y despliegues, modelos/datasets de
terceros, cambios de finalidad y tratamiento de datos personales. El rol
puede variar entre sistemas o actividades: evaluar cada combinación.
Un campo desconocido permanece pendiente.

`aicomply assess` y el formulario de la consola comparten `SystemContext`.
Siempre devuelven una evaluación provisional, fuentes y contexto pendiente.
Las etiquetas de reglas de `scan` priorizan revisión técnica; no sustituyen
la evaluación contextual.

## 2. Mapa de revisión

| Disposición | Condición que debe verificarse | Evidencia que el código no basta para probar |
|---|---|---|
| Arts. 2–3 | Definición, ámbito territorial, exclusiones | Flujo comercial, finalidad real, participantes |
| Art. 5 | Elementos de cada práctica y sus excepciones | Contexto laboral/educativo, perjuicio, biometría, finalidad |
| Art. 6(1), Anexo I | Producto/componente y evaluación de terceros exigida | Normativa sectorial y procedimiento aplicable |
| Art. 6(2), Anexo III | Uso enumerado | Finalidad concreta, personas y decisiones afectadas |
| Art. 6(3)–(4) | Excepción documentada, sin riesgo significativo/influencia material | Justificación del proveedor, registro cuando corresponda; el perfilado impide la excepción |
| Arts. 9–15 | Requisitos de sistemas de alto riesgo | Gestión de riesgos, datos, documentación, logs, instrucciones, supervisión, robustez |
| Arts. 16–27 | Obligaciones por rol | Responsables, contratos, incidentes, instrucciones y evaluaciones |
| Art. 50 | Transparencia según interacción, contenido y rol | Información efectiva, marcado, divulgación y excepciones |
| Arts. 51–55 | Proveedor de modelo GPAI y posible riesgo sistémico | Evaluaciones, documentación, copyright, información a integradores |
| RGPD Arts. 5/6/9/25/32/35 | Tratamiento y riesgos | Base jurídica, minimización, conservación, garantías, EIPD |
| RGPD Art. 22 | Decisión exclusivamente automatizada con efectos jurídicos o similares significativos | Excepciones, intervención humana efectiva, impugnación y garantías |

GPAI y alto riesgo del sistema son evaluaciones distintas y pueden coexistir.
El Art. 13 trata transparencia/instrucciones de sistemas de alto riesgo;
el Art. 50 trata obligaciones específicas de información, marcado y divulgación.
No basta una llamada `logging`, un booleano llamado `human_approved`, un
disclaimer ni una etiqueta de texto para demostrar el cumplimiento material.

## 3. Interpretar hallazgos con prudencia

- Un import de `fer` o dependencia `deepface` acredita un patrón/declaración,
  no emociones en el trabajo ni scraping indiscriminado. Revisar usos reales.
- La ausencia de logging reconocido en un archivo puede coexistir con
  middleware o infraestructura de registro; su presencia no prueba eficacia.
- Un puerto 8000 puede estar detrás de TLS. Revisar redes, proxies y despliegue.
- Sanitizadores del catálogo representan supuestos del análisis. Validar que
  realmente transforman datos y que cubren el riesgo del destino concreto.
- Un nombre de compuerta humana no acredita aprobación efectiva, autenticada,
  específica a la operación, trazable y no eludible.
- Una regex de datos personales puede coincidir con fixtures o falsos positivos.
  Documentar la revisión sin divulgar secretos o datos del cliente.

El analizador no ejecuta código, inspecciona datasets reales ni prueba modelos.
No evalúa métricas por subgrupos, drift, equidad, exactitud runtime o contratos.
Un resultado vacío solo describe el catálogo y el alcance analizados.

## 4. Evidencias de ingeniería

Para cada señal conservar ubicación, bytes/versiones, hashes de fuentes,
catálogo y configuración, alcance/exclusiones, revisor, conclusión motivada,
mitigación y verificación posterior. Registrar responsables, fechas y cambios.

Aplicar controles según el caso: separación de privilegios, validación de
acciones, supervisión humana efectiva, controles de acceso, evaluación de
modelos y datasets, pruebas adversariales, gestión de incidencias y seguimiento.
No registrar indiscriminadamente prompts, respuestas, identificadores o
secretos para demostrar trazabilidad. Definir acceso, minimización y retención.

## 5. Los nueve puntos del Anexo IV

1. Descripción general, finalidad, proveedor, versiones, hardware/software,
   interfaces, usuarios y puesta a disposición.
2. Desarrollo: diseño, lógica, arquitectura, terceros, datos, entrenamiento,
   validación/pruebas, supervisión, cambios y ciberseguridad.
3. Monitorización, funcionamiento, control, capacidades/limitaciones,
   exactitud por grupos, riesgos, entradas y supervisión.
4. Adecuación de las métricas de rendimiento.
5. Sistema de gestión de riesgos del Art. 9.
6. Cambios relevantes durante el ciclo de vida.
7. Normas armonizadas, especificaciones o soluciones alternativas aplicadas.
8. Copia de la declaración UE de conformidad emitida por el responsable.
9. Vigilancia poscomercialización y plan del Art. 72.

`docgen` crea un borrador con estos nueve puntos, imports del snapshot y
señales técnicas. No inventa datasets, finalidad, evaluaciones, responsables,
certificaciones ni declaraciones. El Markdown generado no está firmado:
conservar por separado el JSON firmado y sus evidencias externas.

## 6. Fuentes y calendario

| Fuente oficial | Naturaleza / disposición | Uso y límite de la verificación |
|---|---|---|
| [Reglamento (UE) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | Texto legal publicado; Arts. 2–6, 9–27, 50–55, 99, 113; Anexos I/III/IV | Base normativa. La publicación original no sustituye comprobar modificaciones y régimen transitorio vigentes |
| [RGPD](https://eur-lex.europa.eu/eli/reg/2016/679/oj) | Texto legal; Arts. 5, 6, 9, 22, 25, 32, 35, 83 | Revisar tratamiento, excepciones y legislación complementaria |
| [Service Desk: Art. 6](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-6) | Presentación institucional | Apoyo para Art. 6 y anexos; no sustituye Diario Oficial |
| [Service Desk: Anexo IV](https://ai-act-service-desk.ec.europa.eu/en/ai-act/annex-4) | Presentación institucional | Estructura de documentación de nueve puntos |
| [AI Omnibus](https://digital-strategy.ec.europa.eu/en/news/ai-omnibus-enters-force) | Comunicación institucional consultada el 2026-09-20 | Comunica modificaciones/calendario; pendiente cotejo integral con acto modificativo y texto consolidado |
| [Enforcement AI Act](https://digital-strategy.ec.europa.eu/en/policies/enforcement-ai-act) | Información de la Comisión | Autoridades, aplicación y calendario |

La información institucional consultada comunica 2027-12-02 para los usos
del Anexo III y 2028-08-02 para productos del Anexo I. El clasificador los
presenta como fechas orientativas que requieren confirmar texto vigente,
rol, fecha de comercialización y transición. No convertir fechas de una
noticia o propuesta en un dictamen jurídico. Revalidar este registro antes de
cada release o evaluación de cliente.

## 7. Sanciones: referencias, no predicciones

El Art. 99 diferencia, entre otros, máximos de 35 M€ / 7%, 15 M€ / 3% y
7,5 M€ / 1% según categoría. Hay reglas específicas para empresas, pymes,
autoridades y otros supuestos; la cifra aplicable requiere valoración jurídica.
Los proveedores GPAI tienen un régimen separado, incluido el Art. 101.
RGPD Art. 83(4) incluye Art. 32 y el máximo 10 M€ / 2%;
Art. 83(5) contempla otras infracciones con 20 M€ / 4%.

No sumar máximos por hallazgo. El código no determina facturación, causalidad,
responsabilidad, proporcionalidad, acumulación ni decisión de una autoridad.
No presentar hallazgos como multas previstas o cantidades evitadas.
