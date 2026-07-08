# Analisis Forense y Ciberseguridad

Repositorio tecnico y educativo sobre analisis forense digital, respuesta a incidentes y ciberseguridad defensiva.

El objetivo es reunir documentacion, playbooks, reglas de deteccion y pequenas herramientas reproducibles que ayuden a investigar incidentes, preservar evidencias y mejorar la seguridad de sistemas reales usando principalmente herramientas libres.

> Proyecto en desarrollo. El contenido publicado debe poder verificarse mediante fuentes técnicas, documentación oficial o pruebas reproducibles.

## Propósito

La ciberseguridad y la informática forense son disciplinas distintas, pero se complementan durante todo el ciclo de gestión de incidentes:

- La ciberseguridad ayuda a prevenir, detectar, contener y recuperar.
- La informática forense ayuda a identificar, adquirir, preservar, analizar y documentar evidencias digitales.
- La respuesta a incidentes conecta ambas areas para entender que ocurrió, reducir impacto y evitar repeticiones.

Este repositorio nace para documentar esa intersección desde un enfoque práctico, defensivo y verificable.

## Alcance

Aquí se publicarán materiales como:

- Guías técnicas sobre análisis forense digital y respuesta a incidentes.
- Playbooks defensivos para escenarios comunes como phishing, ransomware, malware o accesos no autorizados.
- Scripts básicos para extracción de indicadores, cálculo de hashes, adquisición controlada de información y apoyo a la documentación.
- Reglas de detección, especialmente Sigma/YARA cuando proceda, con referencias y contexto.
- Ejemplos reproducibles usando datasets de prueba, laboratorios propios o muestras benignas como EICAR cuando aplique.
- Listados razonados de herramientas libres empleadas en DFIR y ciberseguridad defensiva.

No se publicarán:

- Malware real ni instrucciones para desplegar actividad ofensiva contra terceros.
- Credenciales, datos personales, evidencias reales no anonimizadas o información sensible de casos.
- Afirmaciones técnicas sin fuente, prueba o advertencia clara de que son hipotesis.
- Funcionalidades comerciales o privadas que no esten listas para liberarse de forma segura.

## Principios del Proyecto

1. **Verificabilidad**: cada afirmación técnica relevante debe enlazar a una fuente fiable o acompanarse de una prueba reproducible.
2. **Defensa y legalidad**: el material está orientado a laboratorios propios, investigación autorizada, hardening, respuesta a incidentes y analisis forense.
3. **Preservacion de evidencias**: se priorizan integridad, trazabilidad, cadena de custodia y documentación del proceso.
4. **Herramientas libres**: se dará preferencia a proyectos abiertos, documentados y mantenibles.
5. **Claridad**: las guías deben poder ser seguidas por estudiantes, administradores y profesionales sin confundir herramientas, formatos o resultados.

## Estructura Prevista

```text
.
|-- docs/                 # Guías técnicas y referencias
|-- playbooks/            # Procedimientos defensivos paso a paso
|-- tools/                # Scripts sencillos y auditables
|-- sigma/                # Reglas Sigma con referencias
|-- yara/                 # Reglas YARA para laboratorios controlados
|-- labs/                 # Ejercicios reproducibles con datos de prueba
|-- datasets/             # Datos benignos o enlaces a datasets públicos
`-- references/           # Bibliografía, normas y documentación oficial
```

La estructura puede evolucionar conforme se incorporen herramientas y documentación.

## Líneas de Trabajo Iniciales

### 1. Fundamentos DFIR

- Diferencias entre ciberseguridad, respuesta a incidentes e informática forense.
- Conceptos de evidencia digital, integridad, hash, trazabilidad y cadena de custodia.
- Buenas practicas para documentar acciones durante una investigacion.

### 2. Herramientas Básicas

- Calculadora y verificador de hashes.
- Extractor simple de IOCs: IPs, dominios, URLs y hashes.
- Generador básico de informes en Markdown/JSON.
- Plantillas de cadena de custodia y registro de acciones.

### 3. Playbooks Defensivos

- Análisis inicial de correo sospechoso.
- Triage de equipo Windows.
- Respuesta inicial ante ransomware.
- Recoleccion segura de logs.
- Analisis basico de indicadores con APIs públicas respetando sus límites y términos.

### 4. Reglas y Detecciones

- Reglas Sigma con campo `references` obligatorio.
- Reglas YARA para muestras de laboratorio o patrones benignos.
- Mapeo opcional a MITRE ATT&CK cuando la técnica este bien identificada.

## Buenas Prácticas de Publicación

Antes de anadir una guía, script o regla:

- Comprobar que los comandos funcionan en un entorno de prueba.
- Indicar sistema operativo, versión de herramienta y dependencias.
- Incluir enlaces a documentación oficial siempre que sea posible.
- Evitar estadísticas sin informe, fecha y página concreta.
- Separar hechos verificados, inferencias y ejemplos didácticos.
- Anonimizar cualquier dato que pueda identificar a personas, empresas o sistemas reales.

## Referencias Base

Estas referencias sirven como punto de partida para el contenido del repositorio:

- [NIST SP 800-61 Rev. 3 - Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [ISO/IEC 27037:2012 - Guidelines for identification, collection, acquisition and preservation of digital evidence](https://www.iso.org/standard/44381.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Volatility Foundation](https://volatilityfoundation.org/)
- [Autopsy Digital Forensics](https://www.autopsy.com/)
- [EICAR Anti-Malware Testfile](https://www.eicar.org/download-anti-malware-testfile/)

## Contribuciones

Las contribuciones son bienvenidas si respetan el enfoque defensivo y verificable del proyecto.

Para proponer cambios:

1. Abrir una issue explicando el problema, mejora o fuente que se quiere anadir.
2. Enviar un pull request con cambios pequenos y revisables.
3. Incluir referencias cuando se anadan afirmaciones tecnicas, reglas o procedimientos.
4. Evitar datos reales no anonimizados.

## Aviso Legal y Ético

Este repositorio tiene fines educativos, defensivos y de investigacion autorizada. El uso de herramientas o procedimientos aquí descritos debe realizarse unicamente en sistemas propios, laboratorios controlados o entornos donde exista autorización expresa.

El contenido no constituye asesoramiento legal. En investigaciones reales, especialmente si pueden derivar en procedimientos disciplinarios, contractuales o judiciales, deben seguirse las politicas internas aplicables y consultar con responsables legales o peritos cualificados.

## Licencia

Este proyecto se publica bajo licencia MIT, salvo que se indique otra licencia en archivos o directorios concretos. Consulta el archivo [LICENSE](LICENSE) para mas información.

