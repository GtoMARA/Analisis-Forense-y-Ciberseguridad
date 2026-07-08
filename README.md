# Analisis Forense y Ciberseguridad

Repositorio tecnico y educativo sobre analisis forense digital, respuesta a incidentes y ciberseguridad defensiva.

El objetivo es reunir documentacion, playbooks, reglas de deteccion y pequenas herramientas reproducibles que ayuden a investigar incidentes, preservar evidencias y mejorar la seguridad de sistemas reales usando principalmente herramientas libres.

> Proyecto en desarrollo. El contenido publicado debe poder verificarse mediante fuentes tecnicas, documentacion oficial o pruebas reproducibles.

## Proposito

La ciberseguridad y la informatica forense son disciplinas distintas, pero se complementan durante todo el ciclo de gestion de incidentes:

- La ciberseguridad ayuda a prevenir, detectar, contener y recuperar.
- La informatica forense ayuda a identificar, adquirir, preservar, analizar y documentar evidencias digitales.
- La respuesta a incidentes conecta ambas areas para entender que ocurrio, reducir impacto y evitar repeticiones.

Este repositorio nace para documentar esa interseccion desde un enfoque practico, defensivo y verificable.

## Alcance

Aqui se publicaran materiales como:

- Guias tecnicas sobre analisis forense digital y respuesta a incidentes.
- Playbooks defensivos para escenarios comunes como phishing, ransomware, malware o accesos no autorizados.
- Scripts basicos para extraccion de indicadores, calculo de hashes, adquisicion controlada de informacion y apoyo a la documentacion.
- Reglas de deteccion, especialmente Sigma/YARA cuando proceda, con referencias y contexto.
- Ejemplos reproducibles usando datasets de prueba, laboratorios propios o muestras benignas como EICAR cuando aplique.
- Listados razonados de herramientas libres empleadas en DFIR y ciberseguridad defensiva.

No se publicaran:

- Malware real ni instrucciones para desplegar actividad ofensiva contra terceros.
- Credenciales, datos personales, evidencias reales no anonimizadas o informacion sensible de casos.
- Afirmaciones tecnicas sin fuente, prueba o advertencia clara de que son hipotesis.
- Funcionalidades comerciales o privadas que no esten listas para liberarse de forma segura.

## Principios del Proyecto

1. **Verificabilidad**: cada afirmacion tecnica relevante debe enlazar a una fuente fiable o acompanarse de una prueba reproducible.
2. **Defensa y legalidad**: el material esta orientado a laboratorios propios, investigacion autorizada, hardening, respuesta a incidentes y analisis forense.
3. **Preservacion de evidencias**: se priorizan integridad, trazabilidad, cadena de custodia y documentacion del proceso.
4. **Herramientas libres**: se dara preferencia a proyectos abiertos, documentados y mantenibles.
5. **Claridad**: las guias deben poder ser seguidas por estudiantes, administradores y profesionales sin confundir herramientas, formatos o resultados.

## Estructura Prevista

```text
.
|-- docs/                 # Guias tecnicas y referencias
|-- playbooks/            # Procedimientos defensivos paso a paso
|-- tools/                # Scripts sencillos y auditables
|-- sigma/                # Reglas Sigma con referencias
|-- yara/                 # Reglas YARA para laboratorios controlados
|-- labs/                 # Ejercicios reproducibles con datos de prueba
|-- datasets/             # Datos benignos o enlaces a datasets publicos
`-- references/           # Bibliografia, normas y documentacion oficial
```

La estructura puede evolucionar conforme se incorporen herramientas y documentacion.

## Lineas de Trabajo Iniciales

### 1. Fundamentos DFIR

- Diferencias entre ciberseguridad, respuesta a incidentes e informatica forense.
- Conceptos de evidencia digital, integridad, hash, trazabilidad y cadena de custodia.
- Buenas practicas para documentar acciones durante una investigacion.

### 2. Herramientas Basicas

- Calculadora y verificador de hashes.
- Extractor simple de IOCs: IPs, dominios, URLs y hashes.
- Generador basico de informes en Markdown/JSON.
- Plantillas de cadena de custodia y registro de acciones.

### 3. Playbooks Defensivos

- Analisis inicial de correo sospechoso.
- Triage de equipo Windows.
- Respuesta inicial ante ransomware.
- Recoleccion segura de logs.
- Analisis basico de indicadores con APIs publicas respetando sus limites y terminos.

### 4. Reglas y Detecciones

- Reglas Sigma con campo `references` obligatorio.
- Reglas YARA para muestras de laboratorio o patrones benignos.
- Mapeo opcional a MITRE ATT&CK cuando la tecnica este bien identificada.

## Buenas Practicas de Publicacion

Antes de anadir una guia, script o regla:

- Comprobar que los comandos funcionan en un entorno de prueba.
- Indicar sistema operativo, version de herramienta y dependencias.
- Incluir enlaces a documentacion oficial siempre que sea posible.
- Evitar estadisticas sin informe, fecha y pagina concreta.
- Separar hechos verificados, inferencias y ejemplos didacticos.
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

## Aviso Legal y Etico

Este repositorio tiene fines educativos, defensivos y de investigacion autorizada. El uso de herramientas o procedimientos aqui descritos debe realizarse unicamente en sistemas propios, laboratorios controlados o entornos donde exista autorizacion expresa.

El contenido no constituye asesoramiento legal. En investigaciones reales, especialmente si pueden derivar en procedimientos disciplinarios, contractuales o judiciales, deben seguirse las politicas internas aplicables y consultar con responsables legales o peritos cualificados.

## Licencia

Este proyecto se publica bajo licencia MIT, salvo que se indique otra licencia en archivos o directorios concretos. Consulta el archivo [LICENSE](LICENSE) para mas informacion.

