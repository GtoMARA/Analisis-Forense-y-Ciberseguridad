# Cadena de custodia básica en evidencias digitales

## Objetivo

Documentar de forma sencilla cómo preservar la trazabilidad de una evidencia digital desde su identificación hasta su análisis. Esta guía no sustituye procedimientos internos, normativa aplicable ni asesoramiento pericial, pero ofrece una base práctica para laboratorios, formación y primeros pasos en DFIR.

## Conceptos clave

- **Evidencia original**: soporte, archivo, registro o dato que se quiere preservar.
- **Copia de trabajo**: copia utilizada para análisis, evitando modificar el original.
- **Hash**: huella criptográfica que permite comprobar si un archivo ha cambiado.
- **Cadena de custodia**: registro de quién tuvo acceso a la evidencia, cuándo, cómo y con qué finalidad.
- **Trazabilidad**: capacidad de reconstruir las acciones realizadas sobre una evidencia.

## Principios básicos

1. Trabajar sobre copias, no sobre el original.
2. Calcular hashes antes y después de copiar.
3. Registrar fecha, hora, operador, herramienta y sistema usado.
4. Mantener un registro de acciones claro y cronológico.
5. Guardar evidencias, copias e informes en ubicaciones controladas.
6. Evitar servicios externos si la evidencia contiene datos personales, secretos o información sensible.

## Flujo mínimo recomendado

### 1. Identificar la evidencia

Registrar:

- Identificador interno.
- Descripción.
- Origen.
- Ubicación.
- Persona que la localiza.
- Fecha y hora.
- Motivo de adquisición.

Ejemplo:

```text
ID: EVD-2026-001
Tipo: Archivo .eml
Origen: Buzón corporativo de laboratorio
Ubicación inicial: equipo de análisis
Operador: Nombre Apellido
Fecha/hora: 2026-07-08 10:30 UTC
Motivo: Análisis de correo sospechoso
```

### 2. Calcular hash inicial

Windows:

```powershell
Get-FileHash .\evidencia.eml -Algorithm SHA256
```

Linux/macOS:

```bash
sha256sum ./evidencia.eml
```

En macOS también puede usarse:

```bash
shasum -a 256 ./evidencia.eml
```

### 3. Crear una copia de trabajo

Windows:

```powershell
Copy-Item .\evidencia.eml .\trabajo\evidencia_copia.eml
```

Linux/macOS:

```bash
cp ./evidencia.eml ./trabajo/evidencia_copia.eml
```

### 4. Verificar la copia

Windows:

```powershell
Get-FileHash .\trabajo\evidencia_copia.eml -Algorithm SHA256
```

Linux/macOS:

```bash
sha256sum ./trabajo/evidencia_copia.eml
```

El hash de la copia debe coincidir con el hash del original.

### 5. Registrar acciones

Cada acción debe quedar documentada:

| Fecha/hora | Operador | Acción | Herramienta | Resultado |
| --- | --- | --- | --- | --- |
| 2026-07-08 10:30 UTC | Nombre Apellido | Cálculo de hash SHA-256 | Get-FileHash | Hash registrado |
| 2026-07-08 10:35 UTC | Nombre Apellido | Creación de copia de trabajo | Copy-Item | Copia verificada |

## Qué debe incluir una ficha de evidencia

- ID de evidencia.
- Descripción.
- Origen.
- Ubicación actual.
- Hashes calculados.
- Herramientas utilizadas.
- Historial de custodia.
- Observaciones.
- Firma o validación del operador si procede.

## Errores comunes

- Analizar directamente el archivo original.
- No registrar la versión de la herramienta usada.
- Mezclar evidencias de distintos casos sin identificadores claros.
- Subir archivos sensibles a servicios externos.
- Confiar solo en capturas de pantalla sin conservar los datos originales.
- Usar MD5 o SHA-1 como única garantía de integridad. Pueden aparecer en fuentes antiguas, pero se recomienda SHA-256 o superior.

## Referencias

- [NIST SP 800-86 - Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [ISO/IEC 27037:2012](https://www.iso.org/standard/44381.html)
