# Playbook: Analisis inicial de correo sospechoso

## Objetivo

Realizar una primera revision tecnica de un correo sospechoso sin ejecutar adjuntos ni acceder directamente a enlaces potencialmente maliciosos. El resultado esperado es una decision inicial: benigno, sospechoso, malicioso probable o requiere analisis adicional.

## Alcance

Este playbook esta pensado para laboratorios, equipos defensivos y analisis autorizado. No sustituye una investigacion forense completa ni asesoramiento legal.

## Requisitos

- Copia del correo en formato `.eml` siempre que sea posible.
- Editor de texto o visor de cabeceras que no cargue contenido remoto.
- Herramienta de hashing local.
- Entorno aislado si se van a inspeccionar adjuntos.
- Acceso a fuentes de reputacion solo cuando la politica de la organizacion lo permita.

## Precauciones

- No abrir adjuntos con doble clic.
- No hacer clic en enlaces desde el cliente de correo.
- No reenviar el correo sospechoso sin preservar cabeceras.
- No subir correos reales a servicios externos si contienen datos personales, secretos o informacion de la organizacion.
- Trabajar sobre una copia y conservar el original.

## Procedimiento

### 1. Preservar el mensaje

Guardar el correo original como `.eml` o exportarlo con todas sus cabeceras.

Registrar:

- Fecha y hora de recepcion.
- Buzon o usuario afectado.
- Asunto.
- Remitente visible.
- Nombre del archivo exportado.
- Hash SHA-256 del `.eml`.

Ejemplo:

```powershell
Get-FileHash .\correo_sospechoso.eml -Algorithm SHA256
```

### 2. Revisar cabeceras principales

Comprobar:

- `From`
- `Reply-To`
- `Return-Path`
- `Received`
- `Message-ID`
- `Authentication-Results`
- `DKIM-Signature`

Puntos de interes:

- Diferencias entre `From`, `Reply-To` y `Return-Path`.
- Saltos `Received` incoherentes o servidores no esperados.
- Dominios parecidos al dominio legitimo.
- Ausencia o fallo de SPF, DKIM o DMARC.

Importante: un fallo de SPF, DKIM o DMARC no prueba por si solo que un correo sea fraudulento. Es un indicador que debe interpretarse con el resto de evidencias.

### 3. Interpretar SPF, DKIM y DMARC

SPF:

- `pass`: el servidor esta autorizado para enviar por ese dominio.
- `fail`: el servidor no esta autorizado segun la politica SPF.
- `softfail`: el servidor probablemente no esta autorizado, pero la politica es menos estricta.
- `neutral`: el dominio publica una politica explicita que no afirma si el host esta autorizado.
- `none`: no existe registro SPF aplicable.

DKIM:

- Verifica si el mensaje conserva una firma criptografica valida asociada al dominio firmante.
- Para validar un `.eml`, usar herramientas como `dkimpy`/`dkimverify`.
- No usar `opendkim-testkey` como verificador de correos recibidos: sirve para comprobar configuraciones de claves DKIM publicadas en DNS.

DMARC:

- Evalua alineacion de dominios y resultados SPF/DKIM segun la politica publicada por el dominio.
- Revisar si el resultado es `pass` o `fail`, y la politica declarada (`none`, `quarantine`, `reject`).

Referencias:

- [RFC 7208 - SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6376 - DKIM](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7489 - DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [dkimpy](https://pypi.org/project/dkimpy/)

### 4. Extraer indicadores

Extraer y documentar:

- Direcciones IP.
- Dominios.
- URLs.
- Hashes de adjuntos.
- Nombres de archivos.
- Direcciones de correo.

Evitar enviar automaticamente todos los dominios extraidos a APIs externas: una expresion regular puede capturar falsos positivos como nombres de archivo, versiones o texto inocuo.

### 5. Revisar enlaces sin visitarlos directamente

Analizar visualmente:

- Dominio real.
- Uso de acortadores.
- Punycode (`xn--`) o caracteres homografos.
- Subdominios largos o confusos.
- Parametros con tokens, correos o identificadores de usuario.

Si se consulta reputacion, hacerlo desde un entorno controlado y respetando terminos de uso y privacidad.

### 6. Revisar adjuntos

Sin ejecutar el archivo:

- Calcular hash SHA-256.
- Identificar extension y tipo real.
- Revisar si hay doble extension.
- Revisar macros, scripts, documentos comprimidos o ejecutables.
- Analizar en entorno aislado si procede.

Ejemplo:

```powershell
Get-FileHash .\adjunto.bin -Algorithm SHA256
```

### 7. Clasificar el caso

Clasificacion sugerida:

| Estado | Criterio orientativo |
| --- | --- |
| Benigno | No hay indicadores sospechosos y el contexto es coherente. |
| Sospechoso | Hay inconsistencias, pero faltan evidencias suficientes. |
| Malicioso probable | Hay suplantacion, enlace o adjunto sospechoso, o reputacion negativa contrastada. |
| Requiere analisis adicional | El caso puede afectar a mas usuarios, sistemas o datos sensibles. |

## Evidencias a conservar

- `.eml` original.
- Hash del correo.
- Capturas o exportacion de cabeceras.
- Lista de IOCs extraidos.
- Hashes de adjuntos.
- Herramientas y versiones utilizadas.
- Decision final y justificacion.

## Resultado esperado

Un informe breve con:

- Resumen del correo.
- Indicadores encontrados.
- Resultado de autenticacion SPF/DKIM/DMARC.
- Analisis de enlaces y adjuntos.
- Clasificacion.
- Acciones recomendadas.

## Acciones recomendadas

Segun el resultado:

- Marcar como phishing/spam en la plataforma de correo.
- Bloquear dominios, URLs o hashes confirmados.
- Buscar correos similares en otros buzones.
- Resetear credenciales si el usuario interactuo con el enlace.
- Escalar a respuesta a incidentes si hay ejecucion de adjunto, robo de credenciales o impacto organizativo.

## Referencias

- [RFC 5322 - Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322)
- [RFC 7208 - SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6376 - DKIM](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7489 - DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)
