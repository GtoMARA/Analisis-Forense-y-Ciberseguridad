# Guía 1: Análisis Forense de Correos Electrónicos

> **Objetivo**: Analizar correos electrónicos sospechosos para identificar indicadores de compromiso (IOCs), verificar autenticidad (DKIM, SPF, DMARC) y extraer evidencias forenses.

---

## 📌 Tabla de Contenidos
1. [Introducción](#introducción)
2. [Herramientas para el Análisis de Headers](#herramientas-para-el-análisis-de-headers)
3. [Verificación de DKIM](#verificación-de-dkim)
4. [Análisis de SPF](#análisis-de-spf)
5. [Análisis de DMARC](#análisis-de-dmarc)
6. [Extracción de IOCs](#extracción-de-iocs)
7. [Estadísticas y Referencias](#estadísticas-y-referencias)

---

## 📖 Introducción
El correo electrónico sigue siendo uno de los vectores principales de ataques cibernéticos. Según el **Verizon Data Breach Investigations Report (DBIR) 2023**, más del **90% de los incidentes de ciberseguridad comienzan con un correo electrónico malicioso** (phishing, malware adjunto, etc.).

> ⚠️ **Nota**: Las estadísticas deben citarse con fuentes concretas y año. Evitar atribuir cifras genéricas a fabricantes sin respaldo.

---

## 🔍 Herramientas para el Análisis de Headers

### ✅ Herramientas Recomendadas
| Herramienta | Descripción | Enlace |
|-------------|-------------|-------|
| **Message Header Analyzer (MHA)** | Analizador de headers de Microsoft. Visualiza la ruta del correo en un gráfico y resalta anomalías. | [MHA - Microsoft](https://mha.azurewebsites.net/) |
| **Google Admin Toolbox Messageheader** | Analizador de headers de Google. Permite pegar el header completo y obtener un desglose detallado. | [Google Admin Toolbox](https://toolbox.googleapps.com/apps/messageheader/) |
| **mailheader** | Herramienta de línea de comandos para analizar headers de correos. | [GitHub - mailheader](https://github.com/SpamScope/mailheader) |

> ❌ **Herramientas incorrectas (evitar)**:
> - **Mailnag**: No es un analizador de headers. Es un notificador de correo nuevo para escritorio Linux (IMAP/POP).
> - **opendkim-testkey**: No sirve para verificar la firma DKIM de un correo recibido. Solo comprueba si tu propia clave DKIM está publicada en DNS (uso para administradores de servidores emisores).

---

## 🔐 Verificación de DKIM

### ¿Qué es DKIM?
**DomainKeys Identified Mail (DKIM)** es un método de autenticación de correo que permite al destinatario verificar que un mensaje fue enviado por el dominio legítimo y no ha sido alterado en tránsito.

### ¿Cómo verificar DKIM de un correo recibido?
Para verificar la firma DKIM de un correo recibido (`.eml`), usa las siguientes herramientas:

1. **dkimpy (dkimverify)**:
   ```bash
   dkimverify < correo.eml
   ```
   - Instalación: `pip install dkimpy`
   - Documentación: [dkimpy - PyPI](https://pypi.org/project/dkimpy/)

2. **python-dkim** (librería para scripts personalizados):
   ```python
   import dkim
   with open("correo.eml", "rb") as f:
       message = f.read()
   try:
       result = dkim.verify(message)
       print(f"DKIM válido: {result}")
   except dkim.DKIMException as e:
       print(f"Error: {e}")
   ```

3. **Servicios en línea**:
   - [Message Header Analyzer (MHA)](https://mha.azurewebsites.net/)
   - [MXToolbox DKIM Checker](https://mxtoolbox.com/dkim.aspx)

> ❌ **Error común**:
> Usar `opendkim-testkey -d dominio -s selector` para verificar un correo recibido. Esta herramienta **solo comprueba si la clave DKIM está publicada en DNS**, no valida la firma del correo.

---

## 🛡️ Análisis de SPF

### ¿Qué es SPF?
**Sender Policy Framework (SPF)** es un registro DNS que especifica qué servidores de correo están autorizados a enviar correos en nombre de un dominio.

### Resultados de SPF y su significado
| Resultado | Descripción | ¿El correo es legítimo? |
|-----------|-------------|--------------------------|
| `pass`    | El servidor emisor está en la lista de servidores autorizados. | ✅ Sí |
| `fail`    | El servidor emisor **no** está autorizado. | ❌ No (pero no implica fraude, ver nota) |
| `softfail`| El servidor emisor **probablemente** no está autorizado. | ⚠️ Sospechoso |
| `neutral` | El dominio **no especifica** si el servidor está autorizado (política `?all`). | ⚠️ No hay conclusión |
| `none`    | **No hay registro SPF** para el dominio. | ⚠️ No hay protección SPF |
| `permerror`| Error permanente en el registro SPF (sintaxis inválida). | ❌ No se puede evaluar |
| `temperror`| Error temporal (ej: timeout al consultar DNS). | ⚠️ Reintentar |

> ⚠️ **Notas importantes**:
> - **`none` vs `neutral`**: Si no hay registro SPF, el resultado es **`none`**, no `neutral`. `neutral` es un resultado explícito cuando el registro SPF usa `?all`.
> - **`fail` (hardfail)**: Indica que el servidor no está autorizado, pero **no prueba fraude por sí solo**. Los reenvíos de correo (forwarding) y las listas de distribución pueden romper SPF legítimamente.
> - **Ejemplo de registro SPF**: `v=spf1 include:_spf.google.com ~all` (Softfail para servidores no autorizados).

---

## 📜 Análisis de DMARC

### ¿Qué es DMARC?
**Domain-based Message Authentication, Reporting & Conformance (DMARC)** es un estándar que usa SPF y DKIM para:
1. Indicar al destinatario qué hacer con correos que fallan la autenticación (`none`, `quarantine`, `reject`).
2. Recibir informes sobre el uso de tu dominio en correos.

### Ejemplo de registro DMARC:
```
v=DMARC1; p=none; rua=mailto:dmarc-reports@ejemplo.com; ruf=mailto:dmarc-failures@ejemplo.com; pct=100
```
- `p=none`: No aplicar ninguna acción (solo generar informes).
- `p=quarantine`: Poner en cuarentena correos que fallen SPF/DKIM.
- `p=reject`: Rechazar correos que fallen SPF/DKIM.

---

## 🎯 Extracción de IOCs

### IOCs comunes en correos:
1. **Direcciones IP**:
   - Usa **CyberChef** (operación: **"Extract IP addresses"**).
   - Herramienta de línea de comandos: `grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' correo.txt`

2. **Dominios y URLs**:
   - Usa regex **mejorada** para evitar falsos positivos:
     ```python
     import re
     # Regex para dominios (evita capturar archivos como 