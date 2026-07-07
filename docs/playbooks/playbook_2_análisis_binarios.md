# Playbook 2: Análisis Forense de Binarios Maliciosos

> **Objetivo**: Proporcionar un procedimiento para analizar archivos binarios sospechosos (ejecutables, DLLs, scripts) en un entorno seguro, extrayendo indicadores de compromiso (IOCs) y determinando su comportamiento.

---

## 📌 Tabla de Contenidos
1. [Introducción](#introducción)
2. [Preparación del Entorno](#preparación-del-entorno)
3. [Análisis Estático](#análisis-estático)
4. [Análisis Dinámico](#análisis-dinámico)
5. [Extracción de IOCs](#extracción-de-iocs)
6. [Herramientas Avanzadas](#herramientas-avanzadas)
7. [Ejemplos Prácticos](#ejemplos-prácticos)

---

## 📖 Introducción

El análisis de binarios maliciosos es una parte crítica del **análisis forense digital** y la **respuesta a incidentes**. Permite:
- Identificar el tipo de malware (ransomware, spyware, troyano, etc.).
- Extraer IOCs (IPs, dominios, hashes, etc.).
- Entender el comportamiento del malware (persistencia, exfiltración de datos, etc.).

> ⚠️ **Advertencia**:
> **NUNCA ejecutes** malware en un entorno de producción o sin las precauciones adecuadas. Usa **máquinas virtuales aisladas** o **sandboxes** dedicadas.

---

## 🛡️ Preparación del Entorno

### 1. Entorno de Análisis
| Componente | Recomendación | Notas |
|------------|---------------|-------|
| **Sistema Operativo** | Windows 10/11 o Linux (Kali, REMnux) | Usar versiones limpias y actualizadas. |
| **Máquina Virtual** | VMware Workstation, VirtualBox | Aislar el entorno de la red principal. |
| **Snapshot** | Crear snapshot antes del análisis | Permite restaurar el estado inicial rápidamente. |
| **Red** | Desconectada o en red aislada | Evitar que el malware se comunique con C2. |
| **Herramientas** | Instalar herramientas de análisis (ver secciones siguientes). | |

### 2. Herramientas Básicas
- **Análisis estático**:
  - [PEiD](https://www.aldeid.com/wiki/PeID) (Windows).
  - [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy).
  - [pefile](https://github.com/erocarrera/pefile) (Python).
  - [strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings) (Sysinternals).
- **Análisis dinámico**:
  - [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (Sysinternals).
  - [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) (Sysinternals).
  - [Wireshark](https://www.wireshark.org/) (análisis de red).
  - [Regshot](https://sourceforge.net/projects/regshot/) (captura de cambios en el registro).
- **Sandboxes**:
  - [Cuckoo Sandbox](https://cuckoosandbox.org/).
  - [Any.run](https://any.run/).
  - [Hybrid Analysis](https://www.hybrid-analysis.com/).

---

## 🔍 Análisis Estático

El **análisis estático** examina el archivo **sin ejecutarlo**, extrayendo información como:
- Metadatos (nombre, versión, fecha de compilación).
- Secciones y símbolos.
- Cadenas de texto (IPs, dominios, rutas).
- Hashes (MD5, SHA-1, SHA-256).

---

### 1. Uso de `pefile` (Python)

**`pefile`** es una librería de Python para parsear archivos PE (Portable Executable) en Windows.

> ❌ **Error común**:
> Usar atributos inexistentes como:
> - `pe.FileInfo[0].FileName.decode()`
> - `pe.FileInfo[0].FileDescription`
> - `pe.FileInfo[0].FileVersion`
> - `pe.FileInfo[0].CreationDate`
>
> ✅ **Solución**:
> Los metadatos de versión en archivos PE están anidados en:
> `pe.FileInfo → StringFileInfo → StringTable → entries`.
> La fecha de compilación está en `pe.FILE_HEADER.TimeDateStamp`.

#### Ejemplo Corregido:
```python
import pefile

# Cargar el archivo PE
pe = pefile.PE("malware.exe")

# 1. Información básica
print(f"Tipo de archivo: {pe.FILE_HEADER.Machine}")  # Ej: 0x014c (x86), 0x8664 (x64)
print(f"Número de secciones: {pe.FILE_HEADER.NumberOfSections}")
print(f"Fecha de compilación (timestamp): {pe.FILE_HEADER.TimeDateStamp}")

# 2. Metadatos de versión (StringFileInfo)
if hasattr(pe, "FileInfo"):
    for fileinfo in pe.FileInfo:
        if hasattr(fileinfo, "StringTable"):
            for stringtable in fileinfo.StringTable:
                for entry in stringtable.entries:
                    print(f"{entry.key.decode()}: {entry.value.decode()}")
else:
    print("No hay metadatos de versión.")

# 3. Secciones del PE
for section in pe.sections:
    # Decodificar el nombre de la sección (eliminar bytes nulos de padding)
    section_name = section.Name.decode().rstrip('\x00')
    print(f"Sección: {section_name} | Tamaño: {section.SizeOfRawData} bytes | Offset: {section.PointerToRawData}")

# 4. Entrypoint (punto de entrada)
print(f"Entrypoint RVA: {pe.OPTIONAL_HEADER.AddressOfEntryPoint}")

# 5. Cerrar el archivo
pe.close()
```

#### Explicación de los campos:
| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| `pe.FILE_HEADER.Machine` | Arquitectura del binario. | `0x014c` (x86), `0x8664` (x64) |
| `pe.FILE_HEADER.TimeDateStamp` | Fecha de compilación (timestamp Unix). | `1609459200` (2021-01-01) |
| `pe.OPTIONAL_HEADER.AddressOfEntryPoint` | Dirección relativa del punto de entrada. | `0x1000` |
| `section.Name` | Nombre de la sección (`.text`, `.data`, etc.). | `.text` |
| `section.SizeOfRawData` | Tamaño de la sección en el disco. | `4096` |

---

### 2. Extracción de Cadenas con `strings`

La herramienta **`strings`** (de Sysinternals) extrae cadenas de texto legibles de un binario.

#### Ejemplo:
```bash
# Linux:
strings malware.exe | less

# Windows (Sysinternals):
strings.exe malware.exe > strings_output.txt
```

#### Filtrado de IOCs:
```bash
# Extraer IPs:
strings malware.exe | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'

# Extraer dominios:
strings malware.exe | grep -Eo '(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

# Extraer URLs:
strings malware.exe | grep -Eo 'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
```

---

### 3. Uso de Detect It Easy (DIE)

**DIE** es una herramienta gráfica para analizar archivos binarios. Proporciona:
- Tipo de archivo (PE, ELF, script, etc.).
- Hashes (MD5, SHA-1, SHA-256).
- Secciones y metadatos.
- Detección de packers (UPX, NSIS, etc.).

#### Descarga:
- [GitHub - Detect It Easy](https://github.com/horsicq/Detect-It-Easy)

---

## 🚀 Análisis Dinámico

El **análisis dinámico** ejecuta el malware en un **entorno controlado** para observar su comportamiento.

---

### 1. Configuración del Entorno
- **Máquina virtual**:
  - Usar **VMware** o **VirtualBox** con snapshot.
  - Deshabilitar **red** o usar una red aislada.
- **Herramientas de monitoreo**:
  - **Process Monitor** (Sysinternals): Registra actividad de archivos, registro y procesos.
  - **Process Explorer** (Sysinternals): Monitor de procesos avanzado.
  - **Wireshark**: Captura de tráfico de red.
  - **Regshot**: Captura cambios en el registro de Windows.

---

### 2. Uso de Regshot

**Regshot** es una herramienta para capturar y comparar el estado del registro de Windows.

> ⚠️ **Nota sobre Regshot**:
> - Regshot es **principalmente una herramienta GUI**, pero tiene una **versión CLI** con sintaxis específica.
> - La sintaxis `regshot -s antes.reg / regshot -c` **no es estándar** y puede no funcionar.
>
> ✅ **Sintaxis correcta (CLI)**:
> ```bash
> # Capturar estado inicial:
> regshot -s antes.reg
> 
> # Ejecutar el malware (en el entorno aislado):
> malware.exe
> 
> # Capturar estado final:
> regshot -s despues.reg
> 
> # Comparar cambios:
> regshot -c antes.reg despues.reg > cambios.txt
> ```

#### Descarga:
- [Regshot - SourceForge](https://sourceforge.net/projects/regshot/)

---

### 3. Uso de Process Monitor

**Process Monitor** (ProcMon) registra:
- Actividad de archivos (lectura/escritura).
- Cambios en el registro.
- Creación de procesos e hilos.
- Actividad de red.

#### Pasos:
1. **Descargar ProcMon**: [Sysinternals - Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).
2. **Configurar filtros**:
   - Filtrar por el nombre del malware (`malware.exe`).
   - Excluir procesos del sistema (ej: `svchost.exe`).
3. **Iniciar captura**:
   - Ejecutar ProcMon **antes** de ejecutar el malware.
4. **Ejecutar el malware**:
   - Observar la actividad en tiempo real.
5. **Guardar logs**:
   - Exportar a `.PML` (formato nativo) o `.CSV`.

#### Ejemplo de filtro:
- **Include**: `Process Name` `is` `malware.exe` `then` `Include`.
- **Exclude**: `Process Name` `is` `svchost.exe` `then` `Exclude`.

---

### 4. Análisis de Tráfico de Red con Wireshark

**Wireshark** captura y analiza el tráfico de red generado por el malware.

#### Pasos:
1. **Iniciar captura**:
   - Seleccionar la interfaz de red correcta.
   - Iniciar captura **antes** de ejecutar el malware.
2. **Ejecutar el malware**:
   - Observar conexiones sospechosas (IPs, dominios, puertos).
3. **Filtrar tráfico**:
   - Filtrar por IP: `ip.addr == 1.2.3.4`.
   - Filtrar por dominio: `dns.qry.name contains "malicious-site.com"`.
   - Filtrar por puerto: `tcp.port == 443`.
4. **Exportar IOCs**:
   - Extraer IPs, dominios y URLs del tráfico capturado.

---

## 🎯 Extracción de IOCs

### 1. IOCs Comunes en Binarios
| Tipo de IOC | Descripción | Ejemplo |
|------------|-------------|---------|
| **Hashes** | MD5, SHA-1, SHA-256 del archivo. | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (EICAR SHA-256) |
| **IPs** | Direcciones IP de servidores C2. | `1.2.3.4` |
| **Dominios** | Dominios usados para C2. | `malicious-site.com` |
| **URLs** | URLs de descarga o exfiltración. | `http://malicious-site.com/payload.exe` |
| **Mutex** | Mutex usados para evitar múltiples infecciones. | `Global\{12345678-1234-1234-1234-123456789ABC}` |
| **Rutas** | Rutas de archivos o directorios. | `C:\Windows\Temp\malware.exe` |

---

### 2. Extracción Automática con Python

```python
import re
import hashlib
from typing import Dict, List

def calcular_hashes(archivo: str) -> Dict[str, str]:
    """Calcula MD5, SHA-1 y SHA-256 de un archivo."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(archivo, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def extraer_iocs_de_cadenas(archivo: str) -> Dict[str, List[str]]:
    """Extrae IOCs de las cadenas de un binario."""
    # Ejecutar strings y capturar salida
    import subprocess
    result = subprocess.run(["strings", archivo], capture_output=True, text=True)
    cadenas = result.stdout
    
    # Regex para IOCs
    iocs = {
        "ips": re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', cadenas),
        "dominios": re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w\.])', cadenas),
        "urls": re.findall(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?', cadenas),
        "mutex": re.findall(r'Global\\\{[a-fA-F0-9\-]+\}', cadenas),
        "rutas": re.findall(r'[A-Za-z]:\\[^\s]+', cadenas)
    }
    
    # Eliminar duplicados
    for clave in iocs:
        iocs[clave] = list(set(iocs[clave]))
    
    return iocs

# Ejemplo de uso
if __name__ == "__main__":
    archivo = "malware.exe"
    
    # Calcular hashes
    hashes = calcular_hashes(archivo)
    print("Hashes:", hashes)
    
    # Extraer IOCs
    iocs = extraer_iocs_de_cadenas(archivo)
    print("IOCs extraídos:", iocs)
```

> ⚠️ **Nota sobre regex de dominios**:
> La regex `(?:[a-zA-Z0-9-]+\)+[a-zA-Z]{2,}` **captura falsos positivos** (ej: `factura.pdf`, `v1.2.3`).
> Usa la regex mejorada: `(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w\.])`.

---

## 🛠️ Herramientas Avanzadas

### 1. Cuckoo Sandbox

**Cuckoo Sandbox** es un sistema de análisis automático de malware que:
- Ejecuta el malware en un entorno controlado.
- Registra el comportamiento (archivos, registro, red).
- Genera informes detallados con IOCs.

#### Instalación:
```bash
# En Kali Linux:
sudo apt update
sudo apt install cuckoo
```

#### Uso:
```bash
# Iniciar Cuckoo:
cuckoo

# Enviar un archivo para análisis:
cuckoo submit malware.exe
```

#### Informes:
- Los informes se guardan en `/var/lib/cuckoo/analyses/`.
- Incluyen:
  - Comportamiento del malware.
  - IOCs (IPs, dominios, hashes).
  - Capturas de pantalla (si el malware muestra ventanas).

---

### 2. PEStudio

**PEStudio** es una herramienta gráfica para analizar archivos PE. Proporciona:
- Información de headers.
- Secciones y metadatos.
- Detección de packers y ofuscación.
- Extracción de cadenas.

#### Descarga:
- [PEStudio - GitHub](https://github.com/williballenthin/PEStudio)

---

### 3. Ghidra

**Ghidra** es una herramienta de **ingeniería inversa** desarrollada por la NSA. Permite:
- Desensamblar binarios.
- Analizar funciones y llamadas al sistema.
- Modificar binarios (patching).

#### Instalación:
```bash
# En Kali Linux:
sudo apt install ghidra
```

#### Uso:
1. Abrir Ghidra.
2. Crear un nuevo proyecto.
3. Importar el binario.
4. Analizar automáticamente (`Auto Analyze`).
5. Explorar el código desensamblado.

---

## 📝 Ejemplos Prácticos

### Ejemplo 1: Análisis de EICAR

**EICAR** es un archivo de prueba estándar para antivirus. No es malicioso, pero es detectado por todos los motores.

#### Pasos:
1. **Descargar EICAR**:
   ```bash
   wget https://secure.eicar.org/eicar.com.txt
   ```
2. **Calcular hashes**:
   ```bash
   md5sum eicar.com.txt    # 44d88612fea8a8f36de82e1278abb02f
   sha256sum eicar.com.txt # 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
   ```
3. **Verificar tipo de archivo**:
   ```bash
   file eicar.com.txt
   ```
   **Salida esperada**:
   ```
   eicar.com.txt: ASCII text
   ```
   > ⚠️ **Nota**: EICAR **no es un PE32/Win32 EXE**. Es un archivo de **texto ASCII** de **68 bytes**.

4. **Analizar con `pefile`**:
   ```python
   import pefile
   try:
       pe = pefile.PE("eicar.com.txt")
       print("Es un archivo PE.")
   except pefile.PEFormatError:
       print("No es un archivo PE.")  # Esto es lo esperado para EICAR
   ```

---

### Ejemplo 2: Análisis de un Binario Malicioso

#### Pasos:
1. **Preparar el entorno**:
   - Crear una máquina virtual con Windows 10.
   - Instalar Process Monitor, Wireshark y Regshot.
2. **Análisis estático**:
   - Usar `pefile` para extraer metadatos.
   - Usar `strings` para extraer cadenas.
3. **Análisis dinámico**:
   - Ejecutar el malware en la VM.
   - Capturar tráfico con Wireshark.
   - Registrar actividad con Process Monitor.
   - Capturar cambios en el registro con Regshot.
4. **Extraer IOCs**:
   - IPs, dominios, hashes, mutex, rutas.
5. **Consultar IOCs**:
   - VirusTotal, ThreatFox, MalwareBazaar.

---

## 📋 Checklist de Análisis de Binarios

### 🔴 Análisis Estático
- [ ] Calcular hashes (MD5, SHA-1, SHA-256).
- [ ] Verificar tipo de archivo (`file` en Linux, PEiD en Windows).
- [ ] Extraer metadatos con `pefile` o DIE.
- [ ] Extraer cadenas con `strings`.
- [ ] Buscar IOCs en las cadenas (IPs, dominios, URLs).
- [ ] Verificar si el archivo está empaquetado (UPX, NSIS).

### 🟡 Análisis Dinámico
- [ ] Configurar entorno aislado (VM sin red o red controlada).
- [ ] Capturar estado inicial del sistema (Regshot, snapshot).
- [ ] Iniciar monitoreo (Process Monitor, Wireshark).
- [ ] Ejecutar el malware.
- [ ] Observar comportamiento (procesos, archivos, red).
- [ ] Capturar estado final y comparar cambios.

### 🟢 Post-Análisis
- [ ] Documentar IOCs extraídos.
- [ ] Consultar IOCs en bases de datos de inteligencia de amenazas.
- [ ] Generar informe con hallazgos.
- [ ] Limpiar el entorno (revertir snapshot, eliminar malware).

---

## 📚 Recursos Adicionales
- [PEfile Documentation](https://github.com/erocarrera/pefile)
- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [Ghidra](https://ghidra-sre.org/)
- [MalwareTech - Practical Malware Analysis](https://www.malwaretech.com/practical-malware-analysis)
- [NIST SP 800-61 Rev. 3 (2024)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final)

---

## ⚠️ Advertencias Finales
- **NUNCA ejecutes** malware en un entorno de producción.
- Usa **sandboxes** (Cuckoo, Any.run) para análisis seguro.
- **Documenta todo**: IOCs, comportamiento, cambios en el sistema.
- **No confíes en una sola herramienta**: Usa múltiples métodos para validar resultados.
- **Mantén el entorno actualizado**: Parches de seguridad, antivirus, herramientas.
