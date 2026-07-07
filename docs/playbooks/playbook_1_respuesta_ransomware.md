# Playbook 1: Respuesta a Incidentes de Ransomware

> **Objetivo**: Proporcionar un procedimiento estructurado para responder a un incidente de ransomware, incluyendo contención, análisis forense y recuperación.

---

## 📌 Tabla de Contenidos
1. [Introducción](#introducción)
2. [Fases de Respuesta](#fases-de-respuesta)
3. [Identificación de Familias de Ransomware](#identificación-de-familias-de-ransomware)
4. [Contención del Incidente](#contención-del-incidente)
5. [Análisis Forense](#análisis-forense)
6. [Recuperación](#recuperación)
7. [Prevención y Lecciones Aprendidas](#prevención-y-lecciones-aprendidas)

---

## 📖 Introducción

El **ransomware** es un tipo de malware que cifra los archivos de la víctima y exige un rescate (generalmente en criptomonedas) para restaurar el acceso. Según el **SonicWall Cyber Threat Report 2023**, los ataques de ransomware han experimentado un **aumento significativo en los últimos años**, aunque las cifras varían anual y regionalmente.

> ⚠️ **Nota sobre estadísticas**:
> - Las cifras de aumento (ej: "+300%") **deben citarse con el informe específico y año**.
> - Enlace correcto: [SonicWall Cyber Threat Report 2023](https://www.sonicwall.com/resources/white-paper/cyber-threat-report-2023/)
> - Evitar usar la homepage genérica de SonicWall como fuente.

---

## 🔄 Fases de Respuesta

| Fase | Objetivo | Acciones Clave |
|------|----------|----------------|
| **Preparación** | Minimizar el impacto antes de que ocurra el incidente. | - Copias de seguridad offline.
- Plan de respuesta a incidentes (IRP).
- Capacitación de empleados. |
| **Detección e Identificación** | Confirmar que se trata de un ataque de ransomware. | - Monitoreo de alertas (SIEM, EDR).
- Análisis de archivos sospechosos.
- Identificación de la familia de ransomware. |
| **Contención** | Detener la propagación del malware. | - Aislar sistemas afectados.
- Bloquear comunicaciones con C2 (Command & Control).
- Desconectar de la red. |
| **Erradicación** | Eliminar el malware de los sistemas. | - Limpiar sistemas infectados.
- Restaurar desde copias de seguridad.
- Parchear vulnerabilidades explotadas. |
| **Recuperación** | Restaurar operaciones normales. | - Restaurar datos desde backups.
- Verificar integridad de sistemas.
- Monitoreo post-incidente. |
| **Lecciones Aprendidas** | Mejorar la postura de seguridad. | - Revisión de logs.
- Actualización de políticas.
- Capacitación adicional. |

---

## 🔍 Identificación de Familias de Ransomware

### ⚠️ Advertencia Importante
**No confíes en la extensión de los archivos cifrados como único identificador**. Las familias de ransomware modernas suelen:
- Usar **extensiones aleatorias** (ej: 5-10 caracteres generados aleatoriamente).
- No cambiar la extensión en algunos casos (ej: Ryuk).
- Usar extensiones que imitan a otras familias.

> ✅ **Método recomendado**:
> 1. **Analizar la nota de rescate** (nombre, contenido, direcciones de contacto).
> 2. **Usar herramientas como [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)** para identificar la familia.
> 3. **Revisar IOCs** (hashes, IPs, dominios) en bases de datos de inteligencia de amenazas.

---

### 📊 Tabla de Familias de Ransomware (Extensiones Comunes)

> ⚠️ **Nota**: Las extensiones pueden variar entre versiones o campañas. **Siempre verifica con ID Ransomware o análisis forense**.

| Familia | Extensiones Conocidas | Notas |
|---------|----------------------|-------|
| **LockBit** | `.lockbit` (2.0), **aleatoria** (3.0) | LockBit 3.0 usa extensiones aleatorias de 4-10 caracteres. |
| **Conti** | `.CONTI` | Extensión en mayúsculas. Algunas variantes usan extensiones aleatorias de 5 letras. |
| **REvil (Sodinokibi)** | **Aleatoria por víctima** | No usa una extensión fija como `.revil`. |
| **Maze** | **Aleatoria por víctima** | No usa `.maze`. A menudo deja una nota de rescate llamada `DECRYPT-FILES.txt`. |
| **Ryuk** | `.RYK` o **sin cambio** | A menudo no cambia la extensión de los archivos. |
| **Dharma** | `.id-[ID_VÍCTIMA].[correo@dominio].dharma` | Ejemplo: `.id-123456.[evil@mail.com].dharma`. |
| **Phobos** | `.phobos`, `.encrypted` | |
| **Clop** | `.clop` | |
| **BlackCat (ALPHV)** | `.alphv` | |
| **Play** | `.play` | |

> ❌ **Error común en tablas**:
> - **Conti**: ❌ `.cont` → ✅ `.CONTI` (mayúsculas).
> - **REvil/Sodinokibi**: ❌ `.revil` → ✅ **Extensión aleatoria por víctima**.
> - **Maze**: ❌ `.maze` → ✅ **Extensión aleatoria por víctima**.
> - **Ryuk**: ❌ `.ryuk` → ✅ `.RYK` o **sin cambio de extensión**.

---

### 🔎 Identificación con ID Ransomware
1. **Sube un archivo cifrado** o la **nota de rescate** a [ID Ransomware](https://id-ransomware.malwarehunterteam.com/).
2. **Proporciona información adicional**:
   - Extensión de los archivos cifrados.
   - Correo de contacto en la nota de rescate.
   - Hashes de los archivos maliciosos.
3. **Resultado**:
   - Familia de ransomware.
   - Información sobre descifrado (si está disponible).
   - IOCs asociados.

---

## 🚨 Contención del Incidente

### 1. Aislar Sistemas Afectados
- **Desconectar de la red**:
  - Deshabilitar conexiones Wi-Fi/Ethernet.
  - Usar `ip link set <interfaz> down` (Linux) o deshabilitar el adaptador (Windows).
- **Apagar sistemas críticos**:
  - Si el ransomware está activo, apagar los sistemas para evitar que cifren más archivos.
  - **No reiniciar**: Podría borrar evidencia en memoria.

### 2. Bloquear Comunicaciones con C2
- **Identificar IPs/Dominios de C2**:
  - Revisar conexiones activas con:
    ```bash
    # Linux:
    netstat -tulnp | grep ESTABLISHED
    ss -tulnp | grep ESTABLISHED
    
    # Windows:
    netstat -ano | findstr ESTABLISHED
    ```
  - Usar herramientas como **Wireshark** o **Zeek** para analizar tráfico de red.
- **Bloquear IPs/Dominios**:
  - En el firewall:
    ```bash
    # Ejemplo con iptables (Linux):
    iptables -A OUTPUT -d <IP_C2> -j DROP
    
    # Ejemplo con Windows Firewall:
    New-NetFirewallRule -DisplayName "Bloquear C2" -Direction Outbound -RemoteAddress <IP_C2> -Action Block
    ```
  - En DNS (dnsmasq):
    ```bash
    echo "address=/dominio-c2.com/0.0.0.0" >> /etc/dnsmasq.conf
    systemctl restart dnsmasq
    ```

### 3. Preservar Evidencias
- **Adquirir imágenes forenses**:
  - Usar herramientas como **dd** (Linux) o **FTK Imager** (Windows) para crear imágenes de discos.
  - Ejemplo con `dd`:
    ```bash
    dd if=/dev/sda of=/backup/evidencia.img bs=4M status=progress
    ```
- **Capturar memoria RAM**:
  - Linux: `avml` (Volatility) o `LiME`.
  - Windows: **Magnet RAM Capture** o **Volatility**.
- **Guardar logs**:
  - Copiar logs de sistema (`/var/log/` en Linux, Event Viewer en Windows).
  - Exportar logs de firewalls, IDS/IPS, EDR.

---

## 🔬 Análisis Forense

### 1. Análisis de la Nota de Rescate
- **Ubicación común**:
  - Archivos como `README.txt`, `DECRYPT-FILES.txt`, `RECOVER-FILES.txt`.
  - En cada carpeta afectada.
- **Contenido típico**:
  - Nombre de la familia de ransomware.
  - Instrucciones para pagar el rescate.
  - Correo de contacto (ej: `support@ransomware.com`).
  - ID de víctima (para descifrado).
- **Ejemplo de análisis**:
  ```bash
  # Buscar notas de rescate en el sistema:
  find / -type f -name "*README*" -o -name "*DECRYPT*" -o -name "*RECOVER*" 2>/dev/null
  ```

### 2. Análisis de Archivos Cifrados
- **Verificar extensiones**:
  ```bash
  # Listar archivos con extensiones sospechosas:
  find / -type f -regex '.*\.\(lockbit\|CONTI\|RYK\|alphv\)' 2>/dev/null
  ```
- **Calcular hashes**:
  ```bash
  # MD5, SHA-1, SHA-256 de un archivo:
  md5sum archivo_cifrado
  sha1sum archivo_cifrado
  sha256sum archivo_cifrado
  ```
- **Consultar hashes en bases de datos**:
  - [VirusTotal](https://www.virustotal.com/)
  - [MalwareBazaar](https://bazaar.abuse.ch/)
  - [ThreatFox](https://threatfox.abuse.ch/)

### 3. Análisis de Procesos Maliciosos
- **Herramientas recomendadas**:
  | Herramienta | Descripción | Enlace |
  |-------------|-------------|-------|
  | **Process Hacker** | Monitor de procesos avanzado para Windows. | [Process Hacker](https://processhacker.sourceforge.io/) |
  | **Sysinternals Suite** | Herramientas de Microsoft para análisis de sistemas. | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) |
  | **Volatility** | Análisis forense de memoria RAM. | [Volatility](https://www.volatilityfoundation.org/) |
  | **PowerForensics** | Módulo PowerShell para análisis forense. | [PowerForensics](https://github.com/velociraptor-oss/powerforensics) |

> ⚠️ **Nota sobre PowerForensic Analyzer**:
> - **PowerForensic Analyzer** no es una herramienta estándar del ecosistema DFIR.
> - Si se menciona en el contenido, **debe marcarse explícitamente como herramienta propia** o reemplazarse por **PowerForensics** (módulo de Jared Atkinson).

- **Ejemplo con PowerShell (PowerForensics)**:
  ```powershell
  # Instalar el módulo (requiere PowerShell 5.1+):
  Install-Module -Name PowerForensics -Force
  
  # Listar procesos en memoria:
  Get-ProcessInfo
  
  # Analizar un proceso sospechoso:
  Get-Process -Id <PID> | Select-Object *
  ```

### 4. Análisis de Logs
- **Logs de sistema**:
  - Linux: `/var/log/syslog`, `/var/log/auth.log`.
  - Windows: Event Viewer (Event ID 4688 para creación de procesos).
- **Logs de red**:
  - Firewall, IDS/IPS (Snort, Suricata).
  - Proxy (Squid, Blue Coat).
- **Herramientas para análisis**:
  - **ELK Stack** (Elasticsearch, Logstash, Kibana).
  - **Splunk**.
  - **Graylog**.

---

## 🔄 Recuperación

### 1. Restaurar desde Copias de Seguridad
- **Verificar integridad de backups**:
  - Asegurarse de que las copias de seguridad **no estén cifradas**.
  - Usar hashes para comparar archivos.
- **Restaurar sistemas**:
  - Priorizar sistemas críticos.
  - Restaurar en un entorno aislado primero para verificar que no hay malware.

### 2. Desinfección de Sistemas
- **Reinstalar sistemas afectados**:
  - La forma más segura de eliminar el ransomware es **reinstalar el sistema operativo**.
- **Usar herramientas de limpieza**:
  - **Windows Defender Offline Scan**.
  - **Kaspersky Rescue Disk**.
  - **Malwarebytes**.

### 3. Monitoreo Post-Incidente
- **Revisar logs**:
  - Buscar actividad sospechosa después de la recuperación.
- **Actualizar sistemas**:
  - Aplicar parches de seguridad.
  - Actualizar antivirus/EDR.
- **Capacitar empleados**:
  - Evitar abrir archivos adjuntos sospechosos.
  - No hacer clic en enlaces no confiables.

---

## 🛡️ Prevención y Lecciones Aprendidas

### 1. Medidas de Prevención
- **Copias de seguridad**:
  - **Regla 3-2-1**: 3 copias, en 2 medios diferentes, 1 fuera de sitio (offline).
  - Probar restauraciones periódicamente.
- **Segmentación de red**:
  - Aislar sistemas críticos en VLANs separadas.
- **Control de accesos**:
  - Principio de **mínimo privilegio**.
  - Usar **MFA** (Autenticación Multifactor).
- **Herramientas de seguridad**:
  - **EDR** (Endpoint Detection and Response).
  - **SIEM** (Security Information and Event Management).
  - **Firewall y IDS/IPS**.

### 2. Lecciones Aprendidas
- **Revisión del incidente**:
  - ¿Cómo entró el ransomware? (phishing, vulnerabilidad, RDP expuesto).
  - ¿Qué sistemas fueron afectados?
  - ¿Qué datos se perdieron?
- **Actualizar políticas**:
  - Mejorar procedimientos de respuesta a incidentes.
  - Actualizar listas de bloqueo (IPs, dominios).
- **Capacitación**:
  - Simulacros de phishing.
  - Entrenamiento en ciberseguridad para empleados.

---

## 📝 Checklist de Respuesta a Ransomware

### 🔴 Fase de Detección
- [ ] Confirmar que se trata de un ataque de ransomware (archivos cifrados, nota de rescate).
- [ ] Identificar la familia de ransomware (ID Ransomware, análisis de nota de rescate).
- [ ] Determinar el alcance del incidente (sistemas afectados, archivos cifrados).

### 🟡 Fase de Contención
- [ ] Aislar sistemas afectados (desconectar de la red).
- [ ] Bloquear comunicaciones con C2 (firewall, DNS).
- [ ] Preservar evidencias (imágenes de disco, memoria RAM, logs).

### 🟢 Fase de Erradicación
- [ ] Eliminar el malware de los sistemas (reinstalación, herramientas de limpieza).
- [ ] Parchear vulnerabilidades explotadas.
- [ ] Rotar credenciales comprometidas.

### 🔵 Fase de Recuperación
- [ ] Restaurar sistemas desde copias de seguridad.
- [ ] Verificar integridad de los datos restaurados.
- [ ] Monitorear sistemas en busca de actividad sospechosa.

### 🟣 Fase de Lecciones Aprendidas
- [ ] Revisar logs y evidencias para entender el vector de ataque.
- [ ] Actualizar políticas y procedimientos de seguridad.
- [ ] Capacitar a empleados y equipos de TI.

---

## 📚 Recursos Adicionales
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [No More Ransom](https://www.nomoreransom.org/) (Herramientas de descifrado)
- [CISA Ransomware Guide](https://www.cisa.gov/resources-tools/services/ransomware-guide)
- [NIST SP 800-61 Rev. 3 (2024)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final) (Guía para respuesta a incidentes)
- [SonicWall Cyber Threat Report 2023](https://www.sonicwall.com/resources/white-paper/cyber-threat-report-2023/)

---

## ⚠️ Advertencias Importantes
- **NUNCA ejecutes** malware en un entorno de producción. Usa **sandboxes** (Cuckoo Sandbox, Any.run).
- **No pagues el rescate**: No hay garantía de que los atacantes proporcionarán la clave de descifrado. Además, financias actividades criminales.
- **Consulta con expertos**: Si el incidente es grave, considera contratar un equipo de respuesta a incidentes (IR) profesional.
