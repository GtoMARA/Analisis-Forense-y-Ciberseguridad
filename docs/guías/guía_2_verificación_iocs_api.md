# Guía 2: Verificación de IOCs con APIs de Inteligencia de Amenazas

> **Objetivo**: Consultar indicadores de compromiso (IOCs) en bases de datos de inteligencia de amenazas (Threat Intelligence) usando APIs públicas y privadas.

---

## 📌 Tabla de Contenidos
1. [Introducción](#introducción)
2. [Hashes de Archivos](#hashes-de-archivos)
3. [APIs de abuse.ch](#apis-de-abusech)
4. [VirusTotal API v3](#virustotal-api-v3)
5. [Extracción de IOCs con Regex](#extracción-de-iocs-con-regex)
6. [Bloqueo de Dominios con dnsmasq](#bloqueo-de-dominios-con-dnsmasq)
7. [Ejemplo de Código en Python](#ejemplo-de-código-en-python)

---

## 📖 Introducción

Las APIs de inteligencia de amenazas permiten automatizar la verificación de IOCs (hashes, IPs, dominios, URLs) para identificar si están asociados a malware, phishing u otras actividades maliciosas.

> ⚠️ **Nota importante**:
> Desde **2023-2024**, la plataforma **abuse.ch** (ThreatFox, MalwareBazaar, URLhaus) **exige autenticación** con una **Auth-Key**. Regístrate en [https://auth.abuse.ch/](https://auth.abuse.ch/) para obtener tu clave.

---

## 🔑 Hashes de Archivos

### ¿Qué es un hash?
Un **hash** es una representación única de un archivo en formato hexadecimal. Los algoritmos más usados son:
- **MD5**: 32 caracteres (ej: `44d88612fea8a8f36de82e1278abb02f`).
- **SHA-1**: 40 caracteres (ej: `da39a3ee5e6b4b0d3255bfef95601890afd80709`).
- **SHA-256**: 64 caracteres (ej: `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`).

### Ejemplo: Hash del EICAR Test File
El archivo **EICAR** es un estándar para probar antivirus. Sus hashes reales son:
```
MD5:    44d88612fea8a8f36de82e1278abb02f
SHA-1:   3395856ce81f2b7382dee72602f798b642f14140
SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

> ❌ **Error común**:
> Usar `5d41402abc4b2a76b9719d911017c592` como SHA-256 de EICAR. Este es:
> - Un hash **MD5** (32 caracteres).
> - El MD5 de la cadena `"hello"`, **no de EICAR**.

> ⚠️ **Nota sobre EICAR**:
> - **Tipo**: Archivo de **texto ASCII** (formato `.com`).
> - **Tamaño**: **68 bytes**.
> - **No es un PE32/Win32 EXE**. Ningún motor lo clasifica como PE.

---

## 🌍 APIs de abuse.ch

La plataforma **abuse.ch** ofrece varias APIs para consultar IOCs:

| API | Descripción | Endpoint | Auth-Key Requerida |
|-----|-------------|----------|---------------------|
| **ThreatFox** | Base de datos de IOCs (IPs, dominios, URLs, hashes). | `https://threatfox-api.abuse.ch/api/v1/` | ✅ Sí |
| **MalwareBazaar** | Base de datos de muestras de malware. | `https://mb-api.abuse.ch/api/v1/` | ✅ Sí |
| **URLhaus** | Base de datos de URLs maliciosas. | `https://urlhaus-api.abuse.ch/v1/` | ✅ Sí |

> ⚠️ **Cambios recientes (2023-2024)**:
> - Todas las APIs de abuse.ch **exigen Auth-Key** (header: `Auth-Key: TU_CLAVE`).
> - El header `API-KEY` **ya no funciona**.
> - Los límites de consultas dependen de tu plan. Usa **"según tu plan de abuse.ch"** en lugar de cifras fijas.

---

### 📡 ThreatFox API

#### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/search` | POST | Buscar un IOC (IP, dominio, URL, hash). |
| `/download/malware` | GET | Descargar una muestra de malware (requiere permisos). |

#### Campos de Respuesta (Reales):
```json
{
  "query_status": "ok",
  "data": [
    {
      "id": "12345",
      "threat_type": "malware",
      "ioc": "1.2.3.4",
      "confidence_level": 100,
      "malware": "Emotet",
      "tags": ["botnet", "spam"],
      "first_seen": "2023-01-01",
      "last_seen": "2024-01-01"
    }
  ]
}
```

> ❌ **Error común**:
> Usar `data.get('malicious', False)`. **No existe el campo `malicious`**. Usa:
> - `query_status == "ok"` (la consulta fue exitosa).
> - `threat_type` (tipo de amenaza: `malware`, `phishing`, etc.).
> - `confidence_level` (nivel de confianza, 0-100).

#### Ejemplo de Consulta:
```python
import requests

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY = "TU_AUTH_KEY"  # Regístrate en https://auth.abuse.ch/

def consultar_threatfox(ioc):
    headers = {"Auth-Key": AUTH_KEY}
    data = {"query": "search_ioc", "value": ioc}
    response = requests.post(API_URL, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        if result.get("query_status") == "ok" and result.get("data"):
            for item in result["data"]:
                print(f"✅ IOC: {item['ioc']} | Tipo: {item['threat_type']} | Malware: {item.get('malware', 'N/A')}")
        else:
            print(f"❌ IOC no encontrado: {ioc}")
    else:
        print(f"⚠️ Error: {response.status_code} - {response.text}")

# Ejemplo:
consultar_threatfox("1.2.3.4")
```

---

### 🦠 MalwareBazaar API

#### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/search` | POST | Buscar una muestra por hash (MD5, SHA-1, SHA-256). |
| `/download` | GET | Descargar una muestra (requiere permisos). |

#### Campos de Respuesta (Reales):
```json
{
  "query_status": "ok",
  "data": [
    {
      "id": "12345",
      "sha256_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "sha1_hash": "3395856ce81f2b7382dee72602f798b642f14140",
      "md5_hash": "44d88612fea8a8f36de82e1278abb02f",
      "file_name": "eicar.com",
      "file_type": "Win32 EXE",
      "file_size": 68,
      "signature": "EICAR-Test-File",  # Familia de malware
      "first_seen": "2020-01-01",
      "last_seen": "2024-01-01"
    }
  ]
}
```

> ❌ **Error común**:
> Usar `data.get('malware', False)` o `data.get('malware_family')`. **No existen estos campos**. Usa:
> - `signature` (familia de malware).
> - `file_type` (tipo de archivo).
> - `file_size` (tamaño en bytes).

#### Ejemplo de Consulta:
```python
def consultar_malwarebazaar(hash_value):
    headers = {"Auth-Key": AUTH_KEY}
    data = {"query": "get_info", "hash": hash_value}
    response = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        if result.get("query_status") == "ok" and result.get("data"):
            for item in result["data"]:
                print(f"✅ Hash: {hash_value} | Familia: {item.get('signature', 'N/A')} | Tipo: {item.get('file_type', 'N/A')}")
        else:
            print(f"❌ Hash no encontrado: {hash_value}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_malwarebazaar("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

---

### 🌐 URLhaus API

#### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/url` | POST | Buscar una URL. |
| `/download` | GET | Descargar una muestra asociada a una URL. |

#### Campos de Respuesta (Reales):
```json
{
  "query_status": "ok",
  "url": "http://malicious-site.com/payload.exe",
  "url_status": "online",  # online/offline
  "threat": "malware_download",
  "tags": ["malware", "Emotet"],
  "first_seen": "2023-01-01",
  "last_seen": "2024-01-01"
}
```

> ❌ **Error común**:
> Usar `resultado.get('blacklisted', False)`. **No existe el campo `blacklisted`**. Usa:
> - `url_status` (`online` o `offline`).
> - `threat` (tipo de amenaza: `malware_download`, `phishing`, etc.).

#### Ejemplo de Consulta:
```python
def consultar_urlhaus(url):
    headers = {"Auth-Key": AUTH_KEY}
    data = {"url": url}
    response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        if result.get("query_status") == "ok":
            print(f"✅ URL: {url} | Estado: {result.get('url_status', 'N/A')} | Amenaza: {result.get('threat', 'N/A')}")
        else:
            print(f"❌ URL no encontrada: {url}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_urlhaus("http://malicious-site.com/payload.exe")
```

---

### 📊 AbuseIPDB API

#### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v2/check` | GET | Verificar una IP. |

#### Campos de Respuesta (Reales):
```json
{
  "data": {
    "ipAddress": "1.2.3.4",
    "abuseConfidenceScore": 100,
    "countryCode": "RU",
    "isp": "Malicious ISP",
    "domain": "malicious-isp.com",  # Campo único (string), no lista
    "totalReports": 50,
    "lastReportedAt": "2024-01-01T00:00:00+00:00"
  }
}
```

> ❌ **Error común**:
> Mostrar "Dominios asociados: evil.com, phishing-site.xyz". **El campo `domain` es un único dominio (string)**, no una lista.

#### Ejemplo de Consulta:
```python
def consultar_abuseipdb(ip):
    headers = {"Key": AUTH_KEY, "Accept": "application/json"}
    response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        data = result.get("data", {})
        print(f"✅ IP: {ip} | Score: {data.get('abuseConfidenceScore', 0)} | Dominio: {data.get('domain', 'N/A')}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_abuseipdb("1.2.3.4")
```

---

### 👽 AlienVault OTX API

#### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/indicators/GET/{type}/{value}` | GET | Buscar un IOC (IP, dominio, hash, etc.). |

#### Campos de Respuesta (Reales):
```json
{
  "results": {
    "reputation": 0,  # Casi siempre 0 o None
    "pulse_info": {
      "pulses": [
        {
          "name": "Emotet Campaign",
          "threat_type": "malware",
          "tags": ["botnet", "Emotet"],
          "created": "2023-01-01"
        }
      ]
    }
  }
}
```

> ❌ **Error común**:
> Usar `reputation` como indicador de malicia (`1 = Malicioso`). **`reputation` casi siempre es 0 o None**. Usa:
> - `pulse_info.pulses` (lista de pulsos asociados al IOC).
> - `pulse_info.pulses[].threat_type` (tipo de amenaza).

#### Ejemplo de Consulta:
```python
def consultar_otx(ioc, ioc_type="IPv4"):
    headers = {"X-OTX-API-KEY": AUTH_KEY}
    response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/GET/{ioc_type}/{ioc}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        pulses = result.get("results", {}).get("pulse_info", {}).get("pulses", [])
        if pulses:
            for pulse in pulses:
                print(f"✅ IOC: {ioc} | Pulse: {pulse['name']} | Tipo: {pulse['threat_type']}")
        else:
            print(f"❌ IOC no encontrado: {ioc}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_otx("1.2.3.4", "IPv4")
```

---

## 🦠 VirusTotal API v3

### Autenticación:
- Regístrate en [VirusTotal](https://www.virustotal.com/) para obtener una **API Key**.
- Header: `x-apikey: TU_API_KEY`

### Endpoints:
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/files/{hash}` | GET | Consultar un archivo por hash (MD5, SHA-1, SHA-256). |
| `/urls/{id}` | GET | Consultar una URL por su **identificador** (no la URL en crudo). |
| `/ip_addresses/{ip}` | GET | Consultar una IP. |
| `/domains/{domain}` | GET | Consultar un dominio. |

---

### 📡 Consultar un Archivo por Hash

#### Ejemplo:
```python
def consultar_virustotal_hash(hash_value):
    headers = {"x-apikey": "TU_API_KEY"}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_value}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"✅ Hash: {hash_value} | Malicioso: {stats.get('malicious', 0)} | Sospechoso: {stats.get('suspicious', 0)}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_virustotal_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
```

---

### 🌐 Consultar una URL

> ❌ **Error común**:
> Usar `urls/{url}` con la URL en crudo (ej: `urls/https://malicious-site.com`). **Esto devuelve error 404**.
>
> ✅ **Solución**:
> VirusTotal exige el **identificador de la URL**, que es:
> - El **SHA-256 del texto de la URL** (preferido).
> - O la **URL codificada en base64 url-safe sin padding**.

#### Ejemplo:
```python
import hashlib
import base64

def get_url_id(url):
    # Opción 1: SHA-256 de la URL (recomendado)
    sha256 = hashlib.sha256(url.encode()).hexdigest()
    return sha256
    
    # Opción 2: Base64 url-safe sin padding
    # url_b64 = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    # return url_b64

def consultar_virustotal_url(url):
    url_id = get_url_id(url)
    headers = {"x-apikey": "TU_API_KEY"}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print(f"✅ URL: {url} | Malicioso: {stats.get('malicious', 0)}")
    else:
        print(f"⚠️ Error: {response.status_code}")

# Ejemplo:
consultar_virustotal_url("https://malicious-site.com/payload.exe")
```

---

## 🔍 Extracción de IOCs con Regex

### Problema con Regex Genéricas
Usar una regex como `(?:[a-zA-Z0-9-]+\)+[a-zA-Z]{2,}` para extraer dominios **captura falsos positivos**:
- Nombres de archivos: `factura.pdf`, `config.dat`.
- Versiones: `v1.2.3`.
- Otros patrones no relacionados.

### Regex Mejoradas

#### 1. Extraer Dominios (evitando falsos positivos):
```python
import re

# Regex para dominios (evita capturar archivos y versiones):
domain_regex = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w\.])'

# Ejemplo de uso:
text = "Visita example.com o descarga factura.pdf de malware-site.com"
dominios = re.findall(domain_regex, text)
print(dominios)  # ['example.com', 'malware-site.com']
```

#### 2. Extraer URLs:
```python
url_regex = r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
urls = re.findall(url_regex, text)
```

#### 3. Extraer IPs:
```python
ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ips = re.findall(ip_regex, text)
```

#### 4. Extraer Hashes (MD5, SHA-1, SHA-256):
```python
md5_regex = r'\b[a-fA-F0-9]{32}\b'
sha1_regex = r'\b[a-fA-F0-9]{40}\b'
sha256_regex = r'\b[a-fA-F0-9]{64}\b'
```

---

## 🚫 Bloqueo de Dominios con dnsmasq

### Sintaxis Correcta
Para bloquear un dominio en **dnsmasq**, usa la siguiente sintaxis:
```
address=/dominio.com/0.0.0.0
```

> ❌ **Error común**:
> Usar `address=/ dominio.com/0.0.0.0` (con espacio después de `/`). **Esto no funciona**.

### Ejemplo de Configuración:
```bash
# Bloquear dominios maliciosos
echo "address=/malicious-site.com/0.0.0.0" >> /etc/dnsmasq.conf
echo "address=/phishing-site.xyz/0.0.0.0" >> /etc/dnsmasq.conf

# Reiniciar dnsmasq
sudo systemctl restart dnsmasq
```

### Script en Python para Generar Regla:
```python
def bloquear_dominio(dominio):
    # Sintaxis correcta: SIN espacio después de /
    regla = f"address=/{dominio}/0.0.0.0\n"
    with open("/etc/dnsmasq.conf", "a") as f:
        f.write(regla)
    print(f"✅ Dominio bloqueado: {dominio}")

# Ejemplo:
bloquear_dominio("malicious-site.com")
```

---

## 🐍 Ejemplo de Código en Python (Completo)

```python
import requests
import hashlib
import re
from typing import Dict, List, Optional

# Configuración de APIs
API_KEYS = {
    "threatfox": "TU_AUTH_KEY_ABUSE_CH",
    "malwarebazaar": "TU_AUTH_KEY_ABUSE_CH",
    "urlhaus": "TU_AUTH_KEY_ABUSE_CH",
    "abuseipdb": "TU_API_KEY_ABUSEIPDB",
    "virustotal": "TU_API_KEY_VIRUSTOTAL",
    "otx": "TU_API_KEY_OTX"
}

# Regex para extracción de IOCs
REGEX_IOCS = {
    "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "domain": r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w\.])',
    "url": r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b'
}

def extraer_iocs(texto: str) -> Dict[str, List[str]]:
    """Extrae IOCs de un texto."""
    iocs = {}
    for tipo, regex in REGEX_IOCS.items():
        iocs[tipo] = re.findall(regex, texto)
    return iocs

def consultar_threatfox(ioc: str) -> Optional[Dict]:
    """Consulta ThreatFox API."""
    headers = {"Auth-Key": API_KEYS["threatfox"]}
    data = {"query": "search_ioc", "value": ioc}
    response = requests.post("https://threatfox-api.abuse.ch/api/v1/", headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    return None

def consultar_virustotal_url(url: str) -> Optional[Dict]:
    """Consulta VirusTotal API v3 para una URL."""
    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": API_KEYS["virustotal"]}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

# Ejemplo de uso
if __name__ == "__main__":
    texto = "Descarga el archivo de http://malicious-site.com/payload.exe (MD5: 44d88612fea8a8f36de82e1278abb02f)"
    iocs = extraer_iocs(texto)
    print("IOCs extraídos:", iocs)
    
    # Consultar URL en ThreatFox
    for url in iocs.get("url", []):
        resultado = consultar_threatfox(url)
        if resultado and resultado.get("query_status") == "ok":
            print(f"✅ URL maliciosa: {url}")
    
    # Consultar hash en VirusTotal
    for md5 in iocs.get("md5", []):
        # Usar el endpoint de files para hashes
        headers = {"x-apikey": API_KEYS["virustotal"]}
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{md5}", headers=headers)
        if response.status_code == 200:
            print(f"✅ Hash consultado: {md5}")
```

---

## 📝 Checklist de Verificación
- [ ] Usar **Auth-Key** para todas las APIs de abuse.ch (no `API-KEY`).
- [ ] Verificar los **campos reales** de cada API (ej: `signature` en MalwareBazaar, `url_status` en URLhaus).
- [ ] Codificar URLs para VirusTotal (SHA-256 o base64 url-safe).
- [ ] Usar regex **específicas** para evitar falsos positivos.
- [ ] Bloquear dominios en dnsmasq **sin espacios** (`address=/dominio/0.0.0.0`).

---

## 📚 Recursos Adicionales
- [abuse.ch - Auth-Key Registration](https://auth.abuse.ch/)
- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference)
- [AlienVault OTX API Documentation](https://otx.alienvault.com/api/)
- [AbuseIPDB API Documentation](https://www.abuseipdb.com/api)
- [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)
