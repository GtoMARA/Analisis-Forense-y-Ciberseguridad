# ioc-extractor

Herramienta sencilla para extraer posibles IOCs desde texto, logs o correos exportados.

Extrae:

- Direcciones IPv4.
- URLs.
- Dominios.
- Hashes MD5, SHA-1 y SHA-256.
- Correos electrónicos.

## Uso

Windows:

```powershell
python .\ioc_extractor.py .\entrada.txt
python .\ioc_extractor.py .\entrada.txt --json
```

Linux/macOS:

```bash
python3 ./ioc_extractor.py ./entrada.txt
python3 ./ioc_extractor.py ./entrada.txt --json
```

## Ejemplo

```text
Visita https://example.com/login y revisa el hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.
```

Salida:

```text
[urls]
- https://example.com/login

[domains]
- example.com

[sha256]
- 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

## Advertencias

- La extracción por expresiones regulares puede generar falsos positivos.
- No todos los dominios extraídos son maliciosos.
- No envíes automáticamente IOCs a servicios externos si el texto contiene datos personales o información sensible.
- Conviene revisar manualmente los resultados antes de usarlos en reglas, bloqueos o informes.

## Sin dependencias externas

El script usa únicamente la biblioteca estándar de Python.
