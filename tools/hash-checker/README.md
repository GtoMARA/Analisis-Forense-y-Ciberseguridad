# hash-checker

Herramienta sencilla para calcular hashes criptograficos de archivos y, opcionalmente, compararlos con un valor esperado.

## Uso

```powershell
python hash_checker.py archivo.bin
python hash_checker.py archivo.bin --algorithm sha256
python hash_checker.py archivo.bin --algorithm sha256 --expected 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

## Algoritmos soportados

- MD5
- SHA-1
- SHA-256
- SHA-512

MD5 y SHA-1 se incluyen por compatibilidad con fuentes antiguas, no como recomendacion para garantizar integridad fuerte.

## Salida

La herramienta imprime:

- Ruta del archivo.
- Algoritmo usado.
- Hash calculado.
- Resultado de comparacion si se proporciona `--expected`.

## Nota forense

Para preservar trazabilidad, registra tambien:

- Fecha y hora.
- Herramienta y version.
- Operador.
- Ubicacion del archivo.
- Medio original y copia de trabajo.
