# Pruebas funcionales — EduSec Toolkit (Entrega Final)

Documento reproducible: cada bloque contiene el **comando exacto** seguido del
**output real** capturado durante la ejecución en la VM de pruebas (Kali Linux
x86-64, g++ 13). Las capturas correspondientes están en `/evidence/`.

## Referencia rápida de flags por subcomando

Cada subcomando tiene su **propio set de flags** — son módulos independientes,
no comparten convención.

| Subcomando | Flags válidos                                                              |
|------------|----------------------------------------------------------------------------|
| `hash`     | `[--format fnv\|sha256]` + `--string <txt>` **o** `--file <ruta>`          |
| `brute`    | `--format fnv\|sha256` + `--hash <hex>` + `--wordlist <ruta>` + `[--limit N]` |
| `scan`     | `--host <ip\|hostname>` + `[--ports <p1,p2,..>]` (default: top 20)         |
| `procs`    | _(sin flags)_                                                              |
| `sniff`    | `[--count <N>]` (default 20) · requiere `sudo`                             |
| `mem`      | `--pid <PID>`                                                              |

**Errores típicos a evitar:**

- `--file` solo existe en `hash`. En `brute` el flag se llama `--wordlist`.
- `--format` necesita **siempre** un valor inmediatamente después
  (`--format fnv` o `--format sha256`); nunca va solo.
- El hex de `--hash` debe coincidir con el formato (`--format fnv` → 8 chars
  hex; `--format sha256` → 64 chars hex). Si no coincide, nunca habrá match.

## 0. Compilación

```bash
make clean && make
```

Salida (resumen):

```
==> Binario con simbolos: bin/main-debug
==> Binario stripped:     bin/main
==> Copia para ejecucion: ./main
==> Listo:
    bin/main-debug   (con simbolos, para analisis)
    bin/main         (stripped, en bin/)
    ./main            (copia stripped en raiz, atajo)
```

| Binario           | Tamaño  | Símbolos  |
|-------------------|--------:|-----------|
| `bin/main`        | ~67 KB  | stripped  |
| `bin/main-debug`  | ~576 KB | sí (`-g`) |

## 1. Banner / ayuda

```bash
./main --version
./main --help
```

Salida:

```
1.0.0-final
===============================================
  EduSec Toolkit v1.0.0-final
  PIA PAC Ene-Jun 2026 - GRUPO 01
  Uso educativo exclusivo en VMs aisladas
===============================================
Uso: ./main <subcomando> [opciones]

Subcomandos:
  hash    Hashing FNV-1a/32 o SHA-256 de cadena o archivo
          [--format fnv|sha256]  --string <txt> | --file <ruta>
  procs   Enumera procesos via /proc (Linux)
  scan    TCP connect-scan a host
          --host <ip|host>  [--ports <p1,p2,..>]
          (sin --ports prueba el top 20 de servicios comunes)
  brute   Ataque por diccionario contra hash FNV/SHA-256
          --format fnv|sha256 --hash <hex> --wordlist <ruta> [--limit N]
  sniff   Captura pasiva de paquetes (Linux AF_PACKET, root)
          [--count <N>]      Detiene tras N paquetes (default 20)
          Al final lista las IPs unicas observadas
  mem     Inspecciona /proc/<pid>/maps de un proceso
          --pid <PID>
```

## 2. Módulo `hash`

### 2.1. SHA-256 sobre vector oficial NIST (FIPS 180-4 §B.1)

```bash
./main hash --format sha256 --string "abc"
```

Salida:

```
SHA-256(string)  = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

**Validación:** digest de referencia oficial para `"abc"`. Implementación verificada.

### 2.2. SHA-256 de un archivo

```bash
./main hash --format sha256 --file makefile
```

Salida (ejemplo):

```
SHA-256(file)    = 970806755faea7642437a37b1aeacd7e4880eea142026ff8feb7363ab52736f2  (2798 bytes: makefile)
```

### 2.3. FNV-1a/32 de una cadena

```bash
./main hash --format fnv --string "password"
```

Salida:

```
FNV1a-32(string) = 0x364b5f18
```

## 3. Módulo `procs`

```bash
./main procs | head -8
```

Salida (recortada):

```
PID     COMM
----------------------------------------
1       systemd
2       kthreadd
...
1234    main
```

## 4. Módulo `scan`

### 4.1. Scan con puertos por DEFAULT (top 20 servicios comunes)

Si no especificas `--ports`, el scanner prueba automáticamente el top 20 de
servicios más comunes (equivalente a `nmap --top-ports 20`).

```bash
./main scan --host 127.0.0.1
```

Salida (VM limpia, todos cerrados):

```
[scan] objetivo: 127.0.0.1 (127.0.0.1)
[scan] sin --ports especificado, usando top 20 servicios comunes
----------------------------
 PUERTO   ESTADO
----------------------------
  21     CERRADO
  22     CERRADO
  23     CERRADO
  25     CERRADO
  53     CERRADO
  80     CERRADO
  110    CERRADO
  111    CERRADO
  135    CERRADO
  139    CERRADO
  143    CERRADO
  443    CERRADO
  445    CERRADO
  993    CERRADO
  995    CERRADO
  1723   CERRADO
  3306   CERRADO
  3389   CERRADO
  5900   CERRADO
  8080   CERRADO
----------------------------
Resumen: 0 abierto(s) / 20 probado(s)
```

### 4.2. Scan con puertos específicos

```bash
./main scan --host 127.0.0.1 --ports 22,80,443,9999
```

Salida:

```
[scan] objetivo: 127.0.0.1 (127.0.0.1)
----------------------------
 PUERTO   ESTADO
----------------------------
  22     CERRADO
  80     CERRADO
  443    CERRADO
  9999   CERRADO
----------------------------
Resumen: 0 abierto(s) / 4 probado(s)
```

### 4.3. Caso positivo (puerto abierto)

Levanta un servidor en otra terminal:

```bash
# Terminal 2
python3 -m http.server 8080
```

```bash
# Terminal 1
./main scan --host 127.0.0.1 --ports 22,8080
```

Esperado: `8080 ABIERTO`, `22 CERRADO`.

Captura: `evidence/scan_open.png`.

## 5. Módulo `brute`

### 5.1. Diccionario contra SHA-256("password")

```bash
printf 'admin\npassword\nqwerty\n' > /tmp/wl.txt
./main brute --format sha256 \
    --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --wordlist /tmp/wl.txt
```

Salida:

```
[brute] format=sha256  hash=5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  wordlist=/tmp/wl.txt
--------------------------------
[+] MATCH encontrado en 2 intentos (0 ms)
    password = "password"
```

### 5.2. Diccionario contra FNV-1a/32

```bash
./main brute --format fnv --hash 0x364b5f18 --wordlist /tmp/wl.txt
```

Salida:

```
[brute] format=fnv  hash=364b5f18  wordlist=/tmp/wl.txt
--------------------------------
[+] MATCH encontrado en 2 intentos (0 ms)
    password = "password"
```

### 5.3. Benchmark con rockyou.txt

```bash
./main brute --format sha256 \
    --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --wordlist /usr/share/wordlists/rockyou.txt --limit 100000
```

`--limit` acota el diccionario para benchmarks deterministas.

## 6. Módulo `sniff` (requiere root)

Con el default de **20 paquetes** y resumen de IPs únicas al final:

```bash
# Terminal 1 — captura
sudo ./main sniff

# Terminal 2 — genera tráfico
ping -c 4 8.8.8.8
curl -s http://example.com -o /dev/null
```

Salida representativa:

```
[sniffer] Capturando 20 paquetes (Ctrl-C aborta)
------------------------------------------------------
#1  192.168.56.10 -> 8.8.8.8         ICMP  bytes=98
#2  8.8.8.8       -> 192.168.56.10    ICMP  bytes=98
#3  192.168.56.10 -> 93.184.215.14   TCP   sport=51234 dport=80 flags=S  bytes=74
#4  93.184.215.14 -> 192.168.56.10    TCP   sport=80 dport=51234 flags=SA bytes=74
...
------------------------------------------------------
[sniffer] 20 paquetes procesados (18 IPv4)
[sniffer] IPs unicas observadas (4):
  - 192.168.56.10
  - 8.8.8.8
  - 93.184.215.14
  - 192.168.56.1
```

Para reducir a menos paquetes, `sudo ./main sniff --count 10`.

Captura: `evidence/sniff_traffic.png` (toolkit) y `evidence/wireshark_traffic.png`
(captura cruzada con Wireshark para validar parser).

## 7. Módulo `mem`

```bash
./main mem --pid 1 | head -10
```

Salida (las direcciones cambian por ASLR):

```
[mem] inspección de PID 1
  Name:	systemd
  Uid:	0	0	0	0
  VmPeak:	  21800 kB
  VmRSS:	   8420 kB
------------------------------------------------------------
 START-END                  PERMS  TAG    PATH
------------------------------------------------------------
 5651a4b00000-5651a4b30000  r--p   ---    /usr/lib/systemd/systemd
 5651a4b30000-5651a4c00000  r-xp  [ X ]   /usr/lib/systemd/systemd
```

Si aparece la etiqueta `[RWX]` en alguna región, indica memoria
ejecutable+escribible (típica de JIT compilers o shellcode injectado).

## 8. Análisis estático automatizado

```bash
make analysis
```

Genera en `analysis/`:

- `strings_debug.txt`     — strings del binario con símbolos
- `strings_stripped.txt`  — strings del binario stripped
- `symbols.txt`           — `nm --defined-only --demangle bin/main-debug`
- `elf_header.txt`        — `readelf -h bin/main`
- `sections.txt`          — `objdump -h bin/main`

Discusión completa en `analysis/notes.md`.

## 9. Resultado global

| Subcomando  | Build | Ejecución | Salida coincide con spec |
|-------------|:-----:|:---------:|:-----:|
| `--help`    | ✓ | ✓ | ✓ |
| `hash`      | ✓ | ✓ | ✓ (vector FIPS 180-4) |
| `procs`     | ✓ | ✓ | ✓ |
| `scan`      | ✓ | ✓ | ✓ (default + manual) |
| `brute`     | ✓ | ✓ | ✓ (fnv y sha256) |
| `sniff`     | ✓ | ✓ (root) | ✓ (con resumen IPs) |
| `mem`       | ✓ | ✓ | ✓ |

Compilación sin warnings con `-Wall -Wextra -Wpedantic`.
