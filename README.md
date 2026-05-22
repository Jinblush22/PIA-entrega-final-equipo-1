# EduSec Toolkit — PIA PAC — GRUPO 01

> **Entrega Final · Fase IV (Desarrollo Ofensivo Responsable)** · Versión
> `1.0.0-final` · Mayo 2026.
>
> Componente educativo de ciberseguridad implementado en C++17. Uso
> exclusivo en máquinas virtuales aisladas. Material académico para el
> curso PAC del semestre Enero–Junio 2026.

---

## 1. Objetivo del proyecto

Diseñar, implementar, probar y analizar un **toolkit educativo modular** en
C++ que demuestre técnicas reales de ciberseguridad — hashing criptográfico,
fuerza bruta por diccionario, reconocimiento TCP con banner-grabbing,
captura pasiva de paquetes, enumeración local de procesos e inspección de
memoria — en un perfil estrictamente **benigno, no persistente y sin
exfiltración**. El binario resultante sirve además como objetivo de
análisis estático, análisis dinámico e ingeniería inversa con Ghidra,
Radare2 y la suite estándar de GNU binutils.

## 2. Dependencias

**De compilación** (mínimas, todas estándar en Linux moderno):

- `g++` con soporte de C++17 (≥ 7.0; probado con 13.x).
- `make` (GNU Make).
- GNU binutils (`strip`, `nm`, `readelf`, `objdump`) — para `make analysis`.

**De ejecución**: ninguna librería externa en tiempo de ejecución; el binario
está enlazado únicamente contra `libstdc++` y `libc`. El módulo `sniff`
requiere `CAP_NET_RAW` (ejecutar con `sudo`).

**De análisis** (no necesarias para compilar/correr, sí para reproducir el
reporte): Ghidra ≥ 11.0, Radare2 ≥ 5.9, Wireshark, `strace`, `ltrace`,
`gdb`, `checksec` (de pwntools).

## 3. Cómo compilar (comando exacto)

```bash
make
```

Esto produce los tres artefactos:

```
bin/main-debug   ELF64 PIE, ~576 KB, con símbolos (-g -O0)
bin/main         ELF64 PIE,  ~68 KB, stripped (-O2 -s)
./main           copia de bin/main en la raíz, para ejecución cómoda
```

Targets adicionales:

```bash
make debug      # solo binario con símbolos
make release    # solo binario stripped
make analysis   # regenera artefactos en analysis/
make clean      # elimina build/, bin/ y ./main
```

## 4. Cómo ejecutar (comandos exactos)

```bash
# Banner y ayuda
./main --help
./main --version

# Hashing (FNV-1a/32 por defecto; SHA-256 con --format sha256)
./main hash --string "hola"
./main hash --format sha256 --string "abc"
./main hash --format sha256 --file /etc/hostname

# Enumeración de procesos del sistema
./main procs

# TCP connect-scan (sin --ports prueba el top 20 de servicios comunes)
./main scan --host 127.0.0.1
./main scan --host 127.0.0.1 --ports 22,80,443

# Fuerza bruta por diccionario (--format debe coincidir con el hash objetivo)
./main brute --format sha256 \
    --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --wordlist /usr/share/wordlists/rockyou.txt --limit 100000

# Sniffer pasivo (raw sockets — requiere root)
sudo ./main sniff --count 20

# Inspección de mapas de memoria de un proceso
./main mem --pid 1
```

Salidas completas y reproducibles documentadas en `docs/tests.md`.

## 5. Enlaces a entregables

| Documento                   | Ruta                          | Descripción                                   |
|-----------------------------|-------------------------------|-----------------------------------------------|
| Reporte técnico final       | `docs/report_final.pdf`       | 6–10 págs · Diseño, análisis, conclusiones    |
| Plan de pruebas             | `docs/tests.md`               | Comandos exactos + outputs reales             |
| Diseño técnico              | `docs/design.md`              | Arquitectura y módulos                        |
| Notas de ingeniería inversa | `analysis/notes.md`           | Hallazgos sobre el propio binario             |
| Metadatos del entorno       | `METADATA.md`                 | VM, snapshot, versiones de herramientas       |
| Video demo (2–5 min)        | `evidence/demo.mp4`           | Recorrido funcional grabado por el equipo     |

## 6. Integrantes y responsabilidades técnicas

| Integrante      | Matrícula | Responsabilidad principal                                   |
|-----------------|-----------|-------------------------------------------------------------|
| Josue Arcos     |  2009127  | Coordinación técnica, `main.cpp`, dispatcher, `mem_module`  |
| Johan Garay     |  2001776  | `hash_module` (FNV + SHA-256), `bruteforce_module`, `procs` |
| Andrea Abundiz  |  2051169  | `netscan_module` (TCP + banner), `sniffer_module`, RE       |
| (compartido)    |  —        | Documentación, evidencias y análisis estático/dinámico      |

## 7. Estructura de directorios

```
PIA_PAC_FINAL/
├── README.md
├── METADATA.md               (VM, snapshot, versiones)
├── makefile
├── .gitignore
├── main                      (copia stripped para ejecución cómoda)
├── src/
│   ├── main.cpp              (dispatcher)
│   └── modules/
│       ├── sha256.{h,cpp}              (FIPS 180-4 puro)
│       ├── hash_module.{h,cpp}         (FNV + SHA-256)
│       ├── bruteforce_module.{h,cpp}   (diccionario)
│       ├── proc_module.{h,cpp}         (/proc enum)
│       ├── netscan_module.{h,cpp}      (TCP scan + top 20 default)
│       ├── sniffer_module.{h,cpp}      (AF_PACKET)
│       └── mem_module.{h,cpp}          (/proc/maps)
├── bin/
│   ├── main-debug            (con símbolos, para análisis)
│   └── main                  (stripped, para entrega)
├── docs/
│   ├── design.md
│   ├── tests.md
│   ├── report_draft.md       (borrador del 2do avance, conservado)
│   └── report_final.pdf      (reporte final, 6–10 págs)
├── analysis/
│   ├── notes.md              (notas RE manuales)
│   ├── strings_debug.txt
│   ├── strings_stripped.txt
│   ├── symbols.txt
│   ├── elf_header.txt
│   └── sections.txt
└── evidence/
    ├── compilacion.png       (1er avance — conservada)
    ├── ejecucion.png         (1er avance — conservada)
    ├── snapshot_vm.png       (snapshot de la VM)
    ├── exec_final.png        (ejecución completa del toolkit)
    ├── ghidra_or_radare.png  (análisis estático / RE)
    └── demo.mp4              (video 2–5 min)
```

## 8. Tag final

```bash
git add -A
git commit -m "PIA: entrega final — Grupo 01"
git tag -a pia-entrega-final -m "PIA: entrega final — EduSec Toolkit v1.0.0"
```

## 9. Aviso ético

Todo lo aquí distribuido es material académico y se usa únicamente dentro
de las VMs aisladas del equipo. **No** debe ejecutarse contra equipos,
redes o servicios que no pertenezcan al equipo. El toolkit fue diseñado
sin persistencia, sin exfiltración y sin capacidades destructivas;
cualquier uso fuera de ese alcance queda fuera