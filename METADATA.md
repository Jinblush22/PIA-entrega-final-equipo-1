# METADATA — Entorno de desarrollo y pruebas

> Información mínima para que la maestra (u otro grupo) pueda **reproducir**
> exactamente el entorno donde se compiló, ejecutó y analizó `EduSec Toolkit`.

## VM utilizada

| Campo                    | Valor                                       |
|--------------------------|---------------------------------------------|
| Hipervisor               | _e.g. VirtualBox 7.0.18 / VMware Workstation 17 / QEMU 8.2_ |
| Sistema invitado         | _e.g. Kali Linux 2025.1_                    |
| Kernel                   | _salida de_ `uname -r` _e.g._ `6.6.15-amd64` |
| Arquitectura             | x86_64                                      |
| RAM asignada             | _e.g._ 4096 MB                              |
| vCPU                     | _e.g._ 2                                    |
| Modo de red              | host-only / NAT aislada (sin bridge)        |

## Snapshot del trabajo

| Campo               | Valor                                            |
|---------------------|--------------------------------------------------|
| Nombre del snapshot | `pia-entrega-final`                              |
| ID / UUID           | _UUID que muestra el hipervisor_                 |
| Fecha de captura    | _YYYY-MM-DD HH:MM_                               |
| Comentario          | Estado del proyecto justo antes del `git tag`    |

> Capturar el snapshot **después** de:
> 1. `make clean && make && make analysis`
> 2. `git add -A && git commit -m "PIA: entrega final — Grupo 01"`
> 3. `git tag -a pia-entrega-final ...`

## Versiones de herramientas

Salidas reales (`--version`) de las herramientas usadas. Ejecuta cada
comando dentro de la VM y pega la primera línea del output.

| Herramienta | Comando            | Versión observada              |
|-------------|--------------------|--------------------------------|
| g++         | `g++ --version`    | _e.g._ `g++ (Debian 13.2.0-7) 13.2.0` |
| make        | `make --version`   | _e.g._ `GNU Make 4.4.1`        |
| strip       | `strip --version`  | _e.g._ `GNU strip 2.42`        |
| nm          | `nm --version`     | _e.g._ `GNU nm 2.42`           |
| readelf     | `readelf --version`| _e.g._ `GNU readelf 2.42`      |
| objdump     | `objdump --version`| _e.g._ `GNU objdump 2.42`      |
| Ghidra      | menú _Help → About_| _e.g._ `Ghidra 11.1.2`         |
| Radare2     | `r2 -v`            | _e.g._ `radare2 5.9.4`         |
| Wireshark   | `wireshark -v`     | _e.g._ `Wireshark 4.2.4`       |
| strace      | `strace --version` | _e.g._ `strace -- version 6.8` |
| ltrace      | `ltrace --version` | _e.g._ `ltrace version 0.7.3`  |
| gdb         | `gdb --version`    | _e.g._ `GNU gdb 14.1`          |

## SHA-256 de los binarios entregados

Generados con el propio toolkit (`./main hash --format sha256 --file ...`)
después del último `make`. Permite verificar que el binario distribuido es
el mismo que el analizado en el reporte.

```
bin/main         _completar tras compilar_
bin/main-debug   _completar tras compilar_
```

> Comando rápido:
> ```bash
> ./main hash --format sha256 --file bin/main
> ./main hash --format sha256 --file bin/main-debug
> ```

## Comando único de reproducción

Para que la maestra pueda reproducir el build y los análisis en una sola
línea:

```bash
git clone <repo> && cd PIA_PAC_FINAL && make clean && make && make analysis
```
