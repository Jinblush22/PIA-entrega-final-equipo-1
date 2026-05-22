/**
* proc_module.cpp
* Submódulo de enumeración de procesos en entornos Linux.
* details: Utiliza la interfaz de sistema de archivos /proc para listar dinámicamente
* los procesos activos del sistema. Filtra descriptores de directorio numéricos para 
* identificar procesos legítimos y extrae metadatos básicos como el nombre del 
* ejecutable (comm). Implementa preprocesador condicional para garantizar portabilidad.
*/
#include "modules/proc_module.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#if defined(__linux__)
#include <dirent.h>
#endif

namespace edusec::proc_module {

namespace {
/**
* Valida si una cadena consiste únicamente de dígitos.
* details: Utilizada para identificar carpetas de procesos (PIDs) en /proc.
* s- Cadena a evaluar.
* return true si es numérico, false en caso contrario.
*/
bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; });
}
/**
* Lee la primera línea de un archivo de texto.
* details: Utilizada para extraer el nombre del proceso desde /proc/<pid>/comm.
* path- Ruta al archivo del sistema.
* return std::string Contenido de la primera línea.
*/
std::string read_first_line(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::string line;
    std::getline(in, line);
    return line;
}

}
/**
* Orquestador del escaneo de procesos activos.
* details: Itera sobre el sistema de archivos /proc, valida los directorios y 
* despliega un reporte tabular con PID y nombre de ejecutable.
* args- Argumentos de la línea de comandos (no utilizados actualmente).
* return int 0 si el escaneo es exitoso, 1 si ocurre error de acceso.
*/
int run(const std::vector<std::string>& args) {
    (void)args; 

#if defined(__linux__)
    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        std::cerr << "[!] /proc no accesible.\n";
        return 1;
    }

    std::cout << std::left << std::setw(8) << "PID"
              << "COMM\n"
              << std::string(40, '-') << '\n';

    int count = 0;
    while (auto* entry = readdir(dir)) {
        const std::string name = entry->d_name;
        // Filtra para solo procesar directorios de PID
        if (!is_all_digits(name)) continue;

        const std::string comm = read_first_line("/proc/" + name + "/comm");
        std::cout << std::left << std::setw(8) << name << comm << '\n';
        ++count;
    }
    closedir(dir);

    std::cout << std::string(40, '-') << '\n'
              << "Total: " << count << " procesos\n";
    return 0;
#else
    std::cerr << "[!] El módulo procs solo está soportado en Linux en este avance.\n";
    return 1;
#endif
}

} 
