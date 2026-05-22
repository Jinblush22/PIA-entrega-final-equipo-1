/**
* file mem_module.cpp
* Submódulo de inspección de memoria para procesos en Linux.
* details: Utiliza el sistema de archivos virtual procfs (/proc) para leer los 
* permisos de las regiones de memoria mapeadas de un proceso. Es una técnica 
* fundamental en el análisis de malware dinámico y el triaje de incidentes para 
* detectar inyecciones de código (shellcodes) o binarios empaquetados (packers).
*/
#include "modules/mem_module.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace edusec::mem_module {
/**
* namespace anónimo
* Funciones auxiliares de uso interno para la lectura de archivos del sistema.
*/
namespace {
/**
* Lee el contenido íntegro de un archivo de texto en memoria.
* details: Utiliza un std::ostringstream y el buffer del stream (rdbuf) para 
* volcar el contenido del archivo de una sola pasada, lo cual es muy eficiente 
* para archivos pequeños generados dinámicamente como los de /proc.
* path- Ruta absoluta del archivo a leer.
* return std::string Contenido del archivo o una cadena vacía en caso de error.
*/
std::string read_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

} 
/**
* Ejecuta el análisis de los mapas de memoria del PID especificado.
* args- Vector de argumentos analizados desde la línea de comandos.
* return int Código de salida (0 = éxito, 1 = error de permisos/lectura, 2 = error de sintaxis).
*/
int run(const std::vector<std::string>& args) {
    std::string pid;
    // Parseo de argumentos en busca de la bandera --pi
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--pid") pid = args[i + 1];
    }
    // Validación de integridad del parámetro
    if (pid.empty()) {
        std::cerr << "Uso: mem --pid <PID>\n";
        return 2;
    }
    // Lectura del archivo de estado general del proces
    const std::string status = read_file("/proc/" + pid + "/status");
    if (status.empty()) {
        std::cerr << "[!] PID inválido o sin permiso: " << pid << '\n';
        return 1;
    }

    auto extract = [&](const std::string& key) -> std::string {
        const auto pos = status.find(key);
        if (pos == std::string::npos) return {};
        const auto eol = status.find('\n', pos);// Encuentra el final de la línea actual
        return status.substr(pos, eol - pos);
    };

    std::cout << "[mem] inspección de PID " << pid << "\n"
              << "  " << extract("Name:")   << "\n"
              << "  " << extract("Uid:")    << "\n"
              << "  " << extract("VmPeak:") << "\n"
              << "  " << extract("VmRSS:")  << "\n"
              << "------------------------------------------------------------\n"
              << " START-END                  PERMS  TAG    PATH\n"
              << "------------------------------------------------------------\n";

    // --- maps ---
    std::ifstream maps("/proc/" + pid + "/maps");
    if (!maps) {
        std::cerr << "[!] No se pudo leer /proc/" << pid << "/maps\n";
        return 1;
    }

    std::string line;
    int total = 0, rwx_count = 0;
    // Tokenización y parseo línea por línea
    while (std::getline(maps, line)) {
        ++total;
        std::istringstream ls(line);// Se usa istringstream para separar fácilmente por espacios
        std::string range, perms, off, dev, inode, path;
        // Extracción secuencial de las columnas estándar de /proc/maps
        ls >> range >> perms >> off >> dev >> inode;
        std::getline(ls, path); // La ruta (si existe) puede contener espacios, se extrae el resto

        std::string tag = " --- ";
        if (perms.size() >= 3 && perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            tag = "[RWX]";
            ++rwx_count;
        } else if (perms.find('x') != std::string::npos) {
            tag = "[ X ]";
        }
        
        std::cout << " " << std::left << std::setw(26) << range
                  << " " << std::setw(5)  << perms
                  << " " << tag
                  << " " << path << '\n';
    }
    // Reporte final del análisis dinámico
    std::cout << "------------------------------------------------------------\n"
              << "Total regiones: " << total
              << "   Regiones RWX: " << rwx_count;
    // Alerta de seguridad si se detectan anomalías de memoria
    if (rwx_count > 0) {
        std::cout << "  ¡posible shellcode o JIT! revisar.";
    }
    std::cout << '\n';
    return 0;// Análisis completado con éxit
}

}
