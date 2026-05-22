/**
 * file bruteforce_module.cpp
 * Módulo para realizar ataques de fuerza bruta (diccionario) contra hashes.
 * details: Implementa la lectura eficiente de archivos de texto grandes y la comparación 
 * iterativa de hashes utilizando algoritmos FNV-1a o SHA-256 para descubrir contraseñas en texto claro.
 */
#include "modules/bruteforce_module.h"
#include "modules/hash_module.h"
#include "modules/sha256.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

namespace edusec::bruteforce_module {
/**
 * namespace anónimo
 * Funciones de utilidad de uso interno para este módulo (internal linkage).
 */
namespace {
/**
 * Convierte una cadena de texto a minúsculas.
 * details: Se recibe el parámetro por valor para operar sobre una copia. 
 * Utiliza std::transform con una expresión lambda para asegurar conversiones seguras.
 * s-  Cadena de texto original.
 * return std::string Cadena transformada completamente a minúsculas.
 */
std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

}  //Fin namespace anónimo

/**
 * Ejecuta la rutina principal del ataque por diccionario.
 * args- Vector de argumentos analizados desde la línea de comandos.
 * return int Código de estado (0 = éxito/match encontrado, 1 = sin match/error de archivo, 2 = error de sintaxis).
 */

int run(const std::vector<std::string>& args) {
    //Valores por defecto
    std::string format = "fnv";
    std::string target_hash;
    std::string wordlist;
    std::size_t limit = 0;
    //Parseo lineal de argumentos (pares clave-valor)
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        const auto& flag = args[i];
        const auto& val  = args[i + 1];
        if      (flag == "--format")   format = val;
        else if (flag == "--hash")     target_hash = to_lower(val);// Se normaliza para evitar fallos por case-sensitivity
        else if (flag == "--wordlist") wordlist = val;
        else if (flag == "--limit")    limit = std::stoul(val);    // Conversión segura de string a unsigned long
    }
    //Validación de integridad de los parámetros obligatorios
    if (target_hash.empty() || wordlist.empty() ||
        (format != "fnv" && format != "sha256")) {
        std::cerr << "Uso: brute --format fnv|sha256 --hash <hex> "
                  << "--wordlist <ruta> [--limit N]\n";
        return 2;
    }
    //Normalización de datos: Elimina el prefijo "0x" si el usuario lo introdujo
    if (target_hash.rfind("0x", 0) == 0) target_hash.erase(0, 2);
    // Apertura del diccionario utilizando RAII (Resource Acquisition Is Initialization)
    std::ifstream in(wordlist);
    if (!in) {
        std::cerr << "[!] No se pudo abrir diccionario: " << wordlist << '\n';
        return 1;
    }
    // Impresión de parámetros de la ejecución actual
    std::cout << "[brute] format=" << format
              << "  hash=" << target_hash
              << "  wordlist=" << wordlist;
    if (limit) std::cout << "  limit=" << limit;
    std::cout << '\n' << "--------------------------------\n";
    // Inicialización del cronómetro para métricas de rendimiento
    const auto t_start = std::chrono::steady_clock::now();
    std::size_t tried = 0;
    std::string line;
    bool found = false;
    //Lectura eficiente línea por línea (ideal para wordlists masivos, evita sobrecargar la RAM)
    while (std::getline(in, line)) {
        // Sanitización (Manejo de CRLF): Elimina el retorno de carro (\r) si el archivo proviene de Windows
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // Ignorar líneas vacías en el diccionario
        if (line.empty()) continue;
        // Generación dinámica del hash candidato basada en el algoritmo seleccionado
        std::string candidate_hash =
            (format == "fnv") ? edusec::hash_module::fnv1a_32_hex(line)
                              : edusec::sha256::hash_string(line);

        ++tried;
        // Verificación de colisión / match exacto
        if (candidate_hash == target_hash) {
            //Cálculo del delta de tiempo
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t_start).count();
            std::cout << "[+] MATCH encontrado en " << tried
                      << " intentos (" << elapsed << " ms)\n"
                      << "    password = \"" << line << "\"\n";
            found = true;
            break;  // Termina la búsqueda en corto-circuito para ahorrar recurso
        }
        // Condición de parada temprana si se definió un límite de intentos
        if (limit && tried >= limit) break;
    }
    // Reporte de fallo en caso de agotar el diccionario sin éxito
    if (!found) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_start).count();
        std::cout << "[-] Sin match. Probadas " << tried
                  << " palabras en " << elapsed << " ms\n";
        return 1;
    }
    return 0;   // Ejecución exitosa y match encontrado
}

}// namespace edusec::bruteforce_module
