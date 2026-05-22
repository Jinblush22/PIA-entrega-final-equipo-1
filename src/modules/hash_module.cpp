/**
 * file hash_module.cpp
 * Implementación del submódulo de hashing (FNV-1a y SHA-256).
 * details: Proporciona funcionalidades para calcular firmas (hashes) de cadenas de texto
 * en memoria y de archivos completos, utilizando lectura por bloques (chunking) para 
 * evitar el consumo excesivo de RAM en archivos grandes.
 */
#include "modules/hash_module.h"
#include "modules/sha256.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace edusec::hash_module {
/**
 * namespace anónimo
 * Encapsula las constantes matemáticas locales para prevenir colisiones en el enlazado.
 */
namespace {
// Constantes mágicas del algoritmo FNV-1a (32 bits).
// Se declaran como 'constexpr' para que se evalúen y asignen en tiempo de compilació
constexpr std::uint32_t kFnvOffset = 0x811C9DC5u;
constexpr std::uint32_t kFnvPrime  = 0x01000193u;
}
/**
 * Implementación principal del algoritmo FNV-1a para 32 bits.
 * data- Puntero genérico (void*) al inicio del bloque de memoria a procesar.
 * len- Longitud en bytes de la información a procesar.
 * return std::uint32_t Valor hash resultante.
 */
std::uint32_t fnv1a_32(const void* data, std::size_t len) {
    // Casting seguro (static_cast) de void* a enteros sin signo de 8 bits
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t hash = kFnvOffset;
    for (std::size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];   // 1. Aplicar XOR con el byte actual
        hash *= kFnvPrime;  // 2. Multiplicar por el primo (característico de FNV-1a)
    }
    return hash;
}
/**
 * Formatea un valor entero de 32 bits a su representación hexadecimal.
 * value- Entero sin signo de 32 bits.
 * return std::string Cadena de 8 caracteres hexadecimales con ceros a la izquierda (padding).
 */
std::string to_hex_u32(std::uint32_t value) {
    std::ostringstream oss;
    // Uso de manipuladores de flujo (<iomanip>) para garantizar un formato consistente (ej. 0x0000000A)
    oss << std::hex << std::setw(8) << std::setfill('0') << value;
    return oss.str();
}
/**
 * Interfaz o envoltorio amigable para aplicar FNV-1a directamente a un std::string.
 * s- Cadena de texto constante.
 * return std::string Hash formateado en hexadecimal.
 */
std::string fnv1a_32_hex(const std::string& s) {
    return to_hex_u32(fnv1a_32(s.data(), s.size()));
}

namespace {
/**
* enum Algo
* Enumeración fuertemente tipada (enum class) para identificar el algoritmo seleccionado
* de manera más segura que usando simples strings o enteros.
*/
enum class Algo { Fnv, Sha256 };
/**
 * Calcula e imprime en la salida estándar el hash FNV-1a de un texto corto.
 */
int hash_string_fnv(const std::string& text) {
    std::cout << "FNV1a-32(string) = 0x"
              << to_hex_u32(fnv1a_32(text.data(), text.size())) << '\n';
    return 0;
}
/**
* Calcula e imprime en la salida estándar el hash SHA-256 de un texto corto.
*/
int hash_string_sha(const std::string& text) {
    std::cout << "SHA-256(string)  = " << edusec::sha256::hash_string(text) << '\n';
    return 0;
}
/**
 * Calcula el hash FNV-1a de un archivo local de forma segura para la memoria.
 * path- Ruta del archivo en el sistema.
 * return int 0 en éxito, 1 si ocurre un error de lectura/apertura.
 */
int hash_file_fnv(const std::string& path) {
    // std::ios::binary es crucial al leer archivos de cualquier tipo para no corromper 
    // el hash por la manipulación de saltos de línea que hace el SO en modo texto.
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "[!] No se pudo abrir: " << path << '\n';
        return 1;
    }

    std::uint32_t hash = kFnvOffset;
    char buffer[4096];//Buffer de lectura de 4 KB (tamaño de página común, optimiza acceso a disco)
    std::size_t total = 0;
    // Bucle de lectura por bloques (chunking) para archivos pesados
    while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0) {
        const auto got = static_cast<std::size_t>(in.gcount());
        for (std::size_t i = 0; i < got; ++i) {
            hash ^= static_cast<std::uint8_t>(buffer[i]);
            hash *= kFnvPrime;
        }
        total += got;
    }
    std::cout << "FNV1a-32(file)   = 0x" << to_hex_u32(hash)
              << "  (" << total << " bytes leídos: " << path << ")\n";
    return 0;
}
/**
 * Calcula el hash SHA-256 de un archivo local de forma iterativa.
 * path- Ruta del archivo.
 * return int 0 en éxito, 1 en error.
 */
int hash_file_sha(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "[!] No se pudo abrir: " << path << '\n';
        return 1;
    }
    edusec::sha256::Context ctx;
    char buffer[4096];
    std::size_t total = 0;
    // Actualización incremental del contexto del hash. No cargamos el archivo entero.
    while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0) {
        const auto got = static_cast<std::size_t>(in.gcount());
        ctx.update(buffer, got);
        total += got;
    }
    std::cout << "SHA-256(file)    = "
              << edusec::sha256::Context::to_hex(ctx.finalize())
              << "  (" << total << " bytes: " << path << ")\n";
    return 0;
}

}// Fin namespace anónimo interno

/**
 * Delegador principal del submódulo de hashing.
 * details: Analiza los argumentos proporcionados, determina el algoritmo a usar (FNV o SHA256),
 * el tipo de entrada objetivo (cadena en bruto o archivo del sistema) y redirige la ejecución.
 * args- Vector de argumentos ya filtrados por el core del programa.
 * return int Código de salida del sistema.
 */

int run(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Uso: hash [--format fnv|sha256] --string <texto> | --file <ruta>\n";
        return 2;
    }

    Algo algo = Algo::Fnv; // FNV-1a se asume como default si no se especific
    std::string input_flag, input_value;
    // Parseo lineal buscando banderas y sus valores correspondientes
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        // Verificación y validación de la bandera de formato
        if (a == "--format" && i + 1 < args.size()) {
            const std::string& v = args[++i];
            if (v == "sha256") algo = Algo::Sha256;
            else if (v == "fnv") algo = Algo::Fnv;
            else { std::cerr << "[!] --format soporta: fnv | sha256\n"; return 2; }
        // Captura del flag objetivo (string o file) y su payload
        } else if ((a == "--string" || a == "--file") && i + 1 < args.size()) {
            input_flag  = a;
            input_value = args[++i];
        }
    }
    // Comprobación de integridad de los argumentos obligatorioS
    if (input_flag.empty()) {
        std::cerr << "Uso: hash [--format fnv|sha256] --string <texto> | --file <ruta>\n";
        return 2;
    }
    // Enrutamiento final aplicando una estructura ternaria para mayor concisión
    if (input_flag == "--string") {
        return (algo == Algo::Fnv) ? hash_string_fnv(input_value)
                                   : hash_string_sha(input_value);
    }
    return (algo == Algo::Fnv) ? hash_file_fnv(input_value)
                               : hash_file_sha(input_value);
}

} // namespace edusec::hash_module
