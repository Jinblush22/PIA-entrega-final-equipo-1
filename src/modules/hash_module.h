/**
* file hash_module.h
* Interfaz del submódulo de hashing (FNV-1a y SHA-256).
* details: Expone las funciones principales para el cálculo y formateo de hashes. 
* Se separan las definiciones en esta cabecera para permitir que otros módulos 
* (como el de fuerza bruta) reutilicen estas rutinas matemáticas sin crear 
* dependencias circulares ni pasar por la interfaz de línea de comandos.
*/

// Guardas de inclusión (Include Guards) para prevenir definiciones múltiples (ODR - One Definition Rule)
#ifndef EDUSEC_MODULES_HASH_MODULE_H
#define EDUSEC_MODULES_HASH_MODULE_H

#include <cstdint>
#include <string>
#include <vector>
/**
* namespace edusec::hash_module
* Agrupa las rutinas de generación y formateo de firmas no criptográficas (FNV) y criptográficas (SHA).
*/

namespace edusec::hash_module {
/**
* Punto de entrada para la ejecución del submódulo "hash" desde la línea de comandos.
* args- Vector constante de argumentos pasados por referencia para evitar copias innecesarias en memoria.
* return int Código de estado de salida (0 = éxito, >0 = error de I/O o sintaxis).
*/
int run(const std::vector<std::string>& args);
/**
* Calcula el hash FNV-1a (32 bits) de un bloque genérico de memoria.
* details: Al usar void* y std::size_t, la función es agnóstica al tipo de dato, 
* permitiendo procesar tanto cadenas de texto como búferes de archivos binarios.
* data- Puntero genérico (void*) al inicio de los datos a procesar en memoria.
* len- Tamaño en bytes de los datos (garantiza capacidad para cualquier bloque).
* return std::uint32_t Hash resultante de 32 bits sin signo.
*/
std::uint32_t fnv1a_32(const void* data, std::size_t len);
/**
* Interfaz amigable para calcular el hash FNV-1a de una cadena y devolverlo como texto hexadecimal.
* s- Cadena de texto constante pasada por referencia.
* return std::string Hash formateado a 8 caracteres hexadecimales.
*/
std::string   fnv1a_32_hex(const std::string& s);
/**
* Convierte un entero sin signo de 32 bits a su representación hexadecimal.
* value- Valor numérico de 32 bits a formatear.
* return std::string Cadena hexadecimal con relleno de ceros a la izquierda (padding).
*/
std::string   to_hex_u32(std::uint32_t value);

}  // namespace edusec::hash_module

#endif // EDUSEC_MODULES_HASH_MODULE_H
