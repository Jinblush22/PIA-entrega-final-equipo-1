/**
* sha256.h
* Interfaz para el motor de hashing SHA-256.
* details: Provee la clase Context, la cual encapsula el estado del algoritmo 
* SHA-256 (RFC 6234), permitiendo procesar datos de forma incremental y 
* calcular resúmenes (digests) seguros.
*/
#ifndef EDUSEC_MODULES_SHA256_H
#define EDUSEC_MODULES_SHA256_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>

namespace edusec::sha256 {
/**
* Clase para el cálculo de hashes SHA-256.
* details: Implementa la máquina de estado para procesar bloques de datos de 512 bits.
*/
class Context {
   public:
    Context();
    void update(const void* data, std::size_t len);
    std::array<std::uint8_t, 32> finalize();         
    static std::string to_hex(const std::array<std::uint8_t, 32>& digest);

   private:
    void process_block(const std::uint8_t block[64]);

    std::array<std::uint32_t, 8> h_;
    std::array<std::uint8_t, 64> buffer_;
    std::size_t buffer_len_ = 0;
    std::uint64_t bit_count_ = 0;
};

// Funciones utilitarias para hashing rápido de cadenas y bytes.
std::string hash_string(const std::string& s);
std::string hash_bytes(const void* data, std::size_t len);

}

#endif
