/**
 * file main.cpp
 * Punto de entrada principal para EduSec Toolkit.
 * details: Actúa como enrutador (dispatcher) que valida los argumentos de entrada 
 * y delega la ejecución al submódulo correspondiente de seguridad.
 */
#include <iostream>
#include <string>
#include <vector>

// Cabeceras de los submódulos de la herramienta
#include "modules/hash_module.h"
#include "modules/proc_module.h"
#include "modules/netscan_module.h"
#include "modules/bruteforce_module.h"
#include "modules/sniffer_module.h"
#include "modules/mem_module.h"
/**
 * namespace anónimo
 * Se utiliza un espacio de nombres anónimo para restringir el enlazado (internal linkage)
 * de las funciones de interfaz gráfica a esta unidad de traducción. Esto evita 
 * colisiones de nombres en la tabla de símbolos durante la compilación.
 */
namespace {

void print_banner() {   //Imprimir el encabezado principal de la herramienta en la salida exterior
    std::cout
        << "===============================================\n"
        << "  EduSec Toolkit v1.4\n"
        << "  PIA PAC Ene-Jun 2026 - GRUPO 061\n"
        << "  Equipo 1 Angel Arcos, Andrea Abundiz, Johan Garay\n"
        << "===============================================\n";
}
/**
 *  Despliega la guía de uso y la sintaxis de los comandos disponibles.
 *  prog- Nombre del binario en ejecución (normalmente argv[0]).
 */
void print_usage(const char* prog) {    //Imprimir el Uso
    std::cout
        << "Uso: " << prog << " <subcomando> [opciones]\n\n"
        << "Subcomandos:\n"
        << "  hash    Hashing FNV-1a/32 o SHA-256 de cadena o archivo\n"
        << "          [--format fnv|sha256]  --string <txt> | --file <ruta>\n\n"
        << "  procs   Enumera procesos via /proc (Linux)\n\n"
        << "  scan    TCP connect-scan a host\n"
        << "          --host <ip|host>  [--ports <p1,p2,..>]\n"
        << "          (sin --ports prueba el top 20 de servicios comunes)\n\n"
        << "  brute   Ataque por diccionario contra hash FNV/SHA-256\n"
        << "          --format fnv|sha256 --hash <hex> --wordlist <ruta> [--limit N]\n\n"
        << "  sniff   Captura pasiva de paquetes (Linux AF_PACKET, root)\n"
        << "          [--count <N>]      Detiene tras N paquetes (default 20)\n"
        << "          Al final lista las IPs unicas observadas\n\n"
        << "  mem     Inspecciona /proc/<pid>/maps de un proceso\n"
        << "          --pid <PID>\n\n"
        << "  --help, -h    Muestra esta ayuda\n";
}

}//Fin namespace anónimo

/**
 * Función principal y punto de entrada del programa.
 * argc- Cantidad de argumentos pasados por la interfaz de línea de comandos (CLI).
 * argv- Arreglo de punteros a cadenas de caracteres con los argumentos.
 * return int Código de salida del sistema opertivo (0 = éxito, >0 = error).
 */

int main(int argc, char* argv[]) {  
    // Validación mínima de argumentos: Si no hay submando, se muestra la ayuda.
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 0;// Se retorna 0 porque solicitar o necesitar ayuda no es un error de ejecución
    }

    const std::string sub = argv[1];
    
    // Intercepción de banderas de ayuda globales antes de procesar otros módulos
    if (sub == "--help" || sub == "-h") { print_banner(); print_usage(argv[0]); return 0; }
    // Empaquetado de argumentos: Convertimos los punteros char* de C a std::string y los
    // almacenamos en un vector dinámico para facilitar su manejo y paso por referencia
    // a los diferentes módulos. Se omite argv[0] (programa) y argv[1] (subcomando)
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);
    // Enrutamiento de la ejecución hacia el módulo correspondiente
    if (sub == "hash")  return edusec::hash_module::run(args);
    if (sub == "procs") return edusec::proc_module::run(args);
    if (sub == "scan")  return edusec::netscan_module::run(args);
    if (sub == "brute") return edusec::bruteforce_module::run(args);
    if (sub == "sniff") return edusec::sniffer_module::run(args);
    if (sub == "mem")   return edusec::mem_module::run(args);
    // Flujo de fallback: El subcomando introducido no coincide con ningún módulo registrado.
    std::cerr << "[!] Subcomando desconocido: " << sub << "\n\n";
    print_usage(argv[0]);
    return 2;// Código 2 generalmente indica un mal uso de los comandos en la shell
}
