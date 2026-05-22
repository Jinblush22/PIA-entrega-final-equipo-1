/**
* sniffer_module.h
* Interfaz del módulo de captura de paquetes (Sniffer).
* details: Define el contrato público para el escaneo pasivo de tráfico de red,
* permitiendo la integración de la captura de paquetes a nivel de capa de enlace
* dentro de la arquitectura modular del EduSec Toolkit.
*/
#ifndef EDUSEC_MODULES_SNIFFER_MODULE_H
#define EDUSEC_MODULES_SNIFFER_MODULE_H

#include <string>
#include <vector>

namespace edusec::sniffer_module {
/**
* Ejecuta el proceso de captura pasiva de paquetes de red.
* args- Vector de argumentos analizados desde la línea de comandos (ej. --count).
* return int Código de estado (0: éxito, 1: error de privilegios o socket).
*/
int run(const std::vector<std::string>& args);

}

#endif 