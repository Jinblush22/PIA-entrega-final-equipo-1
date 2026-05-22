/**
* netscan_module.h
* Interfaz pública del submódulo de escaneo de red.
* details: Define el contrato de comunicación para el módulo de escaneo TCP, 
* permitiendo su integración desacoplada con el orquestador principal del toolkit.
*/
#ifndef EDUSEC_MODULES_NETSCAN_MODULE_H
#define EDUSEC_MODULES_NETSCAN_MODULE_H

#include <string>
#include <vector>

namespace edusec::netscan_module {
/**
* Ejecuta el proceso de escaneo de puertos (Connect Scan) sobre un host objetivo.
* args- Vector de argumentos analizados desde la línea de comandos (host, puertos).
* return int Código de estado (0: éxito, 1: error de red/host, 2: error de argumentos).
*/
int run(const std::vector<std::string>& args);

}

#endif