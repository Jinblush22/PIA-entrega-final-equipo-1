/**
* proc_module.h
* Interfaz pública del submódulo de enumeración de procesos.
* details: Define el contrato de comunicación para el módulo encargado de la 
* inspección de procesos en el sistema Linux, permitiendo su integración 
* modular y desacoplada con el orquestador principal del toolkit (main.cpp).
*/
#ifndef EDUSEC_MODULES_PROC_MODULE_H
#define EDUSEC_MODULES_PROC_MODULE_H

#include <string>
#include <vector>

namespace edusec::proc_module {
/**
* Ejecuta el escaneo y listado de procesos activos en el sistema.
* details: Itera sobre el sistema de archivos /proc para extraer metadatos
* (PID y nombre de comando) de cada proceso en ejecución.
* args- Vector de argumentos recibidos de la línea de comandos.
* return int Código de estado (0: éxito, 1: error de acceso al sistema).
*/
int run(const std::vector<std::string>& args);

}

#endif
