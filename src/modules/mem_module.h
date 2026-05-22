/**
* file mem_module.h
* Interfaz del submódulo de análisis de memoria dinámica.
* details: Define el contrato para la ejecución de rutinas de inspección 
* del sistema de archivos /proc en Linux. Se aísla la firma de la función 
* para permitir una integración limpia con el despachador principal (main.cpp) 
* manteniendo la implementación técnica completamente encapsulada.
*/

// Guardas de inclusión (Include Guards) para garantizar que el compilador
// procese este archivo de cabecera una sola vez por unidad de traducción,
// previniendo errores de redefinición (ODR - One Definition Rule).
#ifndef EDUSEC_MODULES_MEM_MODULE_H
#define EDUSEC_MODULES_MEM_MODULE_H

#include <string>
#include <vector>

namespace edusec::mem_module {
/**
* Inicia el análisis de la disposición de memoria de un proceso específico.
* details: Recibe los argumentos de la línea de comandos, busca el PID objetivo 
* y coordina la lectura de los archivos de estado para identificar posibles 
* inyecciones de código o violaciones a las políticas de seguridad de memoria.
* args- Vector constante de cadenas que contiene las banderas y valores (ej. --pid 1234).
* Se pasa por referencia constante (const &) para optimizar el uso de recursos y evitar copias profundas.
* return int Código de estado de salida (0 = éxito, 1 = fallo de E/S o permisos, 2 = error de sintaxis).
*/
int run(const std::vector<std::string>& args);

} 
#endif // EDUSEC_MODULES_MEM_MODULE_H
