/**
 * file bruteforce_module.h
 * Definición de la interfaz para el submódulo de ataque por fuerza bruta.
 * details: Este archivo de cabecera expone únicamente la firma de la función 
 * principal del módulo, manteniendo los detalles de implementación encapsulados.
 */
// Guardas de inclusión (Include Guards) para evitar el problema de múltiple inclusión
// y prevenir violaciones a la regla de definición única (ODR - One Definition Rule) 
// durante la fase de preprocesamiento y compilación
#ifndef EDUSEC_MODULES_BRUTEFORCE_MODULE_H
#define EDUSEC_MODULES_BRUTEFORCE_MODULE_H

#include <string>
#include <vector>
/**
 * namespace edusec::bruteforce_module
 * Agrupa el contrato de las funcionalidades correspondientes al ataque de diccionario.
 */
namespace edusec::bruteforce_module {
/**
 * Punto de entrada principal para la ejecución del submódulo "brute".
 * details: Delegador que recibe los argumentos limpios desde el enrutador principal, 
 * configura el entorno de ataque y ejecuta la verificación iterativa contra el diccionario.
 * args- Vector constante de cadenas de texto que contiene las opciones y banderas. 
 * Se pasa por referencia constante (const &) para evitar la sobrecarga de 
 * copiar el vector en memoria.
 * return int Código de salida del módulo (0 = éxito, 1 = fallo/sin match, 2 = error de sintaxis).
 */
int run(const std::vector<std::string>& args);

} // namespace edusec::bruteforce_module

#endif // EDUSEC_MODULES_BRUTEFORCE_MODULE_H
