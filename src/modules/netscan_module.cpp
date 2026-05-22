/**
* file netscan_module.cpp
* Submódulo de escaneo de puertos TCP (Connect Scan).
* details: Implementa un escáner de red interactuando directamente con la API 
* de sockets POSIX. Utiliza sockets no bloqueantes y multiplexación (select) 
* para implementar tiempos de espera (timeouts) personalizados, garantizando 
* un escaneo rápido y eficiente en entornos de red hostiles.
*/
#include "modules/netscan_module.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define EDUSEC_HAS_SOCKETS 1
#else
#define EDUSEC_HAS_SOCKETS 0
#endif

namespace edusec::netscan_module {

namespace {

constexpr int kTimeoutSeconds = 1;
/**
* Vector constante con el Top 20 de puertos más explotados/comunes.
* details: Se utiliza como opción predeterminada para escaneos rápidos de superficie de ataque.
*/
const std::vector<int> kTopPorts20 = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
};
/**
* Analiza una cadena separada por comas (CSV) y extrae los puertos.
* csv- Cadena de texto con los puertos (ej. "80,443,8080").
* return std::vector<int> Lista de puertos validados (1-65535).
*/
std::vector<int> parse_ports(const std::string& csv) {
    std::vector<int> ports;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) continue;
        try {
            const int p = std::stoi(item);
            if (p > 0 && p <= 65535) ports.push_back(p);
        } catch (...) {}
    }
    return ports;
}

#if EDUSEC_HAS_SOCKETS
/**
* Resuelve un nombre de dominio (Hostname) o IP a una estructura in_addr.
* details: Utiliza inet_pton para IPs directas y getaddrinfo para resolución DNS.
* host- Cadena con la dirección IP o dominio.
* out- Referencia a la estructura donde se guardará la dirección resuelta.
* return true si la resolución fue exitosa, false en caso contrario.
*/
bool resolve_host(const std::string& host, in_addr& out) {
    if (inet_pton(AF_INET, host.c_str(), &out) == 1) return true;
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return false;
    out = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return true;
}
/**
* Intenta establecer una conexión TCP (Three-way handshake) con el puerto objetivo.
* details: Implementa un enfoque de I/O asíncrono. Configura el socket como NO BLOQUEANTE 
* (O_NONBLOCK) para que connect() retorne inmediatamente (EINPROGRESS). Luego, usa select() 
* para esperar hasta que el socket sea escribible o el timeout expire.
* addr- Estructura in_addr con la IP objetivo.
* port Puerto TCP a sondear.
* return true si el puerto está ABIERTO, false si está CERRADO o FILTRADO.
*/
bool probe_port(const in_addr& addr, int port) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    const int flags = ::fcntl(sock, F_GETFL, 0);
    ::fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port   = htons(static_cast<uint16_t>(port));
    target.sin_addr   = addr;

    bool open = false;
    const int rc = ::connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));

    if (rc == 0) {
        open = true;// Conexión inmediata (poco común, generalmente localhost)
    } else if (errno == EINPROGRESS) {
        fd_set wset; FD_ZERO(&wset); FD_SET(sock, &wset);
        timeval tv{kTimeoutSeconds, 0};
        if (::select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int so_err = 0; socklen_t len = sizeof(so_err);
            // Verifica si hubo un error real en la conexión o si fue exitosa
            ::getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
            open = (so_err == 0);
        }
    }

    ::close(sock);
    return open;
}

#endif 

} 
// Punto de entrada de ejecución del submódulo
int run(const std::vector<std::string>& args) {
    std::string host;
    std::vector<int> ports;

    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        const auto& flag  = args[i];
        const auto& value = args[i + 1];
        if      (flag == "--host")  host  = value;
        else if (flag == "--ports") ports = parse_ports(value);
    }
    //Validación de precondiciones: El parámetro del host destino es estrictamente obligatorio
    if (host.empty()) {
        std::cerr << "Uso: scan --host <ip|host> [--ports <p1,p2,..>]\n"
                  << "      (sin --ports se prueba el top 20 de servicios comunes)\n";
        return 2;
    }

#if !EDUSEC_HAS_SOCKETS
    std::cerr << "[!] netscan no soportado en esta plataforma.\n";
    return 1;
#else
    bool using_defaults = false;
    // Lógica de respaldo: si la lista está vacía se asigna el diccionario predefinido de puertos comunes
    if (ports.empty()) {
        ports = kTopPorts20;
        using_defaults = true;
    }

    in_addr addr{};
    //Fase preliminar: Conversión y resolución DNS de la cadena de texto de destino
    if (!resolve_host(host, addr)) {
        std::cerr << "[!] No se pudo resolver el host: " << host << '\n';
        return 1;
    }

    char ip_str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    std::cout << "[scan] objetivo: " << host << " (" << ip_str << ")\n";
    if (using_defaults) {
        std::cout << "[scan] sin --ports especificado, usando top 20 servicios comunes\n";
    }
    std::cout << "----------------------------\n"
              << " PUERTO   ESTADO\n"
              << "----------------------------\n";

    int open_count = 0;
    // Bucle síncrono iterativo sobre el vector de puertos seleccionados
    for (int port : ports) {
        const bool open = probe_port(addr, port);
        if (open) ++open_count;
        // Formateo dinámico de espacios en consola basándose en la longitud de caracteres del número de puerto
        std::cout << "  " << port
                  << std::string(port < 10 ? 6 : port < 100 ? 5
                                : port < 1000 ? 4 : port < 10000 ? 3 : 2, ' ')
                  << (open ? "ABIERTO" : "CERRADO") << '\n';
    }

    std::cout << "----------------------------\n"
              << "Resumen: " << open_count << " abierto(s) / "
              << ports.size() << " probado(s)\n";
    return 0; // Finalización exitosa del escaneo
#endif
}

}// namespace edusec::netscan_module
