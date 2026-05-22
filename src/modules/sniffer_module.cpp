/**
* sniffer_module.cpp
* Implementación del Sniffer de red basado en AF_PACKET.
* details: Realiza una captura pasiva de tramas Ethernet utilizando sockets crudos
* (RAW sockets). Procesa encabezados IP/TCP/UDP para extraer direcciones IP únicas
* observadas en el segmento. Requiere privilegios de root para operar.
*/
#include "modules/sniffer_module.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>

#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#define EDUSEC_HAS_AF_PACKET 1
#else
#define EDUSEC_HAS_AF_PACKET 0
#endif

namespace edusec::sniffer_module {

#if EDUSEC_HAS_AF_PACKET

namespace {
/**
* Convierte una dirección IP de red a formato string legible.
* addr_net_order- Dirección en formato network-byte-order.
* return std::string Representación decimal punteada.
*/
std::string ip_to_str(std::uint32_t addr_net_order) {
    char buf[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_net_order, buf, sizeof(buf));
    return buf;
}
//Mapeo técnico de constantes numéricas de protocolos a cadenas de texto descriptivas
std::string proto_name(std::uint8_t p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: {
            std::ostringstream o;
            o << "IPproto=" << int(p);
            return o.str();
        }
    }
}
// Analiza e interpreta byte a byte (Parsing) el buffer de la trama capturada
bool process_packet(const std::uint8_t* data, std::size_t len, int idx,
                    std::set<std::string>& seen_ips) {
    if (len < sizeof(ethhdr) + sizeof(iphdr)) return false;
    const auto* eth = reinterpret_cast<const ethhdr*>(data);
    // ntohs (Network to Host Short): Convierte el EtherType del orden de bytes de la red (Big-Endian) al de la CPU (Little-Endian)
    // Se valida si el EtherType corresponde estrictamente a tráfico IPv4 (0x0800)
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        std::cout << "#" << idx << "  non-IPv4 (eth_proto=0x"
                  << std::hex << ntohs(eth->h_proto) << std::dec << ")\n";
        return false;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(data + sizeof(ethhdr));
    // El campo ihl (Internet Header Length) indica la cantidad de palabras de 32 bits que mide la cabecera IP.
    // Se multiplica por 4 para obtener el tamaño real en bytes (Útil para omitir el campo dinámico "Options" de IP).
    const std::size_t ip_hdr_len = ip->ihl * 4;
    const std::string src = ip_to_str(ip->saddr);
    const std::string dst = ip_to_str(ip->daddr);
    seen_ips.insert(src);
    seen_ips.insert(dst);

    std::cout << "#" << idx << "  " << src << " -> " << dst
              << "  " << proto_name(ip->protocol);
    // Verificación de Capa 4 (Transporte): Procesamiento específico si el payload transporta un segmento TCP
    if (ip->protocol == IPPROTO_TCP && len >= sizeof(ethhdr) + ip_hdr_len + sizeof(tcphdr)) {
        const auto* tcp = reinterpret_cast<const tcphdr*>(
            data + sizeof(ethhdr) + ip_hdr_len);
        // Extracción y conversión de los puertos de red
        std::cout << "  sport=" << ntohs(tcp->source)
                  << "  dport=" << ntohs(tcp->dest);
        std::cout << "  flags=";
        //Evaluación de las banderas lógicas del bitmask TCP que determinan el estado de la conexión
        if (tcp->syn) std::cout << "S";
        if (tcp->ack) std::cout << "A";
        if (tcp->fin) std::cout << "F";
        if (tcp->rst) std::cout << "R";
        if (tcp->psh) std::cout << "P";
    } else if (ip->protocol == IPPROTO_UDP &&
               len >= sizeof(ethhdr) + ip_hdr_len + sizeof(udphdr)) {
        const auto* udp = reinterpret_cast<const udphdr*>(
            data + sizeof(ethhdr) + ip_hdr_len);
        std::cout << "  sport=" << ntohs(udp->source)
                  << "  dport=" << ntohs(udp->dest);
    }

    std::cout << "  bytes=" << len << '\n';
    return true;
}

}
// Punto de entrada del flujo de ejecución del módulo de captura
int run(const std::vector<std::string>& args) {
    int max_packets = 20; //Valor por defecto
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--count") {
            try {
                max_packets = std::stoi(args[i + 1]);
                if (max_packets <= 0) max_packets = 20;
            } catch (...) {}
        }
    }
    // Apertura de Socket Crudo (RAW Socket) en la familia AF_PACKET para interceptar datos directamente de la tarjeta de red (Capa 2)
    // SOCK_RAW: Mantiene intacta la cabecera Ethernet del enlace.
    // htons(ETH_P_ALL): Captura de forma promiscua todos los protocolos soportados a nivel de tramas de red.
    int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[!] socket(AF_PACKET) fallo: " << std::strerror(errno) << '\n'
                  << "    Requiere CAP_NET_RAW. Ejecuta con sudo.\n";
        return 1;
    }

    std::cout << "[sniffer] Capturando " << max_packets
              << " paquetes (Ctrl-C aborta)\n"
              << "------------------------------------------------------\n";

    std::set<std::string> seen_ips;
    std::uint8_t buf[2048];
    int captured = 0, ipv4_count = 0;
    while (captured < max_packets) {
        // Llamada bloqueante al sistema operativo esperando la llegada de una trama desde el driver de red (NIC)
        const ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            std::cerr << "[!] recv: " << std::strerror(errno) << '\n';
            break;
        }
        ++captured;
        if (process_packet(buf, static_cast<std::size_t>(n), captured, seen_ips)) {
            ++ipv4_count;
        }
    }
    //Liberación del descriptor de archivo del socket crudo, sacando a la interfaz de su estado de escucha
    ::close(sock);

    std::cout << "------------------------------------------------------\n"
              << "[sniffer] " << captured << " paquetes procesados ("
              << ipv4_count << " IPv4)\n"
              << "[sniffer] IPs unicas observadas (" << seen_ips.size() << "):\n";
    for (const auto& ip : seen_ips) {
        std::cout << "  - " << ip << '\n';
    }
    return 0;
}

#else  
// Fallback elegante para entornos no compatibles
int run(const std::vector<std::string>& ) {
    std::cerr << "[!] sniffer solo soportado en Linux (AF_PACKET).\n";
    return 1;
}

#endif

}  // namespace edusec::sniffer_module
