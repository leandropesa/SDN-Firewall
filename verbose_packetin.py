from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from .dtos import packet as dtos

def log_debug(*args, **kwargs):
    pass

def log_info(*args, **kwargs):
    pass


TCP_STR = "tcp"
UDP_STR = "udp"
ICMP_STR = "icmp"

IPV4_STR = "ipv4"
IPV6_STR = "ipv6"

IPV4_TYPE = 0x0800
IPV6_TYPE = 0x86DD

TCP_PROTOCOL = 6
UDP_PROTOCOL = 17
ICMP_PROTOCOL = 1
ICMPV6_PROTOCOL = 58
GRE_PROTOCOL = 47
ESP_PROTOCOL = 50
AH_PROTOCOL = 51


def _is_passthrough_protocol(proto_num):
    """Devuelve True para protocolos que no deben ser bloqueados por el firewall
    (ICMP y similares se dejan pasar sin analizar puertos)."""
    return proto_num in (ICMP_PROTOCOL, ICMPV6_PROTOCOL)


def _load_l4(dto_packet, ip_packet):
    """Extrae información de capa 4 (TCP/UDP) del paquete IP.

    Returns:
        True si el paquete debe ser procesado, False si debe ignorarse.
    """
    l4 = ip_packet.find(TCP_STR)
    if l4:
        dto_packet.protocol = TCP_STR
    else:
        l4 = ip_packet.find(UDP_STR)
        if l4:
            dto_packet.protocol = UDP_STR

    if l4:
        dto_packet.src.port = l4.srcport
        dto_packet.dst.port = l4.dstport
        return True

    proto = getattr(ip_packet, "protocol", getattr(ip_packet, "nxt", None))
    if proto is not None and _is_passthrough_protocol(proto):
        log_debug("Dejando pasar protocolo permitido: %s", proto)
        return True

    log_info("Paquete sin capa TCP/UDP ignorado, proto=%s", proto)
    return False


def _load_ipv4_info(dto_packet, ip):
    dto_packet.red_protocol = IPV4_STR
    dto_packet.src.ip = ip.srcip
    dto_packet.dst.ip = ip.dstip
    return _load_l4(dto_packet, ip)


def _load_ipv6_info(dto_packet, ip):
    dto_packet.red_protocol = IPV6_STR
    dto_packet.src.ip = ip.srcip
    dto_packet.dst.ip = ip.dstip
    return _load_l4(dto_packet, ip)


def _parse_ip(dto_packet, eth_packet):
    """Intenta parsear IPv4; si no, IPv6.

    Returns:
        True si se pudo parsear y el paquete debe procesarse.
    """
    ip = eth_packet.find("ipv4")
    if ip:
        return _load_ipv4_info(dto_packet, ip)

    ip = eth_packet.find("ipv6")
    if ip:
        return _load_ipv6_info(dto_packet, ip)

    return False


def verbose_packetin(event):
    """Parsea un evento PacketIn y loguea la información del paquete."""
    eth = event.parsed
    dto = dtos.PacketData()

    dto.src.mac = str(eth.src)
    dto.dst.mac = str(eth.dst)

    if not _parse_ip(dto, eth):
        if dto.red_protocol is None:
            log_debug(
                "Paquete no IPv4/IPv6: tipo=%s",
                ethernet.getNameForType(eth.type),
            )
        return

    if dto.protocol is not None:
        log_info("Paquete permitido: %s", dto)
