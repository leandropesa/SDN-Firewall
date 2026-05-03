import os
import copy

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.revent import EventMixin
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import pox.openflow.libopenflow_01 as of

from . import rule_builder
from .dtos.rule_blocker import RuleBlocker
from . import verbose_packetin as utils

log = core.getLogger()


def _logger_debug(*args, **kwargs):
    fmt = " ".join(["%s"] * len(args))
    log.debug(fmt, *args)


def _logger_info(*args, **kwargs):
    fmt = " ".join(["%s"] * len(args))
    log.info(fmt, *args)


rule_builder.logger = log
utils.log_debug = _logger_debug
utils.log_info = _logger_info


MAP_RED_PROTOCOLS = {
    utils.IPV4_STR: utils.IPV4_TYPE,
    utils.IPV6_STR: utils.IPV6_TYPE,
}

MAP_TRANSPORT_PROTOCOLS = {
    utils.TCP_STR: utils.TCP_PROTOCOL,
    utils.UDP_STR: utils.UDP_PROTOCOL,
    utils.ICMP_STR: utils.ICMP_PROTOCOL,
}


class FlowRuleBlocker(RuleBlocker):
    """Implementación de RuleBlocker que genera flow entries de OpenFlow 1.0.

    Cada instancia representa una regla de bloqueo. Al llamar a
    add_to_connection() se envía la/s flow entry/ies al switch.
    """

    def __init__(self):
        self.fm = of.ofp_flow_mod()
        self.fm.priority = 100
        self.fm.idle_timeout = 0  # regla permanente
        self.fm.hard_timeout = 0  # regla permanente
        self.fm.match = of.ofp_match()
        self.fm.match.dl_type = utils.IPV4_TYPE  # IPv4 por defecto

        self.has_filter_port = False
        self.has_filter_protocol = False

    def is_ipv6(self):
        return self.fm.match.dl_type == utils.IPV6_TYPE

    def filter_by_src_mac(self, mac):
        try:
            self.fm.match.dl_src = EthAddr(mac)
            log.info("Filtro src mac: %s", mac)
        except Exception as e:
            log.warning("src mac inválida '%s': %s", mac, e)

    def filter_by_dst_mac(self, mac):
        try:
            self.fm.match.dl_dst = EthAddr(mac)
            log.info("Filtro dst mac: %s", mac)
        except Exception as e:
            log.warning("dst mac inválida '%s': %s", mac, e)

    def filter_by_src_ip(self, ip):
        try:
            self.fm.match.nw_src = IPAddr6(ip) if self.is_ipv6() else IPAddr(ip)
            log.info("Filtro src ip: %s", ip)
        except Exception as e:
            log.warning("src ip inválida '%s': %s", ip, e)

    def filter_by_dst_ip(self, ip):
        try:
            self.fm.match.nw_dst = IPAddr6(ip) if self.is_ipv6() else IPAddr(ip)
            log.info("Filtro dst ip: %s", ip)
        except Exception as e:
            log.warning("dst ip inválida '%s': %s", ip, e)

    def filter_by_src_port(self, port):
        log.info("Filtro src port: %s", port)
        self.fm.match.tp_src = port
        self.has_filter_port = True

    def filter_by_dst_port(self, port):
        log.info("Filtro dst port: %s", port)
        self.fm.match.tp_dst = port
        self.has_filter_port = True

    def filter_by_protocol(self, protocol):
        code = MAP_TRANSPORT_PROTOCOLS.get(protocol)
        if code is not None:
            log.info("Filtro protocolo transporte: %s (%d)", protocol, code)
            self.fm.match.nw_proto = code
            self.has_filter_protocol = True
        else:
            log.warning("Protocolo de transporte desconocido: %s", protocol)

    def filter_by_red_protocol(self, red_protocol):
        code = MAP_RED_PROTOCOLS.get(red_protocol)
        if code is not None:
            log.info("Filtro protocolo red: %s (0x%04x)", red_protocol, code)
            self.fm.match.dl_type = code
        else:
            log.warning("Protocolo de red desconocido: %s", red_protocol)

    def add_to_connection(self, connection):
        """Envía la flow entry al switch.

        En OpenFlow 1.0, para filtrar por puerto es obligatorio especificar
        el protocolo de transporte (nw_proto). Si la regla tiene puerto pero
        no protocolo, se instalan dos entries: una para TCP y otra para UDP.
        Si la regla usa IPv6, los filtros de puerto/protocolo son incompatibles
        con esta versión de OpenFlow y se omiten con una advertencia.
        """
        if (self.has_filter_port or self.has_filter_protocol) and self.is_ipv6():
            log.warning(
                "Filtro de puerto/protocolo incompatible con IPv6 en OpenFlow 1.0. "
                "La regla no será instalada."
            )
            return

        if self.has_filter_protocol or not self.has_filter_port:
            connection.send(self.fm)
            return

        log.info("Protocolo de transporte no especificado; instalando regla para TCP y UDP")

        fm_tcp = copy.deepcopy(self.fm)
        fm_tcp.match.nw_proto = utils.TCP_PROTOCOL
        connection.send(fm_tcp)

        fm_udp = copy.deepcopy(self.fm)
        fm_udp.match.nw_proto = utils.UDP_PROTOCOL
        connection.send(fm_udp)


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

FIREWALL_RULES = []
TARGET_SWITCHES = []


class Firewall(EventMixin):
    """Controlador de firewall para un switch OpenFlow específico.

    Al instanciarse instala todas las reglas de bloqueo en la conexión
    dada. Los PacketIn subsiguientes se logean en modo verbose para
    facilitar el debugging.
    """

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        log.info("Instalando %d regla(s) en switch %s", len(FIREWALL_RULES), connection)
        for rule in FIREWALL_RULES:
            rule.add_to_connection(connection)

    def _handle_PacketIn(self, event):
        utils.verbose_packetin(event)


def _is_target(dpid_str):
    return dpid_str in TARGET_SWITCHES


def launch():
    """Punto de entrada de POX. Carga la configuración e instala listeners."""
    global FIREWALL_RULES

    FIREWALL_RULES = rule_builder.load_config(
        CONFIG_PATH, TARGET_SWITCHES, FlowRuleBlocker
    )

    log.info("Switches objetivo: %s", TARGET_SWITCHES)
    log.info("Reglas cargadas: %d", len(FIREWALL_RULES))

    def start_switch(event):
        dpid_str = dpid_to_str(event.dpid)
        if _is_target(dpid_str):
            log.info("Conectando firewall a switch: %s", event.connection)
            Firewall(event.connection)
        else:
            log.info("Switch %s no es objetivo, ignorando", dpid_str)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
