from .rule_blocker import RuleBlocker


class Peer:
    def __init__(self, mac, port):
        self.mac = mac
        self.port = port
        self.ip = None

    def __repr__(self):
        if self.ip:
            return "mac:{0} ip:{1} port:{2}".format(self.mac, self.ip, self.port)
        return "mac:{0} port:{1}".format(self.mac, self.port)


class PacketData:
    def __init__(self, protocol=None):
        self.protocol = protocol
        self.red_protocol = None
        self.src = Peer(None, None)
        self.dst = Peer(None, None)

    def __repr__(self):
        return "red:{0} proto:{1}\nsrc=> {2}\ndst=> {3}".format(
            self.red_protocol, self.protocol, self.src, self.dst
        )

    def src_port_is(self, vl):
        return vl == self.src.port

    def dst_port_is(self, vl):
        return vl == self.dst.port

    def src_mac_is(self, vl):
        return vl == self.src.mac

    def dst_mac_is(self, vl):
        return vl == self.dst.mac

    def src_ip_is(self, vl):
        return vl == self.src.ip

    def dst_ip_is(self, vl):
        return vl == self.dst.ip

    def prot_is(self, vl):
        return vl == self.protocol

    def red_prot_is(self, vl):
        return vl == self.red_protocol


class BlockResult:
    """Resultado de evaluación de una condición en modo verbose."""

    def __init__(self, blocked, field, value, constraint):
        self.do_block = blocked
        self.log = (
            field
            + " '"
            + str(value)
            + "'"
            + (" is " if blocked else " is not ")
            + str(constraint)
        )

    def add_to(self, vec):
        vec.append(self.log)


class VerbosePacket(PacketData):
    """Versión de PacketData que devuelve BlockResult en cada comparación,
    permitiendo trazar exactamente qué condición bloqueó el paquete."""

    def __init__(self, protocol=None):
        super().__init__(protocol)

    def src_port_is(self, vl):
        return BlockResult(super().src_port_is(vl), "src port", self.src.port, vl)

    def dst_port_is(self, vl):
        return BlockResult(super().dst_port_is(vl), "dst port", self.dst.port, vl)

    def src_mac_is(self, vl):
        return BlockResult(super().src_mac_is(vl), "src mac", self.src.mac, vl)

    def dst_mac_is(self, vl):
        return BlockResult(super().dst_mac_is(vl), "dst mac", self.dst.mac, vl)

    def src_ip_is(self, vl):
        return BlockResult(super().src_ip_is(vl), "src ip", self.src.ip, vl)

    def dst_ip_is(self, vl):
        return BlockResult(super().dst_ip_is(vl), "dst ip", self.dst.ip, vl)

    def prot_is(self, vl):
        return BlockResult(
            super().prot_is(vl), "transport protocol", self.protocol, vl
        )

    def red_prot_is(self, vl):
        return BlockResult(
            super().red_prot_is(vl), "red protocol", self.red_protocol, vl
        )


class PacketBlockRule(RuleBlocker):
    """Regla de bloqueo que evalúa paquetes en memoria (usada en tests).

    Una regla bloquea un paquete si y solo si TODAS sus condiciones se
    cumplen (lógica AND). Una regla sin condiciones no bloquea nada.
    """

    def __init__(self):
        self.block_conditions = []

    def _add_check(self, check):
        self.block_conditions.append(check)

    def filter_by_src_mac(self, mac):
        self._add_check(lambda pkt, v=mac: pkt.src_mac_is(v))

    def filter_by_src_ip(self, ip):
        self._add_check(lambda pkt, v=ip: pkt.src_ip_is(v))

    def filter_by_src_port(self, port):
        self._add_check(lambda pkt, v=port: pkt.src_port_is(v))

    def filter_by_dst_mac(self, mac):
        self._add_check(lambda pkt, v=mac: pkt.dst_mac_is(v))

    def filter_by_dst_ip(self, ip):
        self._add_check(lambda pkt, v=ip: pkt.dst_ip_is(v))

    def filter_by_dst_port(self, port):
        self._add_check(lambda pkt, v=port: pkt.dst_port_is(v))

    def filter_by_protocol(self, protocol):
        self._add_check(lambda pkt, v=protocol: pkt.prot_is(v))

    def filter_by_red_protocol(self, red_protocol):
        self._add_check(lambda pkt, v=red_protocol: pkt.red_prot_is(v))

    def should_block(self, packet):
        if not self.block_conditions:
            return False
        return all(condition(packet) for condition in self.block_conditions)

    def should_block_verbose(self, packet):
        logs = []
        for condition in self.block_conditions:
            result = condition(packet)
            result.add_to(logs)
            if not result.do_block:
                return (False, logs)
        return (len(logs) > 0, logs)


def is_blocked_by(packet, rules):
    """Devuelve True si alguna regla bloquea el paquete."""
    return any(rule.should_block(packet) for rule in rules)
