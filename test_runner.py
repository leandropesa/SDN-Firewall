import sys
import unittest

import rule_builder
import dtos.packet as dtos


rule_builder.logger.disabled = True


def load_block_rules(file):
    return rule_builder.load_rules_silent(file, dtos.PacketBlockRule)


def packet_blocked(rules, packet):
    """Devuelve True si alguna regla bloquea el paquete."""
    return dtos.is_blocked_by(packet, rules)


def verbose_blocked(rules, packet):
    """Como packet_blocked pero imprime el detalle de cada condición evaluada."""
    for i, rule in enumerate(rules):
        blocked, logs = rule.should_block_verbose(packet)
        print("[INFO] CHECK RULE {} blocked: {}".format(i, blocked))
        for entry in logs:
            print("[INFO]", entry)
        print()
        if blocked:
            return True
    return False


PACKET_TYPE = dtos.PacketData
is_packet_blocked = packet_blocked

if "-v" in sys.argv:
    PACKET_TYPE = dtos.VerbosePacket
    is_packet_blocked = verbose_blocked
    sys.argv.remove("-v")


class BlockingTests(unittest.TestCase):

    def test_01_protocol_block_rule(self):
        """Regla que bloquea solo por protocolo TCP."""
        rules = load_block_rules("test_rules/simple_connection_rule.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertTrue(is_packet_blocked(rules, pkt), "TCP debería ser bloqueado")

        pkt.src = dtos.Peer("MAC4", 5004)
        self.assertTrue(is_packet_blocked(rules, pkt), "TCP debería ser bloqueado desde cualquier src")

        pkt.protocol = "udp"
        self.assertFalse(is_packet_blocked(rules, pkt), "UDP no debería ser bloqueado")

    def test_02_dest_port_block_rule(self):
        """Regla que bloquea por puerto de destino específico."""
        rules = load_block_rules("test_rules/dest_port_rule.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertFalse(is_packet_blocked(rules, pkt), "Puerto 5002 no debería ser bloqueado")

        pkt.dst.port = 5010
        self.assertTrue(is_packet_blocked(rules, pkt), "Puerto 5010 debería ser bloqueado")

    def test_03_traffic_between_hosts(self):
        """Regla bidireccional que bloquea tráfico entre dos MACs específicas."""
        rules = load_block_rules("test_rules/traffic_between_hosts.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertFalse(is_packet_blocked(rules, pkt), "MAC1→MAC2 no debería ser bloqueado")

        pkt.src = dtos.Peer("MAC2", 5001)
        pkt.dst = dtos.Peer("MAC5", 5002)
        self.assertTrue(is_packet_blocked(rules, pkt), "MAC2→MAC5 debería ser bloqueado")

        # Dirección inversa (bidireccional)
        pkt.src = dtos.Peer("MAC5", 5002)
        pkt.dst = dtos.Peer("MAC2", 5001)
        self.assertTrue(is_packet_blocked(rules, pkt), "MAC5→MAC2 debería ser bloqueado (bidireccional)")

    def test_04_from_host_to_port(self):
        """Regla que bloquea tráfico de cualquier origen hacia un puerto específico."""
        rules = load_block_rules("test_rules/general_rules.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertFalse(is_packet_blocked(rules, pkt), "Puerto 5002 no debería ser bloqueado")

        pkt.dst.port = 80
        self.assertTrue(is_packet_blocked(rules, pkt), "Puerto 80 debería ser bloqueado")

    def test_05_complex_case_bidirectional(self):
        """Caso con múltiples condiciones y bidireccionalidad."""
        rules = load_block_rules("test_rules/caso_borde_1.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertTrue(is_packet_blocked(rules, pkt), "Paquete debería ser bloqueado")

    def test_06_complex_case_unidirectional(self):
        """Mismo caso pero sin bidireccionalidad: solo bloquea en una dirección."""
        rules = load_block_rules("test_rules/caso_borde_1_no_bidireccional.json")

        pkt = PACKET_TYPE("tcp")
        pkt.src = dtos.Peer("MAC1", 5001)
        pkt.dst = dtos.Peer("MAC2", 5002)
        self.assertFalse(is_packet_blocked(rules, pkt), "Paquete no debería ser bloqueado (unidireccional)")


if __name__ == "__main__":
    print("Corriendo tests{}...".format(" en modo verbose" if PACKET_TYPE == dtos.VerbosePacket else ""))
    unittest.main(argv=[sys.argv[0]])
