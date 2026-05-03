class RuleBlocker:
    """Interfaz base para reglas de bloqueo de paquetes.

    Cada método recibe el valor del campo a filtrar. Las subclases
    implementan cómo aplicar ese filtro (flow entry en OpenFlow,
    comparación en memoria para tests, etc.).
    """

    def filter_by_src_mac(self, mac):
        pass

    def filter_by_dst_mac(self, mac):
        pass

    def filter_by_src_ip(self, ip):
        pass

    def filter_by_dst_ip(self, ip):
        pass

    def filter_by_src_port(self, port):
        pass

    def filter_by_dst_port(self, port):
        pass

    def filter_by_protocol(self, protocol):
        pass

    def filter_by_red_protocol(self, red_protocol):
        pass
