import json
import os
import logging

logger = logging.getLogger(__name__)


FIELD_SRC_MAC = "mac_src"
FIELD_DST_MAC = "mac_dst"
FIELD_SRC_IP = "ip_src"
FIELD_DST_IP = "ip_dst"
FIELD_SRC_PORT = "src_port"
FIELD_DST_PORT = "dst_port"
FIELD_PROTOCOL = "protocol"
FIELD_RED_PROTOCOL = "red_protocol"
FIELD_BIDIRECTIONAL = "bidireccional"

FIELD_TARGETS = "target_switches"
FIELD_RULES = "block_rules"


_DIRECT_FILTERS = {
    FIELD_PROTOCOL:     lambda rule, v: rule.filter_by_protocol(v),
    FIELD_RED_PROTOCOL: lambda rule, v: rule.filter_by_red_protocol(v),
    FIELD_SRC_MAC:      lambda rule, v: rule.filter_by_src_mac(v),
    FIELD_SRC_IP:       lambda rule, v: rule.filter_by_src_ip(v),
    FIELD_SRC_PORT:     lambda rule, v: rule.filter_by_src_port(v),
    FIELD_DST_MAC:      lambda rule, v: rule.filter_by_dst_mac(v),
    FIELD_DST_IP:       lambda rule, v: rule.filter_by_dst_ip(v),
    FIELD_DST_PORT:     lambda rule, v: rule.filter_by_dst_port(v),
}


_INVERTED_FILTERS = {
    FIELD_PROTOCOL:     lambda rule, v: rule.filter_by_protocol(v),
    FIELD_RED_PROTOCOL: lambda rule, v: rule.filter_by_red_protocol(v),
    FIELD_SRC_MAC:      lambda rule, v: rule.filter_by_dst_mac(v),
    FIELD_SRC_IP:       lambda rule, v: rule.filter_by_dst_ip(v),
    FIELD_SRC_PORT:     lambda rule, v: rule.filter_by_dst_port(v),
    FIELD_DST_MAC:      lambda rule, v: rule.filter_by_src_mac(v),
    FIELD_DST_IP:       lambda rule, v: rule.filter_by_src_ip(v),
    FIELD_DST_PORT:     lambda rule, v: rule.filter_by_src_port(v),
}


_FILTER_ORDER = [
    FIELD_PROTOCOL,
    FIELD_RED_PROTOCOL,
    FIELD_SRC_MAC,
    FIELD_SRC_IP,
    FIELD_SRC_PORT,
    FIELD_DST_MAC,
    FIELD_DST_IP,
    FIELD_DST_PORT,
]


class RuleBuilder:
    """Construye una regla de bloqueo a partir de un dict de constraints.

    Args:
        constraints: dict con los campos del JSON.
        invert: si True, intercambia src y dst (para reglas bidireccionales).
    """

    def __init__(self, constraints, invert=False):
        self.constraints = constraints
        self.invert = invert
        filters = _INVERTED_FILTERS if invert else _DIRECT_FILTERS

        self._checks = []
        for field in _FILTER_ORDER:
            value = constraints.get(field)
            if value is not None:
                apply_fn = filters[field]
                self._checks.append((apply_fn, value))

    def build_new(self, rule_constructor):
        """Instancia una regla nueva y le aplica todos los filtros."""
        rule = rule_constructor()
        for apply_fn, value in self._checks:
            apply_fn(rule, value)
        return rule


def _build_rules_from_spec(rules_spec, rule_constructor, verbose=False):
    """Construye una lista de reglas desde un array de dicts JSON.

    Args:
        rules_spec: lista de dicts con los campos de cada regla.
        rule_constructor: callable que devuelve un RuleBlocker vacío.
        verbose: si True, loguea cada regla creada.

    Returns:
        Lista de reglas construidas.
    """
    rules = []
    for spec in rules_spec:
        if verbose:
            logger.info("Creando regla: %s", spec)

        rules.append(RuleBuilder(spec).build_new(rule_constructor))

        if spec.get(FIELD_BIDIRECTIONAL, False):
            if verbose:
                logger.info("Agregando regla inversa para: %s", spec)
            rules.append(RuleBuilder(spec, invert=True).build_new(rule_constructor))

    if verbose:
        logger.info("Total de reglas cargadas: %d", len(rules))

    return rules


def load_rules(rules_file, rule_constructor):
    """Carga reglas desde un archivo JSON (array raíz).

    Args:
        rules_file: ruta al archivo JSON.
        rule_constructor: callable que devuelve un RuleBlocker vacío.

    Returns:
        Lista de reglas, o lista vacía si el archivo no existe.
    """
    if not os.path.isfile(rules_file):
        logger.warning("Archivo de reglas no encontrado: %s", rules_file)
        return []

    with open(rules_file, "r") as f:
        spec = json.load(f)

    return _build_rules_from_spec(spec, rule_constructor, verbose=True)


def load_rules_silent(rules_file, rule_constructor):
    """Igual que load_rules pero sin logging (útil para tests)."""
    if not os.path.isfile(rules_file):
        return []

    with open(rules_file, "r") as f:
        spec = json.load(f)

    return _build_rules_from_spec(spec, rule_constructor, verbose=False)


def load_config(config_file, targets, rule_constructor):
    """Carga configuración completa desde un JSON con target_switches y block_rules.

    Args:
        config_file: ruta al archivo de configuración.
        targets: lista mutable donde se agregarán los DPIDs objetivo.
        rule_constructor: callable que devuelve un RuleBlocker vacío.

    Returns:
        Lista de reglas cargadas, o lista vacía si el archivo no existe.
    """
    if not os.path.isfile(config_file):
        logger.warning("Archivo de configuración no encontrado: %s", config_file)
        return []

    with open(config_file, "r") as f:
        config = json.load(f)

    for target in config.get(FIELD_TARGETS, []):
        targets.append(str(target))

    return _build_rules_from_spec(
        config.get(FIELD_RULES, []), rule_constructor, verbose=True
    )
