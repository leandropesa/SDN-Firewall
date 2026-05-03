# SDN Firewall sobre OpenFlow

Implementación de un firewall programable sobre **Software Defined Networking** usando OpenFlow 1.0, desarrollada para la materia **Redes** de FIUBA.

El firewall instala *flow entries* permanentes en switches OpenFlow virtuales (Mininet) a través del controlador POX, bloqueando tráfico según reglas declarativas definidas en JSON.

---

### Video de demostración

> La terminal izquierda muestra el controlador POX logueando el tráfico en tiempo real.
> La derecha muestra la CLI de Mininet donde se ejecutan tres comandos: `pingall`
> (prueba conectividad entre todos los hosts), `h1 ping -c3 h4` (bloqueado por regla
> bidireccional, 100% packet loss) y `h2 ping -c3 h3` (fluye normalmente, 0% packet loss,
> 3 paquetes recibidos). El resultado `h1 -> h2 h3 X` y `h4 -> X h2 h3` en el pingall
> confirman que el firewall está bloqueando correctamente el tráfico entre h1 y h4.

---

## Arquitectura

```
config.json
    │
    ▼
rule_builder.py ──── Parsea reglas JSON y las aplica a cualquier RuleBlocker
    │
    ├─► FlowRuleBlocker  ──► flow entries en switches OpenFlow  (producción)
    └─► PacketBlockRule  ──► comparación en memoria             (tests)

firewall.py  ──── Controlador POX: escucha ConnectionUp e instala reglas
verbose_packetin.py ── Parsea PacketIn y loguea tráfico observado
dynamic_topology.py ── Topología Mininet configurable
```

### Separación producción / test

`PacketBlockRule` (en `dtos/packet.py`) replica la semántica de bloqueo sin depender de POX ni Mininet. Esto permite correr la suite de tests en cualquier máquina con Python puro, sin infraestructura de red.

---

## Estructura del proyecto

```
├── firewall.py           # Controlador POX principal
├── rule_builder.py       # Parser de reglas JSON → RuleBlocker
├── verbose_packetin.py   # Parser de PacketIn para logging
├── dynamic_topology.py   # Topología Mininet dinámica
├── run_simulation.py     # Runner de simulaciones con iperf3
├── run_mn                # Script para levantar Mininet
├── run_pox               # Script para levantar POX
├── config.json           # Reglas y switches objetivo por defecto
├── dtos/
│   ├── rule_blocker.py   # Interfaz base RuleBlocker
│   └── packet.py         # PacketData, VerbosePacket, PacketBlockRule
├── test_rules/           # JSONs de reglas para los tests unitarios
│   ├── simple_connection_rule.json
│   ├── dest_port_rule.json
│   ├── traffic_between_hosts.json
│   ├── general_rules.json
│   ├── caso_borde_1.json
│   └── caso_borde_1_no_bidireccional.json
└── test_runner.py        # Suite de tests unitarios (unittest)
```

---

## Formato de reglas (JSON)

Cada regla es un objeto con campos opcionales. Una regla bloquea un paquete si **todos** sus campos coinciden (lógica AND).

```json
{
  "mac_src":      "00:00:00:00:00:01",
  "mac_dst":      "00:00:00:00:00:04",
  "ip_src":       "10.0.0.1",
  "ip_dst":       "10.0.0.2",
  "src_port":     5001,
  "dst_port":     80,
  "protocol":     "tcp",
  "red_protocol": "ipv4",
  "bidireccional": true
}
```

El campo `bidireccional: true` genera automáticamente una segunda regla con src y dst intercambiados.

### Configuración principal (`config.json`)

```json
{
  "target_switches": ["00-00-00-00-00-01"],
  "block_rules": [ ... ]
}
```

`target_switches` indica en qué switches se instalan las reglas (por DPID). El resto de switches dejan pasar el tráfico sin modificar.

---

## Topología

```
h1 ─┐                              ┌─ h3
    s1 ── [s2 ── s3 ── ... ── sN] ── sLast
h2 ─┘                              └─ h4
```

El número de switches intermedios es configurable. El firewall se instala únicamente en `s1` (configurable en `config.json`).

---

## Requisitos

- Linux (Ubuntu 20.04 recomendado)
- [POX](https://github.com/noxrepo/pox) (controlador OpenFlow)
- [Mininet](http://mininet.org/)
- Python 2.7 (para POX) o Python 3 (rama `eel` de POX)
- `iperf3` para las simulaciones

Ver [usage_setup.md](usage_setup.md) para instrucciones de instalación detalladas.

---

## Uso rápido

### 1. Levantar el controlador

```bash
./run_pox        # sin verbose
./run_pox -v     # con verbose
```

### 2. Levantar Mininet (en otra terminal)

```bash
./run_mn         # 0 switches intermedios
./run_mn 3       # 3 switches intermedios
```

### 3. Probar desde la CLI de Mininet

```
mininet> h1 ping h4        # debería fallar (regla bidireccional)
mininet> h2 ping h3        # debería funcionar
mininet> h1 iperf3 -s -p 80 &
mininet> h2 iperf3 -c 10.0.0.1 -p 80    # bloqueado por regla de puerto 80
```

---

## Tests unitarios

No requieren POX ni Mininet:

```bash
python test_runner.py      # resultado por test
python test_runner.py -v   # verbose: detalle de cada condición evaluada
```

### Casos cubiertos

| Test | Descripción |
|------|-------------|
| `test_01` | Bloqueo por protocolo de transporte (TCP) |
| `test_02` | Bloqueo por puerto de destino |
| `test_03` | Bloqueo bidireccional entre dos hosts |
| `test_04` | Bloqueo de cualquier origen hacia un puerto |
| `test_05` | Caso con múltiples condiciones y bidireccionalidad |
| `test_06` | Mismo caso sin bidireccionalidad (unidireccional) |

---

## Detalle técnico: OpenFlow 1.0 y filtros de puerto

En OpenFlow 1.0, para filtrar por puerto de transporte (`tp_src`/`tp_dst`) es **obligatorio** especificar el protocolo (`nw_proto`). Si una regla define un puerto pero no el protocolo, el firewall instala automáticamente **dos** flow entries: una para TCP y otra para UDP. Si el protocolo es IPv6, los filtros de puerto son incompatibles con esta versión de OpenFlow y se omiten con una advertencia en el log.
