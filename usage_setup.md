# Setup y uso

## Dependencias

### Python 2.7 (requerido por POX)

```bash
sudo apt update
sudo apt install build-essential libncursesw5-dev libssl-dev \
    libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev

wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
tar -xvf Python-2.7.18.tgz
cd Python-2.7.18
./configure --enable-optimizations
make
sudo make install
```

### Entorno virtual con Python 2.7

```bash
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
sudo python2.7 get-pip.py
pip2 install virtualenv
virtualenv -p python2.7 tp2_env
source tp2_env/bin/activate
```

> POX también funciona con Python 3 clonando el repo directamente.

---

## Levantar el controlador POX con el firewall

```bash
./run_pox          # sin verbose
./run_pox -v       # con verbose (muestra todos los eventos)
```

Internamente ejecuta:
```bash
cd pox
python pox.py samples.spanning_tree redes.tp2.firewall
```

El módulo `redes.tp2` debe ser un symlink al directorio del TP dentro de `pox/pox/`:
```bash
mkdir pox/pox/redes
ln -s <ruta_al_tp> pox/pox/redes/tp2
```

---

## Levantar Mininet

```bash
./run_mn              # topología con 0 switches intermedios (default)
./run_mn 3            # topología con 3 switches intermedios
./run_mn -h           # ayuda
```

Internamente ejecuta:
```bash
sudo mn --custom ./dynamic_topology.py \
        --topo dynamicTopology,<N> \
        --mac --arp --switch ovsk --controller remote
```

---

## Correr simulaciones con iperf3

### Usando el runner automatizado

```bash
sudo python run_simulation.py -n 0 -s tcp
sudo python run_simulation.py -n 0 -s udp
sudo python run_simulation.py -n 0 -s port_80
sudo python run_simulation.py -n 0 -s mutual_exclude
sudo python run_simulation.py -n 0 -s not_switch
```

### Manualmente con parámetros

```bash
sudo python run_simulation.py -n 2 -H h1 -C h4 -p 5200 --tcp
sudo python run_simulation.py -n 2 -H h1 -C h4 -p 5001 --udp
```

### Comandos directos desde la CLI de Mininet

**Exclusión mutua (tráfico bloqueado entre h1 y h4):**
```
mininet> xterm h1 h4
# En h1:
iperf3 -s -p 5200
# En h4:
iperf3 -c 10.0.0.1 -p 5200
```

**Bloqueo por puerto de destino 80:**
```
mininet> xterm h1 h2
# En h1:
iperf3 -s -p 80
# En h2:
iperf3 -c 10.0.0.1 -p 80
```

**Bloqueo UDP en puerto 5001:**
```
mininet> xterm h1 h3
# En h1:
iperf3 -s -p 5001
# En h3:
iperf3 -c 10.0.0.1 -p 5001 -u
```

**Tráfico no bloqueado (entre h3 y h4, fuera del switch objetivo):**
```
mininet> xterm h3 h4
# En h3:
iperf3 -s -p 5200
# En h4:
iperf3 -c 10.0.0.3 -p 5200
```

---

## Correr tests unitarios

Sin dependencias externas (no requiere POX ni Mininet):

```bash
cd <directorio_del_tp>
python test_runner.py        # resultado por test
python test_runner.py -v     # verbose: muestra qué condición evaluó cada regla
```

---

## Captura con Wireshark

Desde la CLI de Mininet:
```
mininet> s1 wireshark &
```

Filtro útil en Wireshark para tráfico UDP desde 10.0.0.1:
```
ip && udp && ip.src == 10.0.0.1
```
