import os
import sys
import subprocess
import tempfile
import shutil
import time
import filecmp
import threading
import argparse

from dynamic_topology import DynamicTopology,DEF_NUM_SWITCHES

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink

INCLUDE_SERVER_STDOUT = True
INCLUDE_SERVER_STDERR = True

INCLUDE_CLIENT_STDERR = True
INCLUDE_CLIENT_STDOUT = True
CLIENT_TIMEOUT = 20

DEF_H_SERV = "h2"
DEF_H_CLIENT = "h3"

H_SERV = DEF_H_SERV
H_CLIENT = DEF_H_CLIENT

def run(intermediate_switches = DEF_NUM_SWITCHES, port = 5200, use_udp = False):
    topo = DynamicTopology(number_switches = intermediate_switches)
    net = Mininet(topo=topo)
    net.start()

    h_serv = net.get(H_SERV)
    h_cliente = net.get(H_CLIENT)
    server_ip = h_serv.IP()

    server_proc = h_serv.popen(
        ["iperf3", "-s", "-p", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if INCLUDE_SERVER_STDOUT:
        stream_output(server_proc.stdout, "[SERVER STDOUT] ")
    if INCLUDE_SERVER_STDERR:
        stream_output(server_proc.stderr, "[SERVER STDERR] ")

    time.sleep(0.5)

    start_time = time.time()
    try:

        args = ["iperf3", "-c", server_ip, "-p", str(port)]

        if use_udp:
            args.append("-u")

        client_proc = h_cliente.popen( args,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE
        )

        
        if INCLUDE_CLIENT_STDOUT:
            stream_output(client_proc.stdout, "[CLIENT STDOUT] ")
        
        if INCLUDE_CLIENT_STDERR:
            stream_output(client_proc.stderr, "[CLIENT STDERR] ")

        client_proc.wait(timeout=CLIENT_TIMEOUT)
        shutdown(server_proc)
    finally:
        net.stop()

def shutdown(server):
    server.terminate()
    server.wait()

def stream_output(pipe, prefix=""):
    def stream():
        for line in iter(pipe.readline, b''):
            print(f"{prefix}{line.decode().rstrip()}")
    threading.Thread(target=stream, daemon=True).start()






def parse_arguments():
    parser = argparse.ArgumentParser(
        usage="run_simulation [ -h ] -n 3 [ -H h1 ] [ -C h4 ] [ -p PORT ] [-u | -t] \nor run_simulation [ -h ] -n 3 -s simulation\n"  # noqa: E501
        "Runs a mininet simulation"
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-t",
        "--tcp",
        action="store_true",
        help="use tcp",
    )

    verbosity.add_argument(
        "-u", "--udp", action="store_true", help="use udp"
    )
    parser.add_argument(
        "-n", "--switches", required = True, type=int, metavar="", help="Number of intermediate switches"
    )


    parser.add_argument(
        "-s", "--sim", default="", help="Select a simulation"
    )

    parser.add_argument(
        "-S", "--server_host", metavar="", default=DEF_H_SERV, help="server hostname"
    )
    parser.add_argument(
        "-C", "--client_host", metavar="", default=DEF_H_CLIENT, help="client hostname"
    )

    parser.add_argument(
        "-p", "--port", type=int, default=5200, metavar="", help="server port"
    )

    return parser.parse_args()



simulaciones = {
    "tcp": {
        "client_host": "h2",
        "server_host": "h3",
        "port":5001,
    },
    "udp": {
        "client_host": "h2",
        "server_host": "h3",
        "use_udp":True,
        "port":5001,
    },
    "port_80": {
        "port":80,
    },
    "mutual_exclude": {
        "client_host": "h1",
        "server_host": "h4"
    },
    "not_switch": {
        "client_host": "h3",
        "server_host": "h4",
    },
}

def load_sim(name, config):
    sim = simulaciones.get(name, None)

    if sim != None:
        for itm in sim:
            print(">Set",itm, sim[itm])
            config[itm] = sim[itm]
    else:
        print("NOT FOUND SIMULATION ", name)

if __name__ == '__main__':
    args = parse_arguments()

    config = {
        "client_host": DEF_H_CLIENT,
        "server_host": DEF_H_SERV,
        "use_udp": False,
        "port": 5200,
        "intermediate_switches": 0,
    }

    if args.sim != "":
        load_sim(args.sim, config)
    else:
        config["client_host"] = args.client_host
        config["server_host"] = args.server_host
        config["port"] = args.port
        config["use_udp"] = args.udp
        config["intermediate_switches"] = args.switches
    

    for itm in config:
        print(">Got",itm, config[itm])

    H_CLIENT = config["client_host"]
    H_SERV = config["server_host"]
    
    run(config["intermediate_switches"],config["port"], use_udp=config["use_udp"])
