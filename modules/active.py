#!/usr/bin/env python3

import threading
from scapy.all import IP, ICMP, TCP, UDP, sr1, RandShort
from colorama import Fore, Style
from scapy.supersocket import L3RawSocket

# shared state
discovered_hops = set()

# target_ip -> {ttl: responder_ip}
traces = {}
traces_lock = threading.Lock()

# for packets which reached dst
done = set()

# from screamer.py by --tunnel flag
USE_L3_RAW = False
# each L3RawSocket at the thread 
raw_sockets = threading.local()


def send_recv(packet):
    if not USE_L3_RAW:
        return sr1(packet, timeout=1, verbose=0)
    sock = getattr(raw_sockets, "sock", None)
    if sock is None:
        sock = raw_sockets.sock = L3RawSocket()
    return sock.sr1(packet, timeout=1, verbose=0)


# ICMP echo (type 8)
def probe_icmp_echo(target_ip, ttl):
    packet = IP(dst=target_ip, ttl=ttl) / ICMP(type=8)
    reply = send_recv(packet)
    if reply is None or not reply.haslayer(ICMP):
        return None, False
    if reply[ICMP].type == 0: # Echo Reply
        return reply.src, True
    elif reply[ICMP].type == 11: # Time Exceeded
        return reply.src, False
    return None, False


# ICMP timestamp (type 13)
def probe_icmp_timestamp(target_ip, ttl):
    packet = IP(dst=target_ip, ttl=ttl) / ICMP(type=13)
    reply = send_recv(packet)
    if reply is None or not reply.haslayer(ICMP):
        return None, False
    if reply[ICMP].type == 14: # Timestamp Reply
        return reply.src, True
    elif reply[ICMP].type == 11: # Time Exceeded
        return reply.src, False
    return None, False


# TCP SYN
def probe_tcp(target_ip, ttl, dport):
    packet = IP(dst=target_ip, ttl=ttl) / TCP(sport=RandShort(), dport=dport, flags="S")
    reply = send_recv(packet)
    if reply is None:
        return None, False
    if reply.haslayer(TCP): # Expecting TCP ACK or TCP RST
        return reply[IP].src, True
    elif reply[ICMP].type == 11: # Time Exceeded
        return reply.src, False 
    return None, False


# UDP datagram
def probe_udp(target_ip, ttl, dport):
    packet = IP(dst=target_ip, ttl=ttl) / UDP(sport=RandShort(), dport=dport)
    reply = send_recv(packet)
    if reply is None or not reply.haslayer(ICMP):
        return None, False
    if reply[ICMP].type == 3: # ICMP destination unreachable (type 3, code 3)
        return reply.src, True
    elif reply[ICMP].type == 11: # Time Exceeded
        return reply.src, False
    return None, False


# Probes dictionary
probes = {
    "icmp-echo": probe_icmp_echo,
    "icmp-timestamp": probe_icmp_timestamp,
    "tcp": probe_tcp,
    "udp": probe_udp,
}


# Send probes and build the traces (with .setdefault)
def send_probe(target_ip, ttl, method_name, dport):
    probe_fn = probes[method_name]
    if method_name in ("tcp", "udp") and dport is not None:
        responder_ip, reached = probe_fn(target_ip, ttl, dport)
    else:
        responder_ip, reached = probe_fn(target_ip, ttl)
    if responder_ip is None:
        return
    with traces_lock:
        traces.setdefault(target_ip, {})[ttl] = responder_ip
        if responder_ip not in discovered_hops:
            discovered_hops.add(responder_ip)
            print(Fore.GREEN + "[+] Detected Hop: " + Style.RESET_ALL + responder_ip)
        if reached:
            done.add(target_ip)
            

# Build the graph
def write_dot_graph(filename):
    # Build a DOT topology graph from collected traces
    edges = set()
    for hops_by_ttl in traces.values():
        previous_node = "Screamer"
        for ttl in sorted(hops_by_ttl):
            current_node = hops_by_ttl[ttl]
            # same IP can answer on multiple TTLs, skip self-loops
            if previous_node != current_node:
                edges.add((previous_node, current_node))
            previous_node = current_node

    with open(filename, "w") as f:
        f.write("digraph hops {\n")
        f.write("  rankdir=LR;\n")
        f.write('  bgcolor="black";\n')
        f.write('  node [shape=box, style=rounded, fontname="monospace", color=white, fontcolor=white];\n')
        f.write('  edge [color=white];\n')
        f.write('  "Screamer" [shape=ellipse, style=filled, fillcolor=white, fontcolor=black];\n')
        for edge_from, edge_to in sorted(edges):
            f.write('  "' + edge_from + '" -> "' + edge_to + '";\n')
        f.write("}\n")
    print(Fore.WHITE + "[*] DOT graph written: " + filename)