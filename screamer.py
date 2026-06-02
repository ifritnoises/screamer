#!/usr/bin/env python3

import argparse
import logging
import ipaddress
import os
import sys
from scapy.all import conf
from colorama import Fore, Style, init
from modules import passive
from modules import active
import time

# mute scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0
# mute colorama
init(autoreset=True)


# print banner and contact information
def banner():
    ascii_art = r"""
   _____                                         
  ╱  ___│                                        
  ╲ `──.  ___ _ __ ___  __ _ _ __ ___   ___ _ __ 
   `──. ╲╱ __│ '__╱ _ ╲╱ _` │ '_ ` _ ╲ ╱ _ ╲ '__│
  ╱╲__╱ ╱ (__│ │ │  __╱ (_│ │ │ │ │ │ │  __╱ │   
  ╲____╱ ╲___│_│  ╲___│╲__,_│_│ │_│ │_│╲___│_│  v0.1.1
"""
    print(ascii_art)
    print("  Fast Subnet Discovery")
    print("  Made by: Ifrit")
    print("  Contact: contact@ifritnoises.org\n")
    

def require_root():
    if os.geteuid() != 0:
        print(Fore.RED + "[*] Root privileges required")
        sys.exit(1)


# slices large masks into /24 
def expand_targets(cidr, host_positions):
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen == 32:
        raise SystemExit(Fore.RED + "[!] Single host given; tool works on CIDR ranges. Use traceroute/mtr for one host")
    if network.prefixlen <= 24:
        subnets = network.subnets(new_prefix=24)
    else:
        subnets = [network]
    targets = []
    for subnet in subnets:
        for position in host_positions:
            try:
                targets.append(str(subnet[position]))
            except IndexError:
                pass
    return targets


# active mode
def run_active(args):
    require_root()
    # counting 
    active.sent = 0
    # --tunnel
    if args.tunnel:
        active.USE_L3_RAW = True
    from concurrent.futures import ThreadPoolExecutor, as_completed
    if args.method in ("tcp", "udp") and args.dport is None:
        raise SystemExit("--dport is required for method " + args.method)

    host_positions = [int(p) for p in args.positions.split(",")]
    targets = expand_targets(args.range, host_positions)

    print(Style.BRIGHT + "  [ ACTIVE MODE ]\n")
    print(Fore.WHITE + "[*] Target: " + args.range)
    print(Fore.WHITE + "[*] Method: " + args.method)
    print(Fore.WHITE + "[*] Max TTL: " + str(args.max_ttl))
    print(Fore.WHITE + "[*] Threads: " + str(args.threads))

    t0 = time.perf_counter()
    # multithreaded probes (after pressing CTRL+C, it will wait for the thread to finish and save the .dot file)
    try:
        for ttl in range(1, args.max_ttl + 1):
            active_targets = []
            for target_ip in targets:
                if target_ip not in active.done:
                    active_targets.append(target_ip)

            print()
            print("[*] Trying TTL=" + str(ttl))
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(active.send_probe, target_ip, ttl, args.method, args.dport) for target_ip in active_targets]
                for future in as_completed(futures):
                    future.result()
    except KeyboardInterrupt:
        print()
        print(Fore.YELLOW + "[!] Interrupted, exiting...")

    elapsed = time.perf_counter() - t0

    print()
    print("[*] Unique hops found: " + str(len(active.discovered_hops)))
    print("[*] Probes sent: " + str(active.sent) + " across " + str(len(targets)) + " targets")
    print("[*] Elapsed: " + str(round(elapsed, 1)) + "s " + "(threads=" + str(args.threads) + ", method=" + args.method + ", max_ttl=" + str(args.max_ttl) + ")\n")

    # generate .dot graph
    if args.out_dot:
        active.write_dot_graph(args.out_dot)

    # subnets listing
    subnets = sorted({ipaddress.ip_network(ip + "/24", strict=False) for ip in active.done})
    print(Fore.GREEN + "[*] Suggested subnets:")
    for net in subnets:
        print("    " + str(net))

    if args.out_subnets:
        with open(args.out_subnets, "w") as f:
            f.write("\n".join(str(net) for net in subnets) + "\n")


# passive mode, sniffing + parsing 
def run_passive(args):
    print(Style.BRIGHT + "  [ PASSIVE MODE ]\n" + Style.RESET_ALL)
    if args.iface:
        require_root()
        print(Fore.WHITE + "[*] Interface: " + args.iface + "\n")
    else:
        print(Fore.WHITE + "[*] Pcap: " + args.pcap)
        print()
    passive.run(args)


def main():
    banner()
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # args for active mode
    parser_active = subparsers.add_parser("active", help="TTL-based tracing across subnets")
    parser_active.add_argument("range", help="Target CIDR")
    parser_active.add_argument("-m", "--method", choices=["icmp-echo", "icmp-timestamp", "tcp", "udp"], default="icmp-echo")
    parser_active.add_argument("--max-ttl", type=int, default=5, help="Trace depth in hops (default: 5)")
    parser_active.add_argument("--positions", default="1,254", help="Specify the host positions per /24, default: 1,254)")
    parser_active.add_argument("-t", "--threads", type=int, default=30, help="Number of threads, default: 30")
    parser_active.add_argument("--dport", type=int, default=None, help="Destination port for TCP or UDP")
    parser_active.add_argument("--tunnel", action="store_true", help="Use L3RawSocket for tracing in tunnels")
    parser_active.add_argument("--out-dot", default=None, help="Write topology graph to DOT file")
    parser_active.add_argument("--out-subnets", default=None, help="Write suggested subnets to file")

    # args for passive mode
    parser_passive = subparsers.add_parser("passive", help="Passive sniffing of broadcast/multicast traffic")
    src = parser_passive.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", default=None, help="Interface for live capture")
    src.add_argument("--pcap", default=None, help=".pcap file to parse (no root required)")
    parser_passive.add_argument("--output", default=None, help="Write matched packets to pcap (survives Ctrl+C)")
    parser_passive.add_argument("--timeout", type=int, default=None, help="Traffic sniffing timeout (auto-writes pcap if --output was not specified)")

    args = parser.parse_args()

    if args.mode == "active":
        run_active(args)
    elif args.mode == "passive":
        run_passive(args)

if __name__ == "__main__":
    main()