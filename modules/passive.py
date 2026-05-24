#!/usr/bin/env python3

from colorama import Fore, init
from datetime import datetime
from scapy.all import sniff, ARP, IP, IPv6, UDP, Raw, PcapWriter, Ether, DHCP, BOOTP, DNS
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_RS, ICMPv6ND_RA
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Request, DHCP6_Advertise, DHCP6_Reply, DHCP6OptClientId, DUID_LLT, DUID_LL, DUID_EN
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPortID, CDPMsgPlatform
from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUPortID, LLDPDUChassisID

# mute default colorama
init(autoreset=True)

pcap_writer = None
seen = set()


def save(packet):
    if pcap_writer is not None:
        pcap_writer.write(packet)


def already_seen(key):
    if key in seen:
        return True
    seen.add(key)
    return False


# tag colours for protocols, lowkey similar to "responder -A"
TAG_ARP = Fore.CYAN + "[ARP]"
TAG_NDP = Fore.LIGHTBLUE_EX + "[NDP]"
TAG_CDP = Fore.GREEN + "[CDP]"
TAG_LLDP = Fore.YELLOW + "[LLDP]"
TAG_DHCP = Fore.MAGENTA + "[DHCP]"
TAG_DHCPv6 = Fore.LIGHTMAGENTA_EX + "[DHCPv6]"
TAG_MDNS = Fore.LIGHTGREEN_EX + "[mDNS]"
TAG_LLMNR = Fore.LIGHTYELLOW_EX + "[LLMNR]"
TAG_NBTNS = Fore.RED + "[NBT-NS]"
TAG_SSDP = Fore.LIGHTCYAN_EX + "[SSDP]"


def handle_arp(packet):
    # ARP: FF:FF:FF:FF:FF:FF
    if not packet.haslayer(ARP):
        return
    arp = packet[ARP]
    if arp.op == 1:
        key = ("ARP-req", arp.psrc, arp.hwsrc, arp.pdst)
        if already_seen(key):
            return
        print(TAG_ARP + " " + arp.psrc + " (" + arp.hwsrc + ") is looking for: " + arp.pdst)
    elif arp.op == 2:
        key = ("ARP-rep", arp.psrc, arp.hwsrc, arp.pdst, arp.hwdst)
        if already_seen(key):
            return
        print(TAG_ARP + " " + arp.psrc + " (" + arp.hwsrc + ") is at; reply to: " + arp.pdst + " (" + arp.hwdst + ")")
    else:
        return
    save(packet)


def handle_ssdp(packet):
    # SSDP is HTTP-like text over UDP/1900 (no scapy class avaliable)
    if not packet.haslayer(UDP):
        return
    if packet[UDP].dport != 1900 and packet[UDP].sport != 1900:
        return
    if not packet.haslayer(Raw):
        return

    payload = bytes(packet[Raw].load)
    lines = payload.split(b"\r\n")
    first_line = lines[0] if lines else b""

    method = None
    if first_line.startswith(b"M-SEARCH"):
        method = "M-SEARCH"
    elif first_line.startswith(b"NOTIFY"):
        method = "NOTIFY"
    elif first_line.startswith(b"HTTP/"):
        method = "RESPONSE"
    else:
        return  # UDP/1900 but not SSDP

    server = None
    for line in lines[1:]:
        if line.lower().startswith(b"server:"):
            server = line.split(b":", 1)[1].strip().decode(errors="replace")
            break

    src_ip = packet[IP].src if packet.haslayer(IP) else "?"

    key = ("SSDP", src_ip, method, server)
    if already_seen(key):
        return

    print(TAG_SSDP + " " + src_ip + " " + method + " Server=" + str(server))
    save(packet)


def handle_cdp(packet):
    # CDP: 01:00:0C:CC:CC:CC (SNAP: 2000)
    if not packet.haslayer(CDPv2_HDR):
        return

    device_id = None
    port_id = None
    platform = None
    for tlv in packet[CDPv2_HDR].msg:
        if isinstance(tlv, CDPMsgDeviceID):
            device_id = tlv.val.decode(errors="replace")
        elif isinstance(tlv, CDPMsgPortID):
            port_id = tlv.iface.decode(errors="replace")
        elif isinstance(tlv, CDPMsgPlatform):
            platform = tlv.val.decode(errors="replace")

    key = ("CDP", device_id, port_id)
    if already_seen(key):
        return

    print(TAG_CDP + " " + str(device_id) + " port " + str(port_id) + " (" + str(platform) + ")")
    save(packet)


def handle_lldp(packet):
    # LLDP: 01:80:C2:00:00:0E
    if not packet.haslayer(LLDPDU):
        return

    system_name = None
    port_id = None
    chassis_id = None
    # LLDP TLVs are stacked as payloads, walk them via payload chain
    layer = packet[LLDPDU]
    while layer is not None and isinstance(layer, LLDPDU):
        if isinstance(layer, LLDPDUSystemName):
            try:
                system_name = layer.system_name.decode(errors="replace")
            except AttributeError:
                system_name = str(layer.system_name)
        elif isinstance(layer, LLDPDUPortID):
            try:
                port_id = layer.id.decode(errors="replace")
            except AttributeError:
                port_id = str(layer.id)
        elif isinstance(layer, LLDPDUChassisID):
            try:
                chassis_id = layer.id.decode(errors="replace") if isinstance(layer.id, bytes) else str(layer.id)
            except AttributeError:
                chassis_id = str(layer.id)
        layer = layer.payload if layer.payload else None

    key = ("LLDP", system_name, port_id)
    if already_seen(key):
        return

    print(TAG_LLDP + " " + str(system_name) + " port " + str(port_id) + " (chassis " + str(chassis_id) + ")")
    save(packet)


def handle_dhcp(packet):
    # https://datatracker.ietf.org/doc/html/rfc2131
    # DHCPv4: BOOTP + DHCP options layer on UDP/67-68
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return

    bootp = packet[BOOTP]
    options = packet[DHCP].options

    msg_type = None
    hostname = None
    requested_ip = None
    for opt in options:
        if not isinstance(opt, tuple):
            continue
        name = opt[0]
        if name == "message-type":
            msg_type = opt[1]
        elif name == "hostname":
            try:
                hostname = opt[1].decode(errors="replace") if isinstance(opt[1], bytes) else str(opt[1])
            except Exception:
                hostname = str(opt[1])
        elif name == "requested_addr":
            requested_ip = opt[1]

    # message-type: DISCOVER (op=1), DHCPOFFER (op=2), DHCPREQUEST (op=3), DHCPDECLINE (op=4), DHCPACK (op=5), DHCPNAK (op=6), DHCPRELEASE (op=7), DHCPINFORM (op=8)
    if msg_type not in (1, 3):  # only Discover/Request they have hostname+requested
        return

    client_mac = bootp.chaddr[:6].hex(":")  # chaddr is 16 bytes, MAC is first 6

    key = ("DHCP", client_mac, hostname, requested_ip)
    if already_seen(key):
        return

    print(TAG_DHCP + " " + client_mac + " requesting " + str(requested_ip) + " hostname=" + str(hostname))
    save(packet)


def handle_dhcpv6(packet):
    # https://datatracker.ietf.org/doc/html/rfc8415
    # DHCPv6: UDP/546 (client) or UDP/547 (server)
    if not (packet.haslayer(DHCP6_Solicit) or packet.haslayer(DHCP6_Request)
            or packet.haslayer(DHCP6_Advertise) or packet.haslayer(DHCP6_Reply)):
        return

    src_ip = packet[IPv6].src if packet.haslayer(IPv6) else "?"

    duid_str = None
    if packet.haslayer(DHCP6OptClientId):
        duid = packet[DHCP6OptClientId].duid
        if isinstance(duid, (DUID_LLT, DUID_LL)) and hasattr(duid, "lladdr"):
            duid_str = duid.lladdr
        elif isinstance(duid, DUID_EN):
            duid_str = "enterprise-" + str(duid.enterprisenum)
        else:
            duid_str = duid.summary() if hasattr(duid, "summary") else str(duid)

    msg = None
    if packet.haslayer(DHCP6_Solicit):
        msg = "Solicit"
    elif packet.haslayer(DHCP6_Request):
        msg = "Request"
    elif packet.haslayer(DHCP6_Advertise):
        msg = "Advertise"
    elif packet.haslayer(DHCP6_Reply):
        msg = "Reply"

    key = ("DHCPv6", src_ip, msg, duid_str)
    if already_seen(key):
        return

    print(TAG_DHCPv6 + " " + src_ip + " " + msg + " DUID=" + str(duid_str))
    save(packet)


def handle_ndp(packet):
    # https://datatracker.ietf.org/doc/html/rfc4861
    # NDP: ICMPv6 NS (type 135), RS (type 133), RA (type 134)
    src_ip = packet[IPv6].src if packet.haslayer(IPv6) else "?"
    src_mac = packet[Ether].src if packet.haslayer(Ether) else "?"

    if packet.haslayer(ICMPv6ND_NS):
        target = packet[ICMPv6ND_NS].tgt
        key = ("NDP-NS", src_ip, src_mac, target)
        if already_seen(key):
            return
        print(TAG_NDP + " " + src_ip + " (" + src_mac + ") soliciting " + target)
        save(packet)
    elif packet.haslayer(ICMPv6ND_RS):
        key = ("NDP-RS", src_ip, src_mac)
        if already_seen(key):
            return
        print(TAG_NDP + " " + src_ip + " (" + src_mac + ") router solicitation")
        save(packet)
    elif packet.haslayer(ICMPv6ND_RA):
        key = ("NDP-RA", src_ip, src_mac)
        if already_seen(key):
            return
        print(TAG_NDP + " " + src_ip + " (" + src_mac + ") router advertisement")
        save(packet)


def dns_query_name(packet):
    # Extract the queried name from a DNS packet, or None
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]
    if dns.qd is None:
        return None
    try:
        name = dns.qd.qname
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        return name.rstrip(".")
    except Exception:
        return None
    

def dns_answered_name(packet):
    # Extract the announced name from a DNS answer (used by mDNS announcements)
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]
    if dns.ancount == 0 or dns.an is None:
        return None
    try:
        name = dns.an.rrname
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        return name.rstrip(".")
    except Exception:
        return None
    

def handle_mdns(packet):
    # https://datatracker.ietf.org/doc/html/rfc6762
    # mDNS: UDP/5353, multicast 224.0.0.251 (or ff02::fb for IPv6)
    if not packet.haslayer(UDP):
        return
    if packet[UDP].dport != 5353 and packet[UDP].sport != 5353:
        return
    if not packet.haslayer(DNS):
        return

    src_ip = packet[IP].src if packet.haslayer(IP) else (
        packet[IPv6].src if packet.haslayer(IPv6) else "?")
    dns = packet[DNS]

    # qr=0 = query, qr=1 = response
    if dns.qr == 0:
        name = dns_query_name(packet)
        if name is None:
            return
        key = ("mDNS-q", src_ip, name)
        if already_seen(key):
            return
        print(TAG_MDNS + " " + src_ip + " querying " + name)
        save(packet)
    else:
        name = dns_answered_name(packet)
        if name is None:
            return
        key = ("mDNS-a", src_ip, name)
        if already_seen(key):
            return
        print(TAG_MDNS + " " + src_ip + " announcing " + name)
        save(packet)


def handle_llmnr(packet):
    # https://datatracker.ietf.org/doc/html/rfc4795
    # LLMNR: UDP/5355, multicast: 224.0.0.252 (or ff02::1:3 for IPv6)
    if not packet.haslayer(UDP):
        return
    if packet[UDP].dport != 5355 and packet[UDP].sport != 5355:
        return

    src_ip = packet[IP].src if packet.haslayer(IP) else (
        packet[IPv6].src if packet.haslayer(IPv6) else "?")
    
    if packet.haslayer(LLMNRQuery):
        # query: name in the question section
        llmnr = packet[LLMNRQuery]
        if llmnr.qr != 0:
            return
        if not llmnr.qd:
            return
        try:
            name = llmnr.qd.qname
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            name = name.rstrip(".")
        except Exception:
            return
        key = ("LLMNR-q", src_ip, name)
        if already_seen(key):
            return
        print(TAG_LLMNR + " " + src_ip + " querying " + name)
        save(packet)

    elif packet.haslayer(LLMNRResponse):
        # response: name in the answer section
        llmnr = packet[LLMNRResponse]
        if llmnr.ancount == 0 or not llmnr.an:
            return
        try:
            name = llmnr.an.rrname
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            name = name.rstrip(".")
        except Exception:
            return
        key = ("LLMNR-a", src_ip, name)
        if already_seen(key):
            return
        print(TAG_LLMNR + " " + src_ip + " responding " + name)
        save(packet)


def handle_nbtns(packet):
    # https://datatracker.ietf.org/doc/html/rfc1002
    # NBT-NS: UDP/137, broadcast 255.255.255.255
    if not packet.haslayer(NBNSQueryRequest):
        return

    nb = packet[NBNSQueryRequest]
    try:
        name = nb.QUESTION_NAME.decode(errors="replace") if isinstance(nb.QUESTION_NAME, bytes) else str(nb.QUESTION_NAME)
        name = name.strip()
    except Exception:
        name = str(nb.QUESTION_NAME)

    src_ip = packet[IP].src if packet.haslayer(IP) else "?"

    key = ("NBT-NS", src_ip, name)
    if already_seen(key):
        return

    print(TAG_NBTNS + " " + src_ip + " querying " + name)
    save(packet)


# protocol handlers
def on_packet(packet):
    handle_arp(packet)
    handle_ssdp(packet)
    handle_cdp(packet)
    handle_lldp(packet)
    handle_dhcp(packet)
    handle_dhcpv6(packet)
    handle_ndp(packet)
    handle_mdns(packet)
    handle_llmnr(packet)
    handle_nbtns(packet)


# sniffing and writing to pcap
def run(args):
    global pcap_writer

    output_path = args.output
    if args.timeout and not output_path:
        output_path = "screamer-" + datetime.now().strftime("%d-%m-%H-%M") + ".pcap"

    if output_path:
        pcap_writer = PcapWriter(output_path, sync=True, append=True)
        print("[*] Writing matched packets to: " + output_path)

    if args.timeout:
        print("[*] Stopping automatically after " + str(args.timeout) + "s\n")

    try:
        if args.pcap:
            sniff(offline=args.pcap, prn=on_packet, store=False)
        else:
            sniff(iface=args.iface, prn=on_packet, store=False, timeout=args.timeout)
    except KeyboardInterrupt:
        print()
        print(Fore.YELLOW + "[*] Stopped")
    finally:
        if pcap_writer is not None:
            pcap_writer.close()
            pcap_writer = None