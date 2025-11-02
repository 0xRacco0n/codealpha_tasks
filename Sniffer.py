#!/usr/bin/env python3
"""
Simple packet sniffer (Linux and Windows)
- Shows timestamp, src/dst IP, ports (if applicable), protocol
- Shows payload preview (printable ASCII) and hex snippet
Usage:
    sudo python3 sniffer.py         # on Linux
    (Run as admin) python sniffer.py  # on Windows
Note: Only for authorized/ethical use.
"""

import sys
import socket
import struct
import textwrap
import time
import platform
from datetime import datetime

def hexdump(src: bytes, length=32):
    result = []
    for i in range(0, min(len(src), length), 16):
        chunk = src[i:i+16]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        text = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
        result.append(f"{i:04x}  {hex_bytes:<48}  {text}")
    return '\n'.join(result)

def pretty_payload(src: bytes, max_len=80):
    printable = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in src)
    if len(printable) > max_len:
        return printable[:max_len] + '...'
    return printable

def mac_addr(bytes_addr):
    return ':'.join(f"{b:02x}" for b in bytes_addr)

def parse_ethernet_header(packet):
    eth_header = packet[:14]
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', eth_header)
    return {
        'dest_mac': mac_addr(dest_mac),
        'src_mac': mac_addr(src_mac),
        'proto': proto,
        'payload': packet[14:]
    }

def parse_ipv4_header(packet):
    if len(packet) < 20:
        return None
    # !BBHHHBBH4s4s => version/IHL, tos, total length, id, flags/frag, ttl, proto, checksum, src, dst
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    total_length = iph[2]
    proto = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    payload = packet[ihl:total_length]
    return {
        'version': version,
        'ihl': ihl,
        'total_length': total_length,
        'protocol': proto,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'payload': payload
    }

def parse_tcp_header(segment):
    if len(segment) < 20:
        return None
    tcph = struct.unpack('!HHLLBBHHH', segment[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    data_offset = (tcph[4] >> 4) * 4
    payload = segment[data_offset:]
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'payload': payload
    }

def parse_udp_header(segment):
    if len(segment) < 8:
        return None
    udph = struct.unpack('!HHHH', segment[:8])
    src_port, dst_port, length, checksum = udph
    payload = segment[8:length] if length > 8 else segment[8:]
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'payload': payload
    }

def parse_icmp_header(segment):
    if len(segment) < 4:
        return None
    icmph = struct.unpack('!BBH', segment[:4])
    icmp_type, code, checksum = icmph
    payload = segment[4:]
    return {
        'type': icmp_type,
        'code': code,
        'payload': payload
    }

def print_packet_summary(ts, eth, ip_info, l4_info, proto_name):
    ts_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    if l4_info is None:
        # Only IP-level
        print(f"{ts_str}  {ip_info['src_ip']} -> {ip_info['dst_ip']}  {proto_name}  len={len(ip_info['payload'])}")
        payload = ip_info['payload']
    else:
        if proto_name == "TCP" or proto_name == "UDP":
            s = f"{ip_info['src_ip']}:{l4_info['src_port']} -> {ip_info['dst_ip']}:{l4_info['dst_port']}"
        elif proto_name == "ICMP":
            s = f"{ip_info['src_ip']} -> {ip_info['dst_ip']} (ICMP type={l4_info['type']} code={l4_info['code']})"
        else:
            s = f"{ip_info['src_ip']} -> {ip_info['dst_ip']}"
        print(f"{ts_str}  {s}  {proto_name}  payload_len={len(l4_info['payload'])}")
        payload = l4_info['payload']

    if payload:
        preview = pretty_payload(payload, max_len=120)
        print(f"    payload (preview): {preview}")
        print("    hex dump (first 128 bytes):")
        print(textwrap.indent(hexdump(payload, length=128), "      "))
    else:
        print("    (no payload)")
    print("-" * 80)

def bind_socket():
    system = platform.system().lower()
    if system == 'linux':
        try:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)
            return raw_sock
        except PermissionError:
            sys.exit("Error: must run as root to capture packets on Linux.")
    elif system == 'windows':
        # Windows: use IPPROTO_IP + SIO_RCVALL
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host = socket.gethostbyname(socket.gethostname())
            raw_sock.bind((host, 0))
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # enable promiscuous mode:
            SIO_RCVALL = 0x98000001
            raw_sock.ioctl(SIO_RCVALL, socket.RCVALL_ON)
            return raw_sock
        except PermissionError:
            sys.exit("Error: must run as Administrator to capture packets on Windows.")
    else:
        sys.exit(f"Unsupported OS: {system}")

def main():
    print("Simple Packet Sniffer — ethical use only")
    s = bind_socket()
    try:
        while True:
            packet, addr = s.recvfrom(65535)
            ts = time.time()
            # Linux with AF_PACKET: packet starts with Ethernet header
            system = platform.system().lower()
            if system == 'linux':
                eth = parse_ethernet_header(packet)
                if eth['proto'] == 0x0800:  # IPv4
                    ip_info = parse_ipv4_header(eth['payload'])
                    if not ip_info:
                        continue
                    proto = ip_info['protocol']
                    if proto == 6:  # TCP
                        tcp = parse_tcp_header(ip_info['payload'])
                        print_packet_summary(ts, eth, ip_info, tcp, "TCP")
                    elif proto == 17:  # UDP
                        udp = parse_udp_header(ip_info['payload'])
                        print_packet_summary(ts, eth, ip_info, udp, "UDP")
                    elif proto == 1:  # ICMP
                        icmp = parse_icmp_header(ip_info['payload'])
                        print_packet_summary(ts, eth, ip_info, icmp, "ICMP")
                    else:
                        print_packet_summary(ts, eth, ip_info, None, f"IP proto {proto}")
                else:
                    # Non-IPv4 (ARP, IPv6, etc.)
                    # You can extend this to parse more protocols.
                    continue
            elif system == 'windows':
                # On Windows, packet begins with IP header (no Ethernet)
                ip_info = parse_ipv4_header(packet)
                if not ip_info:
                    continue
                proto = ip_info['protocol']
                if proto == 6:
                    tcp = parse_tcp_header(ip_info['payload'])
                    print_packet_summary(ts, None, ip_info, tcp, "TCP")
                elif proto == 17:
                    udp = parse_udp_header(ip_info['payload'])
                    print_packet_summary(ts, None, ip_info, udp, "UDP")
                elif proto == 1:
                    icmp = parse_icmp_header(ip_info['payload'])
                    print_packet_summary(ts, None, ip_info, icmp, "ICMP")
                else:
                    print_packet_summary(ts, None, ip_info, None, f"IP proto {proto}")
    except KeyboardInterrupt:
        if platform.system().lower() == 'windows':
            # turn off promiscuous mode on windows
            try:
                SIO_RCVALL = 0x98000001
                s.ioctl(SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        print("\nStopped by user.")
    finally:
        s.close()

if __name__ == "__main__":
    main()