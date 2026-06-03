import socket
import struct
import textwrap
import time
import sys
import os
import argparse
from datetime import datetime

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB = '\t\t\t\t'
MAX_PAYLOAD_PRINT = 1024

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Linux raw sockets only)")
    parser.add_argument('--interface', '-i', help='Bind to a specific interface (AF_PACKET only)', default=None)
    parser.add_argument('--count', '-c', type=int, help='Number of packets to capture (0 = unlimited)', default=0)
    args = parser.parse_args()

    print("=" * 60)
    print("        BASIC NETWORK SNIFFER")
    print("        CodeAlpha Internship - Task 1")
    print("=" * 60)

    if os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("\n[ERROR] Root privileges required.")
        print("Run with: sudo python3 Network_Sniffer.py")
        sys.exit(1)

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except AttributeError:
        print("[ERROR] AF_PACKET not supported on this OS (Linux only).")
        print("On Windows/macOS, use scapy or WinPcap/Npcap instead.")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Permission denied. Run as root/sudo.")
        sys.exit(1)

    if args.interface:
        try:
            conn.bind((args.interface, 0))
        except Exception as e:
            print(f"[WARNING] Failed to bind to interface {args.interface}: {e}")

    print("\n[*] Sniffing started... Press Ctrl+C to stop.\n")
    packet_count = 0
    max_packets = args.count if args.count and args.count > 0 else None

    try:
        while True:
            try:
                raw_data, addr = conn.recvfrom(65536)
            except OSError as e:
                print(f"[ERROR] Socket error: {e}")
                break

            packet_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S')

            print(f"\n{'='*60}")
            print(f"  Packet #{packet_count}  |  Time: {timestamp}")
            print(f"{'='*60}")

            try:
                result = ethernet_frame(raw_data)
            except ValueError as e:
                print(f"[WARNING] Truncated/invalid ethernet frame: {e}")
                continue

            dest_mac, src_mac, eth_proto, data = result
            print(f"\n[ETHERNET FRAME]")
            print(TAB_1 + f"Destination MAC : {dest_mac}")
            print(TAB_1 + f"Source MAC      : {src_mac}")
            print(TAB_1 + f"Protocol        : {eth_proto}")

            # IPv4
            if eth_proto == 8:
                ipv4_result = ipv4_packet(data)
                if ipv4_result is None:
                    print(TAB_2 + "Truncated IPv4 packet")
                    continue

                (version, header_length, ttl, proto,
                 src_ip, dest_ip, ip_data) = ipv4_result

                print(f"\n[IPv4 PACKET]")
                print(TAB_2 + f"Version         : {version}")
                print(TAB_2 + f"Header Length   : {header_length} bytes")
                print(TAB_2 + f"TTL             : {ttl}")
                print(TAB_2 + f"Source IP       : {src_ip}")
                print(TAB_2 + f"Destination IP  : {dest_ip}")

                # ICMP
                if proto == 1:
                    icmp_result = icmp_packet(ip_data)
                    if icmp_result is None:
                        print(TAB_3 + "Truncated ICMP packet")
                        continue
                    icmp_type, code, checksum, icmp_data = icmp_result
                    print(f"\n[ICMP PACKET]")
                    print(TAB_3 + f"Type      : {icmp_type}")
                    print(TAB_3 + f"Code      : {code}")
                    print(TAB_3 + f"Checksum  : {checksum}")
                    print(TAB_3 + "Payload:")
                    print(format_data(DATA_TAB, icmp_data))

                # TCP
                elif proto == 6:
                    tcp_result = tcp_segment(ip_data)
                    if tcp_result is None:
                        print(TAB_3 + "Truncated TCP segment")
                        continue
                    (src_port, dest_port, sequence, acknowledgment,
                     flag_urg, flag_ack, flag_psh, flag_rst,
                     flag_syn, flag_fin, tcp_data) = tcp_result

                    print(f"\n[TCP SEGMENT]")
                    print(TAB_3 + f"Source Port      : {src_port}")
                    print(TAB_3 + f"Destination Port : {dest_port}")
                    print(TAB_3 + f"Sequence         : {sequence}")
                    print(TAB_3 + f"Acknowledgment   : {acknowledgment}")
                    print(TAB_3 + "Flags:")
                    print(DATA_TAB + f"URG={flag_urg}  ACK={flag_ack}  PSH={flag_psh}")
                    print(DATA_TAB + f"RST={flag_rst}  SYN={flag_syn}  FIN={flag_fin}")
                    if tcp_data:
                        print(TAB_3 + "Payload:")
                        print(format_data(DATA_TAB, tcp_data))

                # UDP
                elif proto == 17:
                    udp_result = udp_segment(ip_data)
                    if udp_result is None:
                        print(TAB_3 + "Truncated UDP segment")
                        continue
                    src_port, dest_port, length, udp_data = udp_result
                    print(f"\n[UDP SEGMENT]")
                    print(TAB_3 + f"Source Port      : {src_port}")
                    print(TAB_3 + f"Destination Port : {dest_port}")
                    print(TAB_3 + f"Length           : {length}")
                    if udp_data:
                        print(TAB_3 + "Payload:")
                        print(format_data(DATA_TAB, udp_data))

                else:
                    print(TAB_2 + f"Other Protocol   : {proto}")
                    print(TAB_2 + "Data:")
                    print(format_data(DATA_TAB, ip_data))

            if max_packets is not None and packet_count >= max_packets:
                print(f"\n[*] Reached packet capture limit: {packet_count}")
                break

    except KeyboardInterrupt:
        print(f"\n\n[*] Sniffer stopped. Total packets captured: {packet_count}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def ethernet_frame(data):
    if len(data) < 14:
        raise ValueError('frame too short')
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    # convert network-order ethertype to host-order
    proto = socket.ntohs(proto)
    return (
        get_mac_addr(dest_mac),
        get_mac_addr(src_mac),
        proto,
        data[14:]
    )


def get_mac_addr(bytes_addr):
    if not bytes_addr or len(bytes_addr) < 6:
        return '00:00:00:00:00:00'
    return ':'.join(f'{b:02x}' for b in bytes_addr[:6]).upper()


def ipv4_packet(data):
    if len(data) < 20:
        return None
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    if len(data) < header_length:
        return None
    try:
        unpacked = struct.unpack('!BBHHHBBH4s4s', data[:20])
        ttl = unpacked[5]
        proto = unpacked[6]
        src = unpacked[8]
        target = unpacked[9]
    except struct.error:
        return None
    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    if len(data) < 4:
        return None
    try:
        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    except struct.error:
        return None
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    if len(data) < 14:
        return None
    try:
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    except struct.error:
        return None
    offset = (offset_reserved_flags >> 12) * 4
    if len(data) < offset:
        return None
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return (
        src_port, dest_port, sequence, acknowledgment,
        flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
        data[offset:]
    )


def udp_segment(data):
    if len(data) < 8:
        return None
    try:
        src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
    except struct.error:
        return None
    return src_port, dest_port, size, data[8:]


def format_data(prefix, data):
    if not data:
        return prefix + "(empty)"
    try:
        # avoid printing unbounded payloads
        if isinstance(data, (bytes, bytearray)):
            raw = bytes(data)
        else:
            raw = bytes(data)
        truncated = False
        if len(raw) > MAX_PAYLOAD_PRINT:
            raw = raw[:MAX_PAYLOAD_PRINT]
            truncated = True
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        lines = textwrap.wrap(text, 60)
        out = '\n'.join(prefix + line for line in lines)
        if truncated:
            out += '\n' + prefix + f"... (truncated, showing first {MAX_PAYLOAD_PRINT} bytes)"
        return out
    except Exception:
        return prefix + repr(data[:40])


if __name__ == "__main__":
    main()