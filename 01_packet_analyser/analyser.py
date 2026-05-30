"""
Project 1 — Network Packet Analyser
Captures live traffic and flags suspicious patterns.
Dependencies: pip install scapy colorama
Run as root:  sudo python analyser.py -i eth0
"""

import argparse, logging
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, ARP, TCP, IP, DNS

SYN_THRESHOLD   = 20
PORT_SCAN_PORTS = 10
LOG_FILE        = "alerts.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s  %(levelname)s  %(message)s")

syn_counts   = defaultdict(int)
port_targets = defaultdict(set)
arp_table    = {}
alert_count  = 0


def alert(level: str, msg: str) -> None:
    global alert_count
    alert_count += 1
    ts     = datetime.now().strftime("%H:%M:%S")
    colour = {"HIGH": "\033[91m", "MED": "\033[93m", "INFO": "\033[96m"}.get(level, "")
    reset  = "\033[0m"
    print(f"[{ts}] {colour}[{level}]{reset} {msg}")
    logging.info(f"[{level}] {msg}")


def check_arp(pkt) -> None:
    if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
        return
    src_ip, src_mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    if src_ip in arp_table and arp_table[src_ip] != src_mac:
        alert("HIGH", f"ARP spoof? {src_ip} changed MAC: {arp_table[src_ip]} → {src_mac}")
    arp_table[src_ip] = src_mac


def check_tcp(pkt) -> None:
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    src   = pkt[IP].src
    flags = pkt[TCP].flags
    if flags == "S":
        syn_counts[src] += 1
        if syn_counts[src] == SYN_THRESHOLD:
            alert("HIGH", f"Possible SYN flood from {src} ({syn_counts[src]} SYNs)")
    port_targets[src].add(pkt[TCP].dport)
    if len(port_targets[src]) == PORT_SCAN_PORTS:
        alert("MED", f"Port scan from {src} — {len(port_targets[src])} unique ports hit")


def check_dns(pkt) -> None:
    if not pkt.haslayer(DNS):
        return
    qname = pkt[DNS].qd.qname.decode(errors="replace") if pkt[DNS].qd else ""
    if len(qname) > 60:
        alert("MED", f"Long DNS query (possible tunnelling?): {qname[:80]}")


def packet_handler(pkt) -> None:
    check_arp(pkt)
    check_tcp(pkt)
    check_dns(pkt)


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyser")
    parser.add_argument("-i", "--iface", default="eth0")
    parser.add_argument("-c", "--count", type=int, default=0)
    args = parser.parse_args()
    print(f"[*] Sniffing on {args.iface} — Ctrl+C to stop\n")
    try:
        sniff(iface=args.iface, prn=packet_handler, store=False, count=args.count)
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. {alert_count} alerts logged to {LOG_FILE}")


if __name__ == "__main__":
    main()
