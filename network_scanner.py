#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# NETWORK SCANNER

"""

import sys
import os
import time
import threading
from scapy.all import ARP, Ether, srp

class NetworkScanner(object):
    def __init__(self):
        self.ips_online = []
        self.threads = []

    def scannear_rede(self, ip_inicial, ip_final):
        ip_base = ".".join(ip_inicial.split(".")[:-1]) + "."
        ip_inicial = int(ip_inicial.split(".")[-1])
        ip_final = int(ip_final)

        for ip_suffix in range(ip_inicial, ip_final + 1):
            ip = ip_base + str(ip_suffix)
            thread = threading.Thread(target=self.ping_and_get_mac, args=(ip,))
            self.threads.append(thread)
            thread.start()

        for thread in self.threads:
            thread.join()

    def ping_and_get_mac(self, ip):
        ping = os.system(f'ping -c 1 {ip} > /dev/null 2>&1')
        if ping == 0:
            mac_address = self.get_mac(ip)
            if mac_address:
                self.ips_online.append((ip, mac_address))

    def get_mac(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            return None

def main():
    ip_inicial = input("Digite o IP inicial (completo): ")
    ip_final = input("Digite o IP final (apenas o último octeto. Ex: 254): ")

    scan = NetworkScanner()
    scan.scannear_rede(ip_inicial, ip_final)

    scan.ips_online.sort()
    output_file = "scan_result.txt"
    
    with open(output_file, "w") as f:
        for pc in scan.ips_online:
            result = f"PC ONLINE >> IP={pc[0]} - MAC={pc[1]}"
            print(result)
            f.write(result + "\n")

        summary = f"\nExistem {len(scan.ips_online)} dispositivos online neste momento\n\n"
        print(summary)
        f.write(summary)

    print(f"Resultado salvo em {output_file}")

if __name__ == '__main__':
    main()

