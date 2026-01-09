from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_sniffer(packet):
    if packet.haslayer(IP):
        print("=================================")
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

sniff(prn=packet_sniffer, count=5)
