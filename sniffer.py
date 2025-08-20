from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} -> {pkt[IP].dst} | Proto: {pkt[IP].proto}")
        if TCP in pkt:
            print(f"   TCP Ports: {pkt[TCP].sport} -> {pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"   UDP Ports: {pkt[UDP].sport} -> {pkt[UDP].dport}")
        if Raw in pkt:
            print(f"   Payload: {pkt[Raw].load[:50]}")  # first 50 bytes of payload

sniff(prn=packet_callback, count=10)
