from scapy.all import *


interface = "enx465b36dd7772"

def analyze_packets(packet):
   
    if packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode('utf-8')
        print(f"[DNS Inquiry] Phone is visiting: {domain}")
        
        
        if "ns-cloud" in domain or "api-check" in domain:
            print(f"⚠️  ALERT: SUSPICIOUS DOMAIN DETECTED: {domain}")

   
    if packet.haslayer(IP):
        if len(packet) > 1200: 
            print(f"📦 Large Data Packet detected to: {packet[IP].dst}")

print(f"Spyware detection started on {interface}... Press Ctrl+C to stop.")
sniff(iface=interface, prn=analyze_packets, store=0)
