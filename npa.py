from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
import binascii

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload = ""

        if TCP in packet:
            proto = "TCP"
            payload = str(packet[TCP].payload)
        elif UDP in packet:
            proto = "UDP"
            payload = str(packet[UDP].payload)
        
        if Raw in packet:
            payload = str(packet[Raw].load)

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {proto}")
        if payload:
            print(f"Payload: {binascii.hexlify(payload.encode()).decode()}")
        print("-" * 50)

def main():
    print("Available interfaces:")
    print(get_if_list())  # Print available interfaces
    # Choose the correct interface based on previous steps
    sniff(prn=packet_callback, store=0, iface="Wi-Fi")  # Update this

if __name__ == "__main__":
    main()
