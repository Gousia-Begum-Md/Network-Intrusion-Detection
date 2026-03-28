from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import os

# 1. Config
FILE_NAME = "live_capture.csv"
FEATURES = ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl']

# Basic mapping to match label-encoded data (adjust if your model uses different numbers)
PROTO_MAP = {'tcp': 1, 'udp': 2, 'icmp': 3, 'other': 0}

def process_packet(packet):
    # Only process IP packets to avoid background noise
    if IP in packet:
        # Extract raw packet data
        sbytes = len(packet)
        sttl = packet[IP].ttl
        
        # Determine protocol
        proto_name = "other"
        if TCP in packet: proto_name = "tcp"
        elif UDP in packet: proto_name = "udp"
        proto_encoded = PROTO_MAP.get(proto_name, 0)

        # Map to your model's exact features
        # Note: Session-based features (like 'dur' and 'rate') are given safe dummy values 
        # here because calculating them in real-time requires complex memory tracking.
        data = {
            'dur': 0.01,           
            'proto': proto_encoded, 
            'service': 0,          
            'state': 1,            
            'spkts': 1,            
            'dpkts': 1,            
            'sbytes': sbytes,      
            'dbytes': 0,           
            'rate': 50.0,          
            'sttl': sttl           
        }
        
        df = pd.DataFrame([data])
        
        # Write to the CSV instantly
        header_needed = not os.path.exists(FILE_NAME)
        df.to_csv(FILE_NAME, mode='a', index=False, header=header_needed)
        
        print(f"[+] Packet Logged -> {proto_name.upper()} | Bytes: {sbytes} | TTL: {sttl}")

# --- Start the Engine ---
if __name__ == "__main__":
    print(f"🛡️ CyberShield Sniffer Active...")
    print(f"📡 Capturing live traffic to '{FILE_NAME}'. Press Ctrl+C to stop.")
    
    # Start sniffing. 'store=0' ensures your RAM doesn't fill up over time.
    sniff(prn=process_packet, store=0)
