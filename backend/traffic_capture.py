import pyshark
import pandas as pd
from datetime import datetime
from feature_extraction import extract_features

def capture_traffic(interface='eth0', duration=10, max_packets=100):
    capture = pyshark.LiveCapture(interface=interface)
    packets_data = []
    print(f"Capturing on {interface} for {duration} seconds...")

    try:
        capture.sniff(timeout=duration)
        for packet in capture.sniffed_packets:
            if len(packets_data) >= max_packets:
                break
            features = extract_features(packet)
            if features:
                packets_data.append(features)
                print(f"Packet: {features}")

    except Exception as e:
        print(f"Capture error: {e}")

    if packets_data:
        df = pd.DataFrame(packets_data)
        filename = f"network_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(filename, index=False)
        print(f"Saved {len(df)} packets to {filename}")
    return packets_data

if __name__ == "__main__":
    capture_traffic(interface='eth0', duration=30, max_packets=500)