import pyshark

# Function to capture live network traffic
def capture_traffic(interface='eth0', duration=10):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=duration)  # Capture for a set duration (in seconds)

    for packet in capture.sniffed_packets():
        print(packet)

if __name__ == "__main__":
    capture_traffic()
