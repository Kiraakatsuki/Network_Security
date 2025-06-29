import pyshark

def extract_features(packet):
    features = {}
    try:
        features['src_ip'] = packet.ip.src
        features['dst_ip'] = packet.ip.dst
        features['protocol'] = packet.transport_layer
        features['length'] = packet.length
        features['packet_time'] = packet.sniff_time
    except AttributeError:
        # Handle cases where the packet does not have IP or transport layer data
        features['src_ip'] = None
        features['dst_ip'] = None
        features['protocol'] = None
        features['length'] = packet.length
        features['packet_time'] = packet.sniff_time
    return features
