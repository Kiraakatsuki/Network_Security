import socket

PROTOCOL_MAP = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}

def ip_to_int(ip):
    try:
        return int(socket.inet_aton(ip).hex(), 16)
    except:
        return 0

def categorize_port(port):
    if port <= 1023:
        return 'well_known'
    elif 1024 <= port <= 49151:
        return 'registered'
    else:
        return 'dynamic'

def extract_features(packet):
    features = {
        'src_ip': 0,
        'dst_ip': 0,
        'protocol': PROTOCOL_MAP['OTHER'],
        'length': 0,
        'src_port': 0,
        'dst_port': 0,
        'flags': 'NONE',
        'src_port_category': 'registered',
        'dst_port_category': 'registered'
    }

    try:
        if hasattr(packet, 'ip'):
            features['src_ip'] = ip_to_int(packet.ip.src)
            features['dst_ip'] = ip_to_int(packet.ip.dst)
            features['length'] = int(getattr(packet, 'length', 0))

            transport = getattr(packet, 'transport_layer', 'OTHER')
            features['protocol'] = PROTOCOL_MAP.get(transport, PROTOCOL_MAP['OTHER'])

            if hasattr(packet, 'tcp'):
                features['src_port'] = int(getattr(packet.tcp, 'srcport', 0))
                features['dst_port'] = int(getattr(packet.tcp, 'dstport', 0))
                features['flags'] = getattr(packet.tcp, 'flags', 'UNK')
            elif hasattr(packet, 'udp'):
                features['src_port'] = int(getattr(packet.udp, 'srcport', 0))
                features['dst_port'] = int(getattr(packet.udp, 'dstport', 0))

            features['src_port_category'] = categorize_port(features['src_port'])
            features['dst_port_category'] = categorize_port(features['dst_port'])

    except Exception as e:
        print(f"Feature extraction error: {e}")

    return features