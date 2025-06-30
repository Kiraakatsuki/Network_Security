import joblib
import pyshark
import pandas as pd
import redis
import json
from datetime import datetime
import socket
import numpy as np
from collections import defaultdict

# Load model pipeline and expected features
try:
    model = joblib.load('backend/model/traffic_classifier_model.pkl')
    expected_features = joblib.load('backend/model/expected_features.pkl')
except Exception as e:
    raise SystemExit(f"[ERROR] Failed to load model or features: {e}")

# Redis setup
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Protocol mapping and statistics holders
PROTOCOL_MAP = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
port_stats = defaultdict(int)
flag_stats = defaultdict(int)

# Convert IP to int
def ip_to_int(ip):
    try:
        return int(socket.inet_aton(ip).hex(), 16)
    except:
        return 0

# Categorize port range
def categorize_port(port):
    if port <= 1023:
        return 'well_known'
    elif 1024 <= port <= 49151:
        return 'registered'
    else:
        return 'dynamic'

# Extract features from each packet
def extract_features(packet):
    features = defaultdict(lambda: 0)
    try:
        if hasattr(packet, 'ip'):
            features['src_ip'] = ip_to_int(packet.ip.src)
            features['dst_ip'] = ip_to_int(packet.ip.dst)
            features['length'] = int(getattr(packet, 'length', 0))
            features['protocol'] = getattr(packet, 'transport_layer', 'OTHER')

            if hasattr(packet, 'tcp'):
                features['src_port'] = int(getattr(packet.tcp, 'srcport', 0))
                features['dst_port'] = int(getattr(packet.tcp, 'dstport', 0))
                features['flags'] = getattr(packet.tcp, 'flags', 'UNK')
            elif hasattr(packet, 'udp'):
                features['src_port'] = int(getattr(packet.udp, 'srcport', 0))
                features['dst_port'] = int(getattr(packet.udp, 'dstport', 0))
                features['flags'] = 'NONE'

            features['src_port_category'] = categorize_port(features['src_port'])
            features['dst_port_category'] = categorize_port(features['dst_port'])

            port_stats[features['dst_port']] += 1
            flag_stats[features['flags']] += 1
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
    return dict(features)

# Process a batch of features and push to Redis
def process_batch(batch):
    df = pd.DataFrame(batch).fillna(0)

    for col in ['src_ip', 'dst_ip', 'length', 'src_port', 'dst_port']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
    for col in ['protocol', 'flags', 'dst_port_category', 'src_port_category']:
        df[col] = df[col].astype(str).fillna('UNKNOWN')

    try:
        X = df[expected_features]
        preds = model.predict(X)
    except Exception as e:
        print(f"[ERROR] Inference failed: {e}")
        return

    last = batch[-1]
    output = {
        "normal": int(np.sum(preds == 0)),
        "malicious": int(np.sum(preds == 1)),
        "normal_percent": float(np.mean(preds == 0) * 100),
        "malicious_percent": float(np.mean(preds == 1) * 100),
        "timestamp": datetime.now().isoformat(),
        "sample_size": len(preds),
        "src_port": last.get('src_port', 0),
        "dst_port": last.get('dst_port', 0),
        "flags": last.get('flags', 'UNK'),
        "gpu": "Active",
        "processing": "Normal",
        "top_ports": dict(sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
        "flag_distribution": dict(flag_stats)
    }

    print(f"[INFO] Processed Batch: {output['sample_size']} packets | Malicious: {output['malicious']}")

    try:
        pipe = redis_client.pipeline()
        pipe.set('live_traffic', json.dumps(output))
        pipe.set('port_statistics', json.dumps(output['top_ports']))
        pipe.set('flag_statistics', json.dumps(output['flag_distribution']))
        pipe.lpush('traffic_history', json.dumps(output))      # Store history
        pipe.ltrim('traffic_history', 0, 299)                  # Keep last 300 batches
        pipe.publish('traffic_updates', json.dumps(output))
        pipe.execute()
    except Exception as e:
        print(f"[ERROR] Redis push failed: {e}")

# Live capture
def capture_and_publish(interface='eth0', batch_size=2):
    print(f"[INFO] Starting packet capture on {interface} (batch size = {batch_size})")
    capture = pyshark.LiveCapture(interface=interface)

    batch = []
    for packet in capture.sniff_continuously():
        feat = extract_features(packet)
        print(f"[DEBUG] Packet features: {feat}")
        if feat:
            batch.append(feat)
        if len(batch) >= batch_size:
            process_batch(batch)
            batch = []

if __name__ == "__main__":
    try:
        capture_and_publish()
    except KeyboardInterrupt:
        print("[INFO] Packet capture stopped.")
