from flask import Flask, jsonify
import redis
import json
from datetime import datetime

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

@app.route("/api/live_traffic")
def live_traffic():
    try:
        raw = redis_client.get('live_traffic')
        if raw is None:
            raise ValueError("No live data in Redis.")
        
        data = json.loads(raw)
        print("[DEBUG] Served live_traffic data:", data)

        # Ensure expected fields
        normal = int(data.get("normal", 0))
        malicious = int(data.get("malicious", 0))
        total = normal + malicious
        threat_level = malicious / (total + 0.001)

        return jsonify({
            "normal": normal,
            "malicious": malicious,
            "threat_level": threat_level,
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "gpu": data.get("gpu", "Active"),
            "processing": data.get("processing", "Normal"),
            "top_ports": data.get("top_ports", {}),
            "flag_distribution": data.get("flag_distribution", {}),
            "src_port": data.get("src_port", 0),
            "dst_port": data.get("dst_port", 0),
            "flags": data.get("flags", "UNK")
        })

    except Exception as e:
        print(f"[ERROR] /api/live_traffic: {e}")
        return jsonify({
            "normal": 0,
            "malicious": 0,
            "threat_level": 1.0,
            "timestamp": datetime.now().isoformat(),
            "gpu": "Inactive",
            "processing": "Error",
            "top_ports": {},
            "flag_distribution": {},
            "src_port": 0,
            "dst_port": 0,
            "flags": "ERR"
        })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
