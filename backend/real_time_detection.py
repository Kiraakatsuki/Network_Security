import joblib
import pyshark
import pandas as pd

# Load the trained model and scaler
model_path = 'backend/model/traffic_classifier_model.pkl'
scaler_path = 'backend/model/scaler.pkl'

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

# Convert IP address to an integer (simplified method)
def ip_to_int(ip):
    parts = ip.split('.')
    return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])

# Function to capture and process traffic
def capture_and_detect():
    capture = pyshark.LiveCapture(interface='eth0')  # Adjust interface as needed
    for packet in capture.sniff_continuously():
        if hasattr(packet, 'ip'):  # Check if the packet has an IP layer
            try:
                # Extract features from the packet
                features = {
                    'src_ip': ip_to_int(packet.ip.src),
                    'dst_ip': ip_to_int(packet.ip.dst),
                    'protocol': packet.transport_layer,
                    'length': len(packet)
                }

                # Convert features to a DataFrame (for compatibility with model input)
                df = pd.DataFrame([features])

                # Convert 'protocol' to numerical (same as during training)
                df['protocol'] = pd.factorize(df['protocol'])[0]

                # Standardize the features using the loaded scaler
                X_scaled = scaler.transform(df)

                # Make prediction using the trained model
                prediction = model.predict(X_scaled)

                # Print the prediction result
                if prediction == 1:
                    print(f"Malicious traffic detected: {packet}")
                else:
                    print(f"Normal traffic detected: {packet}")

            except AttributeError as e:
                # Handle packets that do not have the expected IP or transport layer
                print(f"Error processing packet: {e}")
        else:
            print(f"Non-IP packet detected: {packet}")

# Start the detection
if __name__ == "__main__":
    capture_and_detect()
