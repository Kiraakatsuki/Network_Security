import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import joblib  # For saving the trained model and scaler

# Create the models and scalers directory if it doesn't exist
os.makedirs('backend/model', exist_ok=True)

# Example features for training
data = {
    'src_ip': [192, 10, 172],  # Just placeholders
    'dst_ip': [10, 192, 172],
    'protocol': ['TCP', 'UDP', 'TCP'],
    'length': [512, 1024, 256],
    'malicious': [0, 1, 0]  # Labels: 0 = normal, 1 = malicious
}

df = pd.DataFrame(data)

# Convert categorical features to numerical values
df['protocol'] = pd.factorize(df['protocol'])[0]

# Convert IP addresses to integers (simplified conversion)
df['src_ip'] = df['src_ip'].apply(lambda x: int(x))  # If IPs are in int form, you can modify here if needed
df['dst_ip'] = df['dst_ip'].apply(lambda x: int(x))  # Same as above

# Features (X) and target (y)
X = df.drop('malicious', axis=1)
y = df['malicious']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the scaler
scaler = StandardScaler()

# Fit and transform the training data, and transform the test data
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# Test the model
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

# Print the results
print("Model Accuracy:", accuracy)
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save the trained model to the /backend/model directory
model_filename = 'backend/model/traffic_classifier_model.pkl'
scaler_filename = 'backend/model/scaler.pkl'

joblib.dump(model, model_filename)  # Save the trained model
joblib.dump(scaler, scaler_filename)  # Save the scaler

print(f"Model saved to {model_filename}")
print(f"Scaler saved to {scaler_filename}")
