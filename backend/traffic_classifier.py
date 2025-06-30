# === FIXED: traffic_classifier.py ===
import pandas as pd
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Configuration
RANDOM_STATE = 42
TEST_SIZE = 0.2
MODEL_DIR = 'backend/model'
os.makedirs(MODEL_DIR, exist_ok=True)

# Enhanced dataset
data = {
    'src_ip': [192, 10, 172, 192, 10, 172, 192, 10, 172, 192],
    'dst_ip': [10, 192, 172, 10, 192, 172, 10, 192, 172, 10],
    'protocol': ['TCP', 'UDP', 'TCP', 'ICMP', 'TCP', 'UDP', 'TCP', 'ICMP', 'TCP', 'UDP'],
    'length': [512, 1024, 256, 768, 384, 512, 1024, 256, 768, 384],
    'src_port': [12345, 54321, 45678, 34567, 23456, 12345, 54321, 45678, 34567, 23456],
    'dst_port': [80, 443, 22, 3389, 8080, 80, 443, 22, 3389, 8080],
    'flags': ['ACK', 'SYN', 'FIN', 'RST', 'PSH', 'ACK', 'SYN', 'FIN', 'RST', 'PSH'],
    'malicious': [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
}

df = pd.DataFrame(data)

# Port categorization

def categorize_port(port):
    if port <= 1023:
        return 'well_known'
    elif 1024 <= port <= 49151:
        return 'registered'
    else:
        return 'dynamic'

df['dst_port_category'] = df['dst_port'].apply(categorize_port)
df['src_port_category'] = df['src_port'].apply(categorize_port)

# Define features
numeric_features = ['src_ip', 'dst_ip', 'length', 'src_port', 'dst_port']
categorical_features = ['protocol', 'flags', 'dst_port_category', 'src_port_category']

preprocessor = ColumnTransformer([
    ('num', StandardScaler(), numeric_features),
    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
])

pipeline = Pipeline([
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(random_state=RANDOM_STATE))
])

param_grid = {
    'classifier__n_estimators': [50, 100],
    'classifier__max_depth': [None, 10],
    'classifier__min_samples_split': [2, 5]
}

X = df[numeric_features + categorical_features]
y = df['malicious']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

grid_search = GridSearchCV(pipeline, param_grid, cv=3, scoring='roc_auc', verbose=1)
grid_search.fit(X_train, y_train)

best_model = grid_search.best_estimator_
print(f"Best parameters: {grid_search.best_params_}")

# Evaluation
y_pred = best_model.predict(X_test)
y_proba = best_model.predict_proba(X_test)[:, 1]

print("\nModel Evaluation:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Save model and metadata
joblib.dump(best_model, f'{MODEL_DIR}/traffic_classifier_model.pkl')
joblib.dump(X.columns.tolist(), f'{MODEL_DIR}/expected_features.pkl')

print("\nSaved model artifacts:")
print(f"- Model: {MODEL_DIR}/traffic_classifier_model.pkl")
print(f"- Features: {MODEL_DIR}/expected_features.pkl")
