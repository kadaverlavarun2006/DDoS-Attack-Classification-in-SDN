
# DDoS Attack Classification in SDN
# Hybrid Model: DBN (RBM) + SVM


import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.neural_network import BernoulliRBM
from sklearn.metrics import accuracy_score, classification_report

# 1. GENERATING SAMPLE NETWORK TRAFFIC DATA

np.random.seed(42)
data_size = 1800

traffic_data = pd.DataFrame({
    "Pkt_Count": np.random.randint(10, 500, data_size),
    "Byte_Count": np.random.randint(1000, 100000, data_size),
    "Pkt_Rate": np.random.uniform(0.1, 200, data_size),
    "Delay": np.random.uniform(1, 100, data_size),
    "Jitter": np.random.uniform(0.1, 50, data_size),
    "Flows": np.random.randint(1, 20, data_size)
})

# 2. MULTI-CLASS LABEL ASSIGNMENT

conditions = [
    (traffic_data["Pkt_Rate"] < 50),
    (traffic_data["Pkt_Rate"] >= 50) & (traffic_data["Pkt_Rate"] < 100),
    (traffic_data["Pkt_Rate"] >= 100) & (traffic_data["Pkt_Rate"] < 150),
    (traffic_data["Pkt_Rate"] >= 150)
]

labels = ["Normal", "UDP_Flood", "TCP_SYN", "HTTP_Flood"]

traffic_data["Attack_Type"] = np.select(conditions, labels, default="Normal")

# 3. PREPROCESSING

X = traffic_data.drop("Attack_Type", axis=1)
y = traffic_data["Attack_Type"]

# Encode labels
encoder = LabelEncoder()
y = encoder.fit_transform(y)

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

# 4. HYBRID MODEL (DBN + SVM)

rbm_layer = BernoulliRBM(n_components=90, learning_rate=0.01, n_iter=25)

svm_classifier = SVC(kernel='rbf', C=12, gamma='scale', decision_function_shape='ovr')

# Pipeline
ddos_model = Pipeline([
    ('dbn', rbm_layer),
    ('svm', svm_classifier)
])

# Train model
ddos_model.fit(X_train, y_train)

# 5. MODEL EVALUATION

y_pred = ddos_model.predict(X_test)

print("=== DDoS Classification Results ===")
print("Accuracy:", accuracy_score(y_test, y_pred))

print("\nDetailed Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=encoder.classes_))


# 6. REAL-TIME CLASSIFICATION FUNCTION

feature_names = X.columns

def classify_network_traffic(sample_features):
    # Convert list → DataFrame with proper column names
    sample_df = pd.DataFrame([sample_features], columns=feature_names)
    
    sample_scaled = scaler.transform(sample_df)
    prediction = ddos_model.predict(sample_scaled)[0]
    
    return encoder.inverse_transform([prediction])[0]

# 7. SINGLE SAMPLE TEST

sample_input = [250, 60000, 160, 30, 15, 8]

result = classify_network_traffic(sample_input)

print("\n=== SAMPLE RESULT ===")
print("Input Features:", sample_input)
print("Predicted Class:", result)

# 8. MULTIPLE SAMPLE TESTS

print("\n=== MULTIPLE SAMPLE TESTS ===")

test_samples = [
    [100, 20000, 30, 10, 5, 3],    # Normal
    [200, 50000, 80, 20, 10, 5],   # UDP_Flood
    [250, 60000, 120, 30, 15, 8],  # TCP_SYN
    [300, 80000, 170, 40, 20, 10]  # HTTP_Flood
]

for sample in test_samples:
    prediction = classify_network_traffic(sample)
    print("Input:", sample, "→ Predicted:", prediction)
