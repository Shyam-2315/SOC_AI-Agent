import numpy as np
import joblib

from sklearn.ensemble import IsolationForest


# NORMAL SOC EVENT COUNTS
X = np.array([
    [5],
    [7],
    [8],
    [10],
    [12],
    [15],
    [20],
    [22],
    [25],
    [30]
])


model = IsolationForest(
    contamination=0.1,
    random_state=42
)

model.fit(X)

joblib.dump(
    model,
    "ai/anomaly_model.pkl"
)

print("Anomaly detection model trained")