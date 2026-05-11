from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


MODEL_PATH = Path(__file__).with_name("anomaly_model.pkl")

# NORMAL SOC EVENT COUNTS
TRAINING_DATA = np.array([
    [5],
    [7],
    [8],
    [10],
    [12],
    [15],
    [20],
    [22],
    [25],
    [30],
])


def train_model(model_path: Path = MODEL_PATH) -> Path:
    model = IsolationForest(
        contamination=0.1,
        random_state=42,
    )
    model.fit(TRAINING_DATA)
    joblib.dump(model, model_path)
    return model_path


if __name__ == "__main__":
    output_path = train_model()
    print(f"Anomaly detection model trained: {output_path}")
