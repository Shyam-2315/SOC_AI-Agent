from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np

from ai.train_model import train_model


MODEL_PATH = Path(__file__).with_name("anomaly_model.pkl")


@lru_cache(maxsize=1)
def get_model():
    if not MODEL_PATH.exists():
        train_model(MODEL_PATH)
    return joblib.load(MODEL_PATH)


def detect_anomaly(event_count: int):
    data = np.array([[event_count]])
    model = get_model()
    prediction = model.predict(data)
    score = model.decision_function(data)

    if prediction[0] == -1:
        return {
            "is_anomaly": True,
            "anomaly_score": float(score[0]),
        }

    return {
        "is_anomaly": False,
        "anomaly_score": float(score[0]),
    }
