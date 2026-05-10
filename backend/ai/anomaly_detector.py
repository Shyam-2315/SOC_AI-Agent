import joblib
import numpy as np


MODEL_PATH = "ai/anomaly_model.pkl"


model = joblib.load(MODEL_PATH)


def detect_anomaly(event_count: int):

    data = np.array([[event_count]])

    prediction = model.predict(data)

    score = model.decision_function(data)

    if prediction[0] == -1:

        return {
            "is_anomaly": True,
            "anomaly_score": float(score[0])
        }

    return {
        "is_anomaly": False,
        "anomaly_score": float(score[0])
    }