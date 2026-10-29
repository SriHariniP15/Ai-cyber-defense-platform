
from sklearn.ensemble import IsolationForest

# A small synthetic dataset for demonstrating the ML pipeline.
# Values represent:
# [failed logins, requests per minute, unusual port, malware alert]
TRAINING_DATA = [
    [0, 10, 0, 0],
    [1, 15, 0, 0],
    [0, 20, 0, 0],
    [1, 25, 0, 0],
    [2, 30, 0, 0],
    [0, 12, 0, 0],
    [1, 18, 0, 0],
    [2, 22, 0, 0],
    [12, 250, 1, 0],
    [20, 400, 1, 0],
    [15, 300, 1, 1],
    [30, 500, 1, 1],
]

model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)

model.fit(TRAINING_DATA)


def detect_anomaly(
    failed_logins: int,
    requests_per_minute: int,
    unusual_port: int,
    malware_alert: int
) -> dict:
    features = [[
        failed_logins,
        requests_per_minute,
        unusual_port,
        malware_alert
    ]]

    prediction = int(model.predict(features)[0])
    anomaly_score = float(model.decision_function(features)[0])

    return {
        "is_anomaly": prediction == -1,
        "anomaly_score": round(anomaly_score, 4),
        "model": "IsolationForest"
    }


if __name__ == "__main__":
    result = detect_anomaly(
        failed_logins=20,
        requests_per_minute=400,
        unusual_port=1,
        malware_alert=0
    )
    print(result)

