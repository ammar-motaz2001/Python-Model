"""
Train brute-force attack detection model (same workflow as DDoS).
Uses mixed_dataset.csv: username, timestamp, passwords, foreign_ip, Label (0=Benign, 1=Attack).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# load dataset
df = pd.read_csv("mixed_dataset.csv")

# label already 0/1
y = df["Label"]

# feature: password attempt count (from string representation of list)
def password_count(s):
    try:
        s = str(s).strip()
        if s.startswith("["):
            return max(1, s.count(",") + 1)
        return 1
    except Exception:
        return 1

df["password_count"] = df["passwords"].apply(password_count)

# features from timestamp: hour, day of week
def parse_ts(ts):
    try:
        t = datetime.strptime(ts.strip(), "%a %b %d %H:%M:%S %Y")
        return t.hour, t.weekday()
    except Exception:
        return 12, 0

df[["hour", "day_of_week"]] = df["timestamp"].apply(
    lambda x: pd.Series(parse_ts(x))
)

# encode categoricals so API can use same encoding
username_enc = LabelEncoder()
ip_enc = LabelEncoder()
df["username_enc"] = username_enc.fit_transform(df["username"].astype(str))
df["foreign_ip_enc"] = ip_enc.fit_transform(df["foreign_ip"].astype(str))

# feature columns (same order as API will send)
feature_cols = [
    "username_enc",
    "hour",
    "day_of_week",
    "password_count",
    "foreign_ip_enc",
]
X = df[feature_cols]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = float(accuracy_score(y_test, y_pred))

joblib.dump(model, "model_bruteforce.pkl")
joblib.dump(username_enc, "username_encoder.pkl")
joblib.dump(ip_enc, "ip_encoder.pkl")

metrics_path = Path("model_metrics.json")
existing: dict = {}
if metrics_path.is_file():
    try:
        existing = json.loads(metrics_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        existing = {}
existing["brute_force"] = {
    "accuracy": round(accuracy, 6),
    "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
    "n_test_samples": int(len(y_test)),
    "test_size_fraction": 0.2,
    "random_state": 42,
}
metrics_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

print("Brute-force model trained and saved successfully!")
print(f"Features: {feature_cols}")
print(f"Test accuracy: {accuracy:.6f} (n_test={len(y_test)})")
