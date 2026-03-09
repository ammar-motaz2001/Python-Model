import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# load dataset (Excel; fallback to CSV if present)
try:
    df = pd.read_excel("ddos_dataset.xlsx")
except FileNotFoundError:
    df = pd.read_csv("ddos.csv")

# convert label
df["Label"] = df["Label"].apply(lambda x: 0 if x == "Benign" else 1)

# split features and target
X = df.drop("Label", axis=1)
y = df["Label"]

# split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# create model
model = RandomForestClassifier(n_estimators=100)

# train model
model.fit(X_train, y_train)

# save model
joblib.dump(model, "model.pkl")

print("Model trained and saved successfully!")