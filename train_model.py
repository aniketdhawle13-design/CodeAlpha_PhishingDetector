import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("Loading dataset...")

df = pd.read_csv("phishing.csv")

print(df.head())

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
X,
y,
test_size=0.2,
random_state=42
)

print("Training model...")

model = RandomForestClassifier(
n_estimators=200,
max_depth=15,
random_state=42
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(
y_test,
predictions
)

print(f"Accuracy: {accuracy*100:.2f}%")

joblib.dump(
model,
"model.pkl"
)

print("Model saved as model.pkl")
