import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
data = pd.read_csv("url_dataset.csv")

# 🔥 Use ALL features except url and label
X = data.drop(['url', 'status'], axis=1)
y = data['status']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# 🔥 Better model for this dataset
model = RandomForestClassifier(n_estimators=100)

# Train
model.fit(X_train, y_train)

# Accuracy
accuracy = model.score(X_test, y_test)
print("Accuracy:", accuracy)

# Save model
joblib.dump(model, "url_model.pkl")

print("✅ URL Model trained successfully")