import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
import joblib

# Load data
data = pd.read_csv("upi_dataset.csv")

X = data['upi']
y = data['label']

# Convert text → numbers
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Split
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2)

# Train
model = MultinomialNB()
model.fit(X_train, y_train)

# Accuracy
print("Accuracy:", model.score(X_test, y_test))

# Save
joblib.dump(model, "upi_model.pkl")
joblib.dump(vectorizer, "upi_vectorizer.pkl")

print("✅ UPI model trained")