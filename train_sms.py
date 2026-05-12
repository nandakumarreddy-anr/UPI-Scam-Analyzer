import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
import joblib

# Load dataset
data = pd.read_csv("spam.csv", encoding='latin-1')

data = data[['v1', 'v2']]
data.columns = ['label', 'message']

# Convert labels
data['label'] = data['label'].map({'ham': 0, 'spam': 1})

# Vectorize
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(data['message'])
y = data['label']

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train
model = MultinomialNB()
model.fit(X_train, y_train)

# Accuracy
print("Accuracy:", model.score(X_test, y_test))

# Save
joblib.dump(model, "sms_model.pkl")
joblib.dump(vectorizer, "sms_vectorizer.pkl")

print("✅ SMS model trained")