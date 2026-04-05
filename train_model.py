import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Load dataset
data = pd.read_csv("dataset.csv")

# Input (URLs)
X = data["url"]

# Output (0 = safe, 1 = phishing)
y = data["label"]

# Convert text into numbers
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)

# Train ML model
model = LogisticRegression()
model.fit(X_vec, y)

# Save model files
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Model trained and saved successfully!")