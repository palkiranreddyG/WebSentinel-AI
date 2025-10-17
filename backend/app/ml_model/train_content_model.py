# train_content_model.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import EarlyStopping
from dl_model_builder import build_model
import joblib

# Load data
data = pd.read_csv('app/ml_model/dataset/dataset_full.csv')
X = data['html']
y = data['label']

# Vectorize content
vectorizer = TfidfVectorizer(max_features=1000)
X_vec = vectorizer.fit_transform(X).toarray()

# Save vectorizer
joblib.dump(vectorizer, 'app/ml_model/content_vectorizer.pkl')

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# Build model
model = build_model(input_dim=X_train.shape[1])
early_stop = EarlyStopping(monitor='val_loss', patience=3)

# Train
model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=10, callbacks=[early_stop])

# Save model
model.save('app/ml_model/content_model.h5')
