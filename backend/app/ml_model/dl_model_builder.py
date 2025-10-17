from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.preprocessing import StandardScaler
import joblib

def build_model():
    """Build a NN for 77 features. Returns model and scaler."""
    model = Sequential([
        Dense(128, activation='relu', input_dim=77),  # 77 input features
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model, StandardScaler()  # Scaler must be fitted later