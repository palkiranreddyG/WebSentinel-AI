import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import logging

# Set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLThreatTrainer:
    def __init__(self):
        """Initialize trainer with paths"""
        self.dataset_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "dataset", "dataset_full.csv"
        )
        self.model_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "url_model.keras"
        )
        self.scaler_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "url_scaler.pkl"
        )
        self.feature_names = self._get_feature_names()
        self.model = None
        self.scaler = None

    def _get_feature_names(self):
        """Define feature names in the same order as url_predictor.py"""
        features = [
            'asn_ip', 'directory_length', 'domain_google_index', 'domain_in_ip',
            'domain_length', 'domain_spf', 'email_in_url', 'file_length',
            'params_length', 'qty_and_directory', 'qty_and_domain', 'qty_and_file', 'qty_and_params',
            'qty_and_url', 'qty_asterisk_directory', 'qty_asterisk_domain', 'qty_asterisk_file',
            'qty_asterisk_params', 'qty_asterisk_url', 'qty_at_directory', 'qty_at_domain', 'qty_at_file',
            'qty_at_params', 'qty_at_url', 'qty_comma_directory', 'qty_comma_domain', 'qty_comma_file',
            'qty_comma_params', 'qty_comma_url', 'qty_dollar_directory', 'qty_dollar_domain',
            'qty_dollar_file', 'qty_dollar_params', 'qty_dollar_url', 'qty_dot_directory',
            'qty_dot_domain', 'qty_dot_file', 'qty_dot_params', 'qty_dot_url', 'qty_equal_directory',
            'qty_equal_domain', 'qty_equal_file', 'qty_equal_params', 'qty_equal_url',
            'qty_exclamation_directory', 'qty_exclamation_domain', 'qty_exclamation_file',
            'qty_exclamation_params', 'qty_exclamation_url', 'qty_hashtag_directory',
            'qty_hashtag_domain', 'qty_hashtag_file', 'qty_hashtag_params', 'qty_hashtag_url',
            'qty_hyphen_directory', 'qty_hyphen_domain', 'qty_hyphen_file', 'qty_hyphen_params',
            'qty_hyphen_url', 'qty_ip_resolved', 'qty_mx_servers', 'qty_nameservers',
            'qty_percent_directory', 'qty_percent_domain', 'qty_percent_file', 'qty_percent_params',
            'qty_percent_url', 'qty_plus_directory', 'qty_plus_domain', 'qty_plus_file',
            'qty_plus_params', 'qty_plus_url', 'qty_params', 'qty_questionmark_directory',
            'qty_questionmark_domain', 'qty_questionmark_file', 'qty_questionmark_params',
            'qty_questionmark_url', 'qty_redirects', 'qty_slash_directory', 'qty_slash_domain',
            'qty_slash_file', 'qty_slash_params', 'qty_slash_url', 'qty_space_directory',
            'qty_space_domain', 'qty_space_file', 'qty_space_params', 'qty_space_url',
            'qty_tilde_directory', 'qty_tilde_domain', 'qty_tilde_file', 'qty_tilde_params',
            'qty_tilde_url', 'qty_tld_url', 'qty_underline_directory', 'qty_underline_domain',
            'qty_underline_file', 'qty_underline_params', 'qty_underline_url', 'qty_vowels_domain',
            'server_client_domain',
             'time_domain_activation', 'time_domain_expiration',
            'time_response', 'tls_ssl_certificate', 'tld_present_params', 'ttl_hostname',
            'url_google_index', 'url_shortened', 'length_url'
        ]
        return features

    def load_data(self):
        """Load and preprocess the dataset"""
        logger.info("Loading dataset...")
        try:
            df = pd.read_csv(self.dataset_path)
            X = df[self.feature_names]
            y = df['phishing']
            logger.info(f"Dataset loaded: {X.shape[0]} samples, {X.shape[1]} features")
            return X, y
        except Exception as e:
            logger.error(f"Failed to load dataset: {str(e)}")
            raise

    def preprocess_data(self, X, y):
        """Split and scale the data"""
        logger.info("Preprocessing data...")
        try:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Save the scaler
            joblib.dump(self.scaler, self.scaler_path)
            logger.info(f"Scaler saved to {self.scaler_path}")
            
            return X_train_scaled, X_test_scaled, y_train, y_test
        except Exception as e:
            logger.error(f"Failed to preprocess data: {str(e)}")
            raise

    def build_model(self):
        """Build the neural network model"""
        logger.info("Building model...")
        try:
            self.model = Sequential([
                Dense(64, activation='relu', input_shape=(len(self.feature_names),)),
                Dense(32, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            logger.info("Model built successfully")
        except Exception as e:
            logger.error(f"Failed to build model: {str(e)}")
            raise

    def train(self, X_train, y_train, X_test, y_test):
        """Train the model"""
        logger.info("Training model...")
        try:
            self.model.fit(
                X_train, y_train,
                epochs=10,
                batch_size=32,
                validation_data=(X_test, y_test),
                verbose=1
            )
            self.model.save(self.model_path)
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to train model: {str(e)}")
            raise

    def evaluate(self, X_test, y_test):
        """Evaluate the model"""
        logger.info("Evaluating model...")
        try:
            loss, accuracy = self.model.evaluate(X_test, y_test, verbose=0)
            logger.info(f"Test Accuracy: {accuracy:.4f}, Test Loss: {loss:.4f}")
            return accuracy
        except Exception as e:
            logger.error(f"Failed to evaluate model: {str(e)}")
            raise

def main():
    trainer = URLThreatTrainer()
    
    # Load and preprocess data
    X, y = trainer.load_data()
    X_train_scaled, X_test_scaled, y_train, y_test = trainer.preprocess_data(X, y)
    
    # Build and train the model
    trainer.build_model()
    trainer.train(X_train_scaled, y_train, X_test_scaled, y_test)
    
    # Evaluate the model
    accuracy = trainer.evaluate(X_test_scaled, y_test)
    print(f"Final Test Accuracy: {accuracy:.4f}")

if __name__ == "__main__":
    main()