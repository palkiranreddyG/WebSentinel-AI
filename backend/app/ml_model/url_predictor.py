import os
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from tensorflow.keras.models import load_model
import requests
import whois
import dns.resolver
from datetime import datetime
import logging

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class ThreatPredictor:
    def __init__(self):
        """Initialize predictor with automatic feature alignment"""
        self.model_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "url_model.keras"
        )
        self.scaler_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "url_scaler.pkl"
        )
        self.dataset_path = os.path.join(
            r"C:\Users\Krupa\OneDrive\Desktop\WEB DEV\Projects\ai-threat-detector\backend",
            "app", "ml_model", "dataset", "dataset_full.csv"
        )
        try:
            self.model = load_model(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.feature_names = self._get_feature_names()
            logger.info(f"🔢 Model loaded successfully with {len(self.feature_names)} features")
        except Exception as e:
            logger.error(f"Failed to initialize ThreatPredictor: {str(e)}")
            raise

    def _get_feature_names(self):
        """Define feature names in the order expected by the trained model (alphabetical for simplicity)"""
        features = [
            'asn_ip','directory_length', 'domain_google_index', 'domain_in_ip',
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
            'server_client_domain', 'time_domain_activation', 'time_domain_expiration',
            'time_response', 'tls_ssl_certificate', 'tld_present_params', 'ttl_hostname',
            'url_google_index', 'url_shortened', 'length_url'
        ]
        return features

    def extract_features(self, url):
        """Extract all features from the URL"""
        features = {name: 0 for name in self.feature_names}  # Initialize all to 0
        
        try:
            # Parse the URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query
            scheme = parsed.scheme

            # --- URL-level features ---
            features['length_url'] = len(url)
            features['qty_dot_url'] = url.count('.')
            features['qty_hyphen_url'] = url.count('-')
            features['qty_underline_url'] = url.count('_')
            features['qty_slash_url'] = url.count('/')
            features['qty_questionmark_url'] = url.count('?')
            features['qty_equal_url'] = url.count('=')
            features['qty_at_url'] = url.count('@')
            features['qty_and_url'] = url.count('&')
            features['qty_exclamation_url'] = url.count('!')
            features['qty_space_url'] = url.count(' ')
            features['qty_tilde_url'] = url.count('~')
            features['qty_comma_url'] = url.count(',')
            features['qty_plus_url'] = url.count('+')
            features['qty_asterisk_url'] = url.count('*')
            features['qty_hashtag_url'] = url.count('#')
            features['qty_dollar_url'] = url.count('$')
            features['qty_percent_url'] = url.count('%')
            features['qty_tld_url'] = len([part for part in domain.split('.') if part in ['com', 'org', 'net', 'co', 'in', 'uk']])

            # --- Domain-level features ---
            features['qty_dot_domain'] = domain.count('.')
            features['qty_hyphen_domain'] = domain.count('-')
            features['qty_underline_domain'] = domain.count('_')
            features['qty_slash_domain'] = domain.count('/')
            features['qty_questionmark_domain'] = domain.count('?')
            features['qty_equal_domain'] = domain.count('=')
            features['qty_at_domain'] = domain.count('@')
            features['qty_and_domain'] = domain.count('&')
            features['qty_exclamation_domain'] = domain.count('!')
            features['qty_space_domain'] = domain.count(' ')
            features['qty_tilde_domain'] = domain.count('~')
            features['qty_comma_domain'] = domain.count(',')
            features['qty_plus_domain'] = domain.count('+')
            features['qty_asterisk_domain'] = domain.count('*')
            features['qty_hashtag_domain'] = domain.count('#')
            features['qty_dollar_domain'] = domain.count('$')
            features['qty_percent_domain'] = domain.count('%')
            features['qty_vowels_domain'] = sum(1 for char in domain if char in 'aeiou')
            features['domain_length'] = len(domain)
            features['domain_in_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
            features['server_client_domain'] = 1 if 'server' in domain or 'client' in domain else 0
            features['suspicious_domain_keywords'] = 1 if any(keyword in domain for keyword in ['login', 'secure', 'update', 'verify', 'account']) else 0

            # --- Directory-level features ---
            if path:
                dir_path = '/'.join(path.split('/')[:-1]) if '.' in path.split('/')[-1] else path
                features['qty_dot_directory'] = dir_path.count('.')
                features['qty_hyphen_directory'] = dir_path.count('-')
                features['qty_underline_directory'] = dir_path.count('_')
                features['qty_slash_directory'] = dir_path.count('/')
                features['qty_questionmark_directory'] = dir_path.count('?')
                features['qty_equal_directory'] = dir_path.count('=')
                features['qty_at_directory'] = dir_path.count('@')
                features['qty_and_directory'] = dir_path.count('&')
                features['qty_exclamation_directory'] = dir_path.count('!')
                features['qty_space_directory'] = dir_path.count(' ')
                features['qty_tilde_directory'] = dir_path.count('~')
                features['qty_comma_directory'] = dir_path.count(',')
                features['qty_plus_directory'] = dir_path.count('+')
                features['qty_asterisk_directory'] = dir_path.count('*')
                features['qty_hashtag_directory'] = dir_path.count('#')
                features['qty_dollar_directory'] = dir_path.count('$')
                features['qty_percent_directory'] = dir_path.count('%')
                features['directory_length'] = len(dir_path)
                features['suspicious_directory_keywords'] = 1 if any(keyword in dir_path.lower() for keyword in ['hidden', 'bin', 'temp', 'download']) else 0

            # --- File-level features ---
            if path and '.' in path.split('/')[-1]:
                file_name = path.split('/')[-1]
                features['qty_dot_file'] = file_name.count('.')
                features['qty_hyphen_file'] = file_name.count('-')
                features['qty_underline_file'] = file_name.count('_')
                features['qty_slash_file'] = file_name.count('/')
                features['qty_questionmark_file'] = file_name.count('?')
                features['qty_equal_file'] = file_name.count('=')
                features['qty_at_file'] = file_name.count('@')
                features['qty_and_file'] = file_name.count('&')
                features['qty_exclamation_file'] = file_name.count('!')
                features['qty_space_file'] = file_name.count(' ')
                features['qty_tilde_file'] = file_name.count('~')
                features['qty_comma_file'] = file_name.count(',')
                features['qty_plus_file'] = file_name.count('+')
                features['qty_asterisk_file'] = file_name.count('*')
                features['qty_hashtag_file'] = file_name.count('#')
                features['qty_dollar_file'] = file_name.count('$')
                features['qty_percent_file'] = file_name.count('%')
                features['file_length'] = len(file_name)
                features['suspicious_file_extension'] = 1 if file_name.split('.')[-1].lower() in ['exe', 'spc', 'bat', 'cmd', 'dll'] else 0
                features['malware_file_name'] = 1 if any(name in file_name.lower() for name in ['boatnet', 'mirai', 'gafgyt']) else 0

            # --- Parameter-level features ---
            if query:
                features['qty_dot_params'] = query.count('.')
                features['qty_hyphen_params'] = query.count('-')
                features['qty_underline_params'] = query.count('_')
                features['qty_slash_params'] = query.count('/')
                features['qty_questionmark_params'] = query.count('?')
                features['qty_equal_params'] = query.count('=')
                features['qty_at_params'] = query.count('@')
                features['qty_and_params'] = query.count('&')
                features['qty_exclamation_params'] = query.count('!')
                features['qty_space_params'] = query.count(' ')
                features['qty_tilde_params'] = query.count('~')
                features['qty_comma_params'] = query.count(',')
                features['qty_plus_params'] = query.count('+')
                features['qty_asterisk_params'] = query.count('*')
                features['qty_hashtag_params'] = query.count('#')
                features['qty_dollar_params'] = query.count('$')
                features['qty_percent_params'] = query.count('%')
                features['params_length'] = len(query)
                features['tld_present_params'] = 1 if any(tld in query for tld in ['com', 'org', 'net', 'co', 'in', 'uk']) else 0
                features['qty_params'] = len(query.split('&')) if query else 0

            # --- Additional features ---
            features['email_in_url'] = 1 if '@' in url and not domain.count('@') else 0
            features['time_response'] = 0.5  # Approximation
            features['asn_ip'] = 0  # Requires DNS lookup
            features['qty_ip_resolved'] = 1  # Default
            features['qty_nameservers'] = 2  # Typical value
            features['qty_mx_servers'] = 1  # Typical value
            features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
            features['url_google_index'] = 1  # Assume indexed
            features['domain_google_index'] = 1  # Assume indexed
            features['url_shortened'] = 1 if any(shortener in domain for shortener in ['bit.ly', 'goo.gl', 'tinyurl', 't.co']) else 0
            features['brand_impersonation'] = 0
            for brand in ['amazon', 'paypal', 'google', 'facebook']:
                if brand in domain.replace('0', 'o').replace('1', 'i'):
                    features['brand_impersonation'] = 1
                    break

            # --- Features required by the training data ---
            # Domain Age (in days)
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    features['time_domain_activation'] = (datetime.now() - creation_date).days
                else:
                    features['time_domain_activation'] = 0  # Unknown
                if w.expiration_date:
                    expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                    features['time_domain_expiration'] = (expiration_date - datetime.now()).days
                else:
                    features['time_domain_expiration'] = 0  # Unknown
            except Exception as e:
                logger.warning(f"Failed to fetch WHOIS for {domain}: {str(e)}")
                features['time_domain_activation'] = 0
                features['time_domain_expiration'] = 0

            # Number of Redirects
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                features['qty_redirects'] = len(response.history) if response.history else 0
            except Exception as e:
                logger.warning(f"Failed to fetch redirects for {url}: {str(e)}")
                features['qty_redirects'] = 0

            # TTL Hostname
            try:
                answers = dns.resolver.resolve(domain, 'A')
                features['ttl_hostname'] = answers.ttl if answers else 0
            except Exception as e:
                logger.warning(f"Failed to fetch TTL for {domain}: {str(e)}")
                features['ttl_hostname'] = 0

            # SPF Record
            features['domain_spf'] = 0
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = rdata.to_text()
                    if "v=spf1" in txt.lower():
                        features['domain_spf'] = 1
                        break
            except Exception as e:
                logger.warning(f"Failed to fetch DNS records for {domain}: {str(e)}")

            logger.debug(f"Extracted features for {url}: {features}")

        except Exception as e:
            logger.error(f"Error extracting features for {url}: {str(e)}")
            raise
        
        return features

    def predict(self, features):
        """Make prediction with extracted features"""
        try:
            input_df = pd.DataFrame([features])[self.feature_names]
            input_scaled = self.scaler.transform(input_df)
            prob = float(self.model.predict(input_scaled, verbose=0)[0][0])
            features_detected = len([f for f in features if features[f] != 0])

            # Adjust probability based on features
            if features['tls_ssl_certificate'] == 1:  # HTTPS
                prob *= 0.8
            if features['time_domain_activation'] > 365:  # Older than 1 year
                prob *= 0.7
            if features['domain_spf'] == 1:
                prob *= 0.6
            prob = min(max(prob, 0.0), 1.0)  # Clamp between 0 and 1

            return {
                'probability': prob,
                'risk': '🛑 HIGH RISK' if prob > 0.75 else '✅ LIKELY SAFE',
                'features_detected': features_detected
            }
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise

def predict_url_threat(url):
    """Wrapper function to predict URL threat using ThreatPredictor"""
    predictor = ThreatPredictor()
    features = predictor.extract_features(url)
    result = predictor.predict(features)
    return result['probability'], result['features_detected']

def main():
    print("🚀 URL Threat Predictor")
    print("1. Check URL (automatic feature extraction)")
    print("2. Enter features manually (advanced)")
    print("3. Exit")
    
    predictor = ThreatPredictor()
    
    while True:
        choice = input("\nChoose option (1-3): ")
        
        if choice == "1":
            url = input("Enter URL to check: ").strip()
            if not url:
                print("❌ Please enter a valid URL")
                continue
                
            print("\n🔍 Analyzing URL...")
            features = predictor.extract_features(url)
            result = predictor.predict(features)
            
            if 'error' in result:
                print(f"❌ Prediction error: {result['error']}")
            else:
                print(f"\n📊 Results for: {url}")
                print(f"Risk Probability: {result['probability']:.4f}")
                print(f"Verdict: {result['risk']}")
                print(f"Features Detected: {result['features_detected']}/{len(predictor.feature_names)}")
                
        elif choice == "2":
            print("\nEnter features manually (press Enter for 0):")
            features = {name: 0 for name in predictor.feature_names}
            for name in predictor.feature_names:
                value = input(f"{name}: ") or "0"
                try:
                    features[name] = float(value)
                except ValueError:
                    features[name] = 0.0
            result = predictor.predict(features)
            if 'error' in result:
                print(f"❌ Prediction error: {result['error']}")
            else:
                print(f"\n📊 Prediction Result:")
                print(f"Risk Probability: {result['probability']:.4f}")
                print(f"Verdict: {result['risk']}")
                print(f"Features Detected: {result['features_detected']}/{len(predictor.feature_names)}")
            
        elif choice == "3":
            print("Exiting...")
            break
            
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()