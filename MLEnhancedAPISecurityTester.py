import requests
import json
import sys
import argparse
import numpy as np
from urllib.parse import urlparse
from prettytable import PrettyTable
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import re
import os


class MLEnhancedAPISecurityTester:
    def __init__(self, config_path='config.json'):
        """
        Initialize the security tester with ML capabilities
        """
        # Load configuration
        with open(config_path) as f:
            self.config = json.load(f)

        # Sensitive keyword detection
        self.sensitive_keywords = self.config.get("sensitive_keywords",
                                                  ["key", "token", "password", "ssn", "credit", "card"])

        # ML model for anomaly detection
        self.anomaly_detector = None
        self.scaler = None

        # Feature extraction and ML model paths
        self.model_path = 'api_security_model.joblib'
        self.scaler_path = 'api_security_scaler.joblib'

    def extract_features(self, response):
        """
        Extract security-relevant features from API response
        """
        features = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'num_sensitive_headers': 0,
            'num_sensitive_keywords': 0,
            'redirects': len(response.history),
            'header_count': len(response.headers)
        }

        # Check headers for sensitive information
        for key, value in response.headers.items():
            if any(sensitive in key.lower() for sensitive in self.sensitive_keywords):
                features['num_sensitive_headers'] += 1

        # Check response content for sensitive keywords
        if response.text:
            features['num_sensitive_keywords'] = sum(
                len(re.findall(keyword, response.text.lower()))
                for keyword in self.sensitive_keywords
            )

        return features

    def train_anomaly_detector(self, training_urls):
        """
        Train an Isolation Forest for anomaly detection
        """
        # Collect features from multiple API responses
        training_features = []
        for url in training_urls:
            try:
                response = requests.get(url, timeout=5)
                features = self.extract_features(response)
                training_features.append(list(features.values()))
            except requests.exceptions.RequestException:
                continue

        # Scale features
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(training_features)

        # Train Isolation Forest
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expect 10% of samples to be anomalous
            random_state=42
        )
        self.anomaly_detector.fit(scaled_features)

        # Save model and scaler
        joblib.dump(self.anomaly_detector, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def load_ml_model(self):
        """
        Load pre-trained ML models if available
        """
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.anomaly_detector = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)

    def detect_ml_anomalies(self, url, headers=None):
        """
        Use ML to detect potential security anomalies
        """
        if not (self.anomaly_detector and self.scaler):
            self.load_ml_model()

        try:
            response = requests.get(url, headers=headers, timeout=5)
            features = self.extract_features(response)

            # Scale features
            scaled_features = self.scaler.transform([list(features.values())])

            # Predict anomaly
            prediction = self.anomaly_detector.predict(scaled_features)

            return {
                'is_anomaly': prediction[0] == -1,
                'features': features,
                'anomaly_score': self.anomaly_detector.decision_function(scaled_features)[0]
            }
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    def run_comprehensive_security_tests(self, url, headers=None):
        """
        Comprehensive security testing with ML enhancement
        """
        results = []

        # Traditional security checks
        results.append(("HTTPS Check", self.check_https(url)))
        results.append(("Authentication Check", self.test_authentication(url, headers)))

        # Sensitive data detection
        try:
            response = requests.get(url, headers=headers, timeout=5)
            sensitive_data = self.detect_sensitive_data(response)
            results.append(("Sensitive Data Check", sensitive_data))
        except requests.exceptions.RequestException as e:
            results.append(("Sensitive Data Check", f"Error: {str(e)}"))

        # ML Anomaly Detection
        ml_results = self.detect_ml_anomalies(url, headers)
        results.append(("ML Anomaly Detection",
                        f"Anomaly Detected: {ml_results.get('is_anomaly', 'N/A')}, "
                        f"Anomaly Score: {ml_results.get('anomaly_score', 'N/A')}"
                        ))

        return results

    # Existing methods from previous implementation
    def check_https(self, url):
        parsed_url = urlparse(url)
        return "Secure (HTTPS)" if parsed_url.scheme == 'https' else "Insecure (HTTP)"

    def test_authentication(self, url, headers=None):
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 401:
                return "Unauthorized (Authentication Required)"
            elif response.status_code == 403:
                return "Forbidden (Token Invalid or Insufficient Permissions)"
            return f"Accessible (Status: {response.status_code})"
        except requests.exceptions.RequestException as e:
            return f"Error: {str(e)}"

    def detect_sensitive_data(self, response):
        findings = []
        try:
            if response.headers.get('Content-Type') == 'application/json':
                data = response.json()
                for key in data.keys():
                    if any(sensitive in key.lower() for sensitive in self.sensitive_keywords):
                        findings.append(f"Sensitive key detected: {key}")

            for key, value in response.headers.items():
                if any(sensitive in key.lower() for sensitive in self.sensitive_keywords):
                    findings.append(f"Sensitive header detected: {key}")
        except json.JSONDecodeError:
            pass

        return findings or "No sensitive data detected"


def display_report(results):
    """
    Displays the test results in a tabular format
    """
    table = PrettyTable()
    table.field_names = ["Test", "Result"]
    for test, result in results:
        if isinstance(result, list):
            result = "\n".join(result)
        table.add_row([test, result])
    print(table)


def main():
    parser = argparse.ArgumentParser(description="ML-Enhanced API Security Tester")
    parser.add_argument("url", help="API endpoint URL")
    parser.add_argument("--headers", help="Headers as JSON string", default="{}")
    parser.add_argument("--train", help="URLs for training ML model", nargs='+')
    args = parser.parse_args()

    # Process arguments
    url = args.url
    headers = json.loads(args.headers)

    # Initialize security tester
    security_tester = MLEnhancedAPISecurityTester()

    # Train ML model if training URLs provided
    if args.train:
        security_tester.train_anomaly_detector(args.train)
    else:
        security_tester.load_ml_model()

    # Run comprehensive security tests
    results = security_tester.run_comprehensive_security_tests(url, headers)

    # Display report
    display_report(results)


if __name__ == "__main__":
    main()