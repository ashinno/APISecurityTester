import os
import json
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from typing import Dict, List, Any


class MobileAppSecurityFramework:
    def __init__(self, config_path: str = 'config.json'):
        """
        Initialize the Mobile App Security Testing Framework

        :param config_path: Path to configuration file
        """
        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {}

        # Initialize components
        self.vulnerability_model = None
        self.dataset = None
        self.preprocessor = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.X_train_scaled = None
        self.X_test_scaled = None

    def load_dataset(self, dataset_path: str):
        """
        Load and preprocess the mobile app security dataset

        :param dataset_path: Path to the dataset CSV
        """
        # Ensure dataset exists
        if not os.path.exists(dataset_path):
            # Generate dataset if not exists
            from mobile_security_dataset import generate_mobile_app_vulnerability_dataset
            generate_mobile_app_vulnerability_dataset(n_samples=1000)

        # Load dataset
        self.dataset = pd.read_csv(dataset_path)

        # Preprocessing
        self.preprocessor = StandardScaler()

        # Separate features and labels
        X = self.dataset.drop('vulnerability_label', axis=1)
        y = self.dataset['vulnerability_label']

        # Split the data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        # Scale features
        self.X_train_scaled = self.preprocessor.fit_transform(self.X_train)
        self.X_test_scaled = self.preprocessor.transform(self.X_test)

    def build_ml_model(self):
        """
        Build and compile the vulnerability detection neural network
        """
        # Ensure dataset is loaded
        if self.X_train_scaled is None:
            raise ValueError("Dataset must be loaded first. Call load_dataset() method.")

        self.vulnerability_model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(self.X_train_scaled.shape[1],)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

        self.vulnerability_model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )

    def train_model(self, epochs: int = 50, batch_size: int = 32):
        """
        Train the vulnerability detection model

        :param epochs: Number of training epochs
        :param batch_size: Training batch size
        """
        # Ensure model is built
        if self.vulnerability_model is None:
            raise ValueError("Model must be built first. Call build_ml_model() method.")

        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )

        history = self.vulnerability_model.fit(
            self.X_train_scaled,
            self.y_train,
            validation_split=0.2,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping]
        )

        return history

    def evaluate_model(self):
        """
        Evaluate the model's performance

        :return: Comprehensive performance metrics
        """
        # Predict on test data
        y_pred = (self.vulnerability_model.predict(self.X_test_scaled) > 0.5).astype(int)

        # Generate classification report
        report = classification_report(
            self.y_test,
            y_pred,
            target_names=['No Vulnerability', 'Vulnerability']
        )

        # Confusion Matrix
        cm = confusion_matrix(self.y_test, y_pred)

        return {
            'classification_report': report,
            'confusion_matrix': cm
        }

    def detect_vulnerabilities(self, app_features: Dict[str, Any]) -> Dict[str, float]:
        """
        Detect vulnerabilities in a mobile application

        :param app_features: Dictionary of application features
        :return: Vulnerability scores and types
        """
        # Ensure preprocessor exists
        if self.preprocessor is None:
            raise ValueError("Dataset must be loaded first. Call load_dataset() method.")

        # Convert input to scaled features
        features_array = self.preprocessor.transform(
            pd.DataFrame([app_features])
        )

        # Predict vulnerability probability
        vulnerability_prob = self.vulnerability_model.predict(features_array)[0][0]

        vulnerability_types = {
            'insecure_storage': vulnerability_prob * 0.4,
            'weak_encryption': vulnerability_prob * 0.3,
            'api_misuse': vulnerability_prob * 0.3
        }

        return {
            'total_vulnerability_score': vulnerability_prob,
            'vulnerability_breakdown': vulnerability_types
        }

    def generate_security_report(self, results: Dict[str, Any]) -> str:
        """
        Generate a detailed security report

        :param results: Vulnerability detection results
        :return: Formatted security report
        """
        report = "Mobile App Security Assessment Report\n"
        report += "=" * 40 + "\n\n"

        report += f"Total Vulnerability Score: {results['total_vulnerability_score']:.2%}\n\n"

        report += "Vulnerability Breakdown:\n"
        for vuln_type, score in results['vulnerability_breakdown'].items():
            report += f"- {vuln_type.replace('_', ' ').title()}: {score:.2%}\n"

        return report


def generate_mobile_app_vulnerability_dataset(n_samples=1000):
    """
    Generate a synthetic mobile app vulnerability dataset

    :param n_samples: Number of sample applications
    :return: DataFrame with mobile app security features
    """
    import numpy as np
    import pandas as pd
    from sklearn.datasets import make_classification

    # Generate feature matrix
    X, y = make_classification(
        n_samples=n_samples,
        n_features=10,  # Multiple security-related features
        n_informative=7,
        n_redundant=3,
        random_state=42
    )

    # Create feature names representing security attributes
    feature_names = [
        'storage_encryption_level',
        'api_security_score',
        'data_transmission_security',
        'authentication_strength',
        'input_validation_score',
        'network_communication_security',
        'third_party_library_risk',
        'runtime_permissions_management',
        'code_obfuscation_level',
        'certificate_pinning_implementation'
    ]

    # Create DataFrame
    df = pd.DataFrame(X, columns=feature_names)

    # Add vulnerability label
    df['vulnerability_label'] = y

    # Add some realistic variations
    df['storage_encryption_level'] = np.clip(df['storage_encryption_level'], 0, 1)
    df['api_security_score'] = np.abs(df['api_security_score'])

    # Save dataset
    df.to_csv('mobile_app_vulnerabilities.csv', index=False)
    return df


# Main execution script
def main():
    # Ensure dataset is generated
    generate_mobile_app_vulnerability_dataset()

    # Initialize framework
    security_framework = MobileAppSecurityFramework()

    # Load dataset
    security_framework.load_dataset('mobile_app_vulnerabilities.csv')

    # Build ML model
    security_framework.build_ml_model()

    # Train model
    training_history = security_framework.train_model()

    # Evaluate model
    model_performance = security_framework.evaluate_model()
    print("Model Performance:")
    print(model_performance['classification_report'])

    # Example app vulnerability detection
    sample_app_features = {
        'storage_encryption_level': 0.3,
        'api_security_score': 0.2,
        'data_transmission_security': 0.4,
        'authentication_strength': 0.1,
        'input_validation_score': 0.2,
        'network_communication_security': 0.3,
        'third_party_library_risk': 0.4,
        'runtime_permissions_management': 0.2,
        'code_obfuscation_level': 0.1,
        'certificate_pinning_implementation': 0.2
    }

    vulnerability_results = security_framework.detect_vulnerabilities(sample_app_features)

    # Generate security report
    security_report = security_framework.generate_security_report(vulnerability_results)
    print("\nSecurity Report:")
    print(security_report)


if __name__ == "__main__":
    main()