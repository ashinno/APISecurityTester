import os
import json
import numpy as np
import pandas as pd
import tensorflow as tf
import matplotlib.pyplot as plt
import logging
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, precision_recall_curve
)
from typing import Dict, List, Any
from sklearn.datasets import make_classification


class MobileAppSecurityFramework:
    def __init__(self, config_path: str = 'config.json'):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_framework.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Load configuration
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {}
            self.logger.warning(f"Config file not found at {config_path}, using defaults")

        # Validate configuration
        self.validate_config()

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

    def validate_config(self):
        """Validate configuration settings"""
        required_config = {
            'model_params': {
                'learning_rate': float,
                'dropout_rate': float,
                'batch_size': int
            },
            'training_params': {
                'epochs': int,
                'validation_split': float
            }
        }
        
        for section, params in required_config.items():
            if section not in self.config:
                self.config[section] = {}
            
            for param, param_type in params.items():
                if param not in self.config[section]:
                    if param_type == float:
                        self.config[section][param] = 0.001 if param == 'learning_rate' else 0.3
                    elif param_type == int:
                        self.config[section][param] = 32 if param == 'batch_size' else 50

    def validate_features(self, app_features: Dict[str, Any]) -> bool:
        """Validate input features"""
        required_features = [
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
        
        missing_features = set(required_features) - set(app_features.keys())
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")
            
        for feature, value in app_features.items():
            if not isinstance(value, (int, float)):
                raise TypeError(f"Feature {feature} must be numeric")
            if not 0 <= value <= 1:
                raise ValueError(f"Feature {feature} must be between 0 and 1")
                
        return True

    def load_dataset(self, dataset_path: str):
        """Load and preprocess the mobile app security dataset"""
        self.logger.info(f"Loading dataset from {dataset_path}")
        
        if not os.path.exists(dataset_path):
            self.logger.info("Dataset not found. Generating new dataset...")
            self.generate_dataset()

        self.dataset = pd.read_csv(dataset_path)
        self.preprocessor = StandardScaler()

        X = self.dataset.drop('vulnerability_label', axis=1)
        y = self.dataset['vulnerability_label']

        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        self.X_train_scaled = self.preprocessor.fit_transform(self.X_train)
        self.X_test_scaled = self.preprocessor.transform(self.X_test)
        self.logger.info("Dataset loaded and preprocessed successfully")

    def generate_dataset(self, n_samples=1000):
        """Generate synthetic security dataset"""
        X, y = make_classification(
            n_samples=n_samples,
            n_features=10,
            n_informative=7,
            n_redundant=3,
            random_state=42
        )

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

        df = pd.DataFrame(X, columns=feature_names)
        df['vulnerability_label'] = y

        df['storage_encryption_level'] = np.clip(df['storage_encryption_level'], 0, 1)
        df['api_security_score'] = np.abs(df['api_security_score'])

        df.to_csv('mobile_app_vulnerabilities.csv', index=False)
        self.logger.info(f"Generated dataset with {n_samples} samples")
        return df

    def build_ml_model(self):
        """Build and compile the vulnerability detection model with improved architecture"""
        if self.X_train_scaled is None:
            raise ValueError("Dataset must be loaded first")

        self.vulnerability_model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', 
                                input_shape=(self.X_train_scaled.shape[1],)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(self.config['model_params']['dropout_rate']),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(self.config['model_params']['dropout_rate']),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(self.config['model_params']['dropout_rate']/2),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

        self.vulnerability_model.compile(
            optimizer=tf.keras.optimizers.Adam(
                learning_rate=self.config['model_params']['learning_rate']
            ),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC(), tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        self.logger.info("Enhanced model built successfully")

    def train_model(self):
        """Train the vulnerability detection model with extended training"""
        if self.vulnerability_model is None:
            raise ValueError("Model must be built first")

        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=15,  # Increased patience
            restore_best_weights=True
        )

        reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.2,
            patience=5,
            min_lr=0.0001
        )

        history = self.vulnerability_model.fit(
            self.X_train_scaled,
            self.y_train,
            validation_split=self.config['training_params']['validation_split'],
            epochs=100,  # Increased epochs for better training
            batch_size=self.config['model_params']['batch_size'],
            callbacks=[early_stopping, reduce_lr]
        )
        
        self.logger.info("Extended model training completed")
        return history

    def save_model(self, model_path: str = 'models/vulnerability_model.h5'):
        """Save the trained model"""
        if self.vulnerability_model is None:
            raise ValueError("No model to save")
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        self.vulnerability_model.save(model_path)
        self.logger.info(f"Model saved to {model_path}")

    def load_saved_model(self, model_path: str = 'models/vulnerability_model.h5'):
        """Load a previously trained model"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"No model found at {model_path}")
        
        self.vulnerability_model = tf.keras.models.load_model(model_path)
        self.logger.info(f"Model loaded from {model_path}")

    def plot_training_history(self, history):
        """Visualize training metrics"""
        plt.figure(figsize=(12, 4))
        
        plt.subplot(1, 2, 1)
        plt.plot(history.history['loss'], label='Training Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title('Model Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        plt.plot(history.history['accuracy'], label='Training Accuracy')
        plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
        plt.title('Model Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('training_history.png')
        plt.close()
        self.logger.info("Training history plot saved")

    def evaluate_model(self):
        """Evaluate model performance"""
        y_pred = (self.vulnerability_model.predict(self.X_test_scaled) > 0.5).astype(int)

        report = classification_report(
            self.y_test,
            y_pred,
            target_names=['No Vulnerability', 'Vulnerability']
        )

        cm = confusion_matrix(self.y_test, y_pred)
        
        self.logger.info("Model evaluation completed")
        return {
            'classification_report': report,
            'confusion_matrix': cm
        }

    def calculate_advanced_metrics(self):
        """Calculate additional performance metrics"""
        y_pred_prob = self.vulnerability_model.predict(self.X_test_scaled)
        y_pred = (y_pred_prob > 0.5).astype(int)
        
        fpr, tpr, _ = roc_curve(self.y_test, y_pred_prob)
        roc_auc = auc(fpr, tpr)
        
        precision, recall, _ = precision_recall_curve(self.y_test, y_pred_prob)
        pr_auc = auc(recall, precision)
        
        self.logger.info("Advanced metrics calculated")
        return {
            'roc_auc': roc_auc,
            'pr_auc': pr_auc,
            'fpr': fpr,
            'tpr': tpr,
            'precision': precision,
            'recall': recall
        }

    def detect_vulnerabilities(self, app_features: Dict[str, Any]) -> Dict[str, float]:
        """Detect vulnerabilities in a mobile application"""
        self.validate_features(app_features)
        
        if self.preprocessor is None:
            raise ValueError("Dataset must be loaded first")

        features_array = self.preprocessor.transform(
            pd.DataFrame([app_features])
        )

        vulnerability_prob = self.vulnerability_model.predict(features_array)[0][0]

        vulnerability_types = {
            'insecure_storage': vulnerability_prob * 0.4,
            'weak_encryption': vulnerability_prob * 0.3,
            'api_misuse': vulnerability_prob * 0.3
        }

        self.logger.info("Vulnerability detection completed")
        return {
            'total_vulnerability_score': vulnerability_prob,
            'vulnerability_breakdown': vulnerability_types
        }

    def generate_security_report(self, results: Dict[str, Any]) -> str:
        """Generate detailed security report"""
        report = "Mobile App Security Assessment Report\n"
        report += "=" * 40 + "\n\n"
        report += f"Total Vulnerability Score: {results['total_vulnerability_score']:.2%}\n\n"
        report += "Vulnerability Breakdown:\n"
        
        for vuln_type, score in results['vulnerability_breakdown'].items():
            report += f"- {vuln_type.replace('_', ' ').title()}: {score:.2%}\n"
        
        self.logger.info("Security report generated")
        return report


def main():
    # Initialize framework
    framework = MobileAppSecurityFramework()

    # Load dataset
    framework.load_dataset('mobile_app_vulnerabilities.csv')

    # Build and train model
    framework.build_ml_model()
    history = framework.train_model()
    
    # Visualize training progress
    framework.plot_training_history(history)

    # Calculate and display metrics
    advanced_metrics = framework.calculate_advanced_metrics()
    print("\nAdvanced Model Metrics:")
    print(f"ROC AUC: {advanced_metrics['roc_auc']:.3f}")
    print(f"PR AUC: {advanced_metrics['pr_auc']:.3f}")

    # Evaluate model
    model_performance = framework.evaluate_model()
    print("\nModel Performance:")
    print(model_performance['classification_report'])

    # Save the trained model
    framework.save_model()

    # Example vulnerability detection
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

    # Detect vulnerabilities and generate report
    vulnerability_results = framework.detect_vulnerabilities(sample_app_features)
    security_report = framework.generate_security_report(vulnerability_results)
    print("\nSecurity Report:")
    print(security_report)


if __name__ == "__main__":
    main()