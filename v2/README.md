# API Security Tester

A machine learning-based framework for testing and assessing mobile application security vulnerabilities.

## Features

- Vulnerability detection using machine learning
- Security risk assessment
- Detailed security reports generation
- Advanced metrics calculation (ROC-AUC, PR-AUC)
- Support for multiple security features analysis

## Installation

```bash
pip install api-security-tester
```

## Quick Start

```python
from api_security_tester import MobileAppSecurityFramework

# Initialize the framework
framework = MobileAppSecurityFramework()

# Example security features to analyze
app_features = {
    'storage_encryption_level': 0.8,
    'api_security_score': 0.7,
    'data_transmission_security': 0.9,
    'authentication_strength': 0.8,
    'input_validation_score': 0.7,
    'network_communication_security': 0.8,
    'third_party_library_risk': 0.2,
    'runtime_permissions_management': 0.7,
    'code_obfuscation_level': 0.6,
    'certificate_pinning_implementation': 0.8
}

# Detect vulnerabilities
results = framework.detect_vulnerabilities(app_features)

# Generate security report
report = framework.generate_security_report(results)
print(report)
```

## Security Features

The framework analyzes the following security aspects:

1. Storage Encryption Level
2. API Security
3. Data Transmission Security
4. Authentication Strength
5. Input Validation
6. Network Communication Security
7. Third-party Library Risk
8. Runtime Permissions Management
9. Code Obfuscation
10. Certificate Pinning

## Advanced Usage

### Training Custom Models

```python
# Generate and train with custom dataset
framework.generate_dataset(n_samples=1000)
framework.load_dataset('mobile_app_vulnerabilities.csv')
framework.build_ml_model()
framework.train_model()

# Save trained model
framework.save_model('custom_model.h5')
```

### Calculating Advanced Metrics

```python
# Get model performance metrics
metrics = framework.calculate_advanced_metrics()
print(f"ROC-AUC Score: {metrics['roc_auc']}")
print(f"PR-AUC Score: {metrics['pr_auc']}")
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact contact@ashinno.com
