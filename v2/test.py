from MobileAppSecurityFramework import MobileAppSecurityFramework

def test_framework():
    # Initialize framework
    framework = MobileAppSecurityFramework()

    # Test with different app configurations
    test_apps = [
        {
            'storage_encryption_level': 0.9,
            'api_security_score': 0.8,
            'data_transmission_security': 0.9,
            'authentication_strength': 0.85,
            'input_validation_score': 0.9,
            'network_communication_security': 0.8,
            'third_party_library_risk': 0.2,
            'runtime_permissions_management': 0.85,
            'code_obfuscation_level': 0.7,
            'certificate_pinning_implementation': 0.9
        },
        {
            'storage_encryption_level': 0.2,
            'api_security_score': 0.3,
            'data_transmission_security': 0.1,
            'authentication_strength': 0.2,
            'input_validation_score': 0.3,
            'network_communication_security': 0.2,
            'third_party_library_risk': 0.8,
            'runtime_permissions_management': 0.3,
            'code_obfuscation_level': 0.1,
            'certificate_pinning_implementation': 0.2
        }
    ]

    # Load and prepare the model
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model(epochs=20)  # Reduced epochs for testing

    # Evaluate model performance
    performance = framework.evaluate_model()
    print("\nModel Performance:")
    print(performance['classification_report'])
    print("\nConfusion Matrix:")
    print(performance['confusion_matrix'])

    # Test vulnerability detection
    print("\nTesting different app configurations:")
    for i, app in enumerate(test_apps, 1):
        print(f"\nTest App {i}:")
        results = framework.detect_vulnerabilities(app)
        report = framework.generate_security_report(results)
        print(report)

if __name__ == "__main__":
    test_framework()