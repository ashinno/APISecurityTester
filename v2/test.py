import os
import numpy as np
import tensorflow as tf
from MobileAppSecurityFramework import MobileAppSecurityFramework

def test_saved_model():
    # Initialize the framework
    framework = MobileAppSecurityFramework()
    
    # Load the dataset to get the preprocessor
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    
    # Load the saved model
    framework.load_saved_model('models/vulnerability_model.h5')
    
    # Test cases with different security levels
    test_cases = [
        {
            'name': 'High Risk App',
            'features': {
                'storage_encryption_level': 0.1,
                'api_security_score': 0.2,
                'data_transmission_security': 0.1,
                'authentication_strength': 0.2,
                'input_validation_score': 0.1,
                'network_communication_security': 0.2,
                'third_party_library_risk': 0.8,
                'runtime_permissions_management': 0.1,
                'code_obfuscation_level': 0.1,
                'certificate_pinning_implementation': 0.1
            }
        },
        {
            'name': 'Medium Risk App',
            'features': {
                'storage_encryption_level': 0.5,
                'api_security_score': 0.5,
                'data_transmission_security': 0.5,
                'authentication_strength': 0.5,
                'input_validation_score': 0.5,
                'network_communication_security': 0.5,
                'third_party_library_risk': 0.5,
                'runtime_permissions_management': 0.5,
                'code_obfuscation_level': 0.5,
                'certificate_pinning_implementation': 0.5
            }
        },
        {
            'name': 'Low Risk App',
            'features': {
                'storage_encryption_level': 0.9,
                'api_security_score': 0.8,
                'data_transmission_security': 0.9,
                'authentication_strength': 0.9,
                'input_validation_score': 0.8,
                'network_communication_security': 0.9,
                'third_party_library_risk': 0.2,
                'runtime_permissions_management': 0.8,
                'code_obfuscation_level': 0.9,
                'certificate_pinning_implementation': 0.9
            }
        }
    ]
    
    # Test each case
    print("Model Testing Results")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\nTesting {test_case['name']}:")
        print("-" * 30)
        
        # Detect vulnerabilities
        results = framework.detect_vulnerabilities(test_case['features'])
        
        # Generate and print report
        report = framework.generate_security_report(results)
        print(report)

if __name__ == "__main__":
    test_saved_model()