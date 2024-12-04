import pandas as pd
import numpy as np
from sklearn.datasets import make_classification


def generate_mobile_app_vulnerability_dataset(n_samples=1000):
    """
    Generate a synthetic mobile app vulnerability dataset

    :param n_samples: Number of sample applications
    :return: DataFrame with mobile app security features
    """
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

    return df


# Generate and save dataset
dataset = generate_mobile_app_vulnerability_dataset()
dataset.to_csv('mobile_app_vulnerabilities.csv', index=False)
print("Dataset generated successfully!")