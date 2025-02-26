import pandas as pd
import numpy as np
from sklearn.datasets import make_classification


def generate_mobile_app_vulnerability_dataset(n_samples=5000):
    """
    Generate a synthetic mobile app vulnerability dataset with realistic patterns
    
    :param n_samples: Number of sample applications
    :return: DataFrame with mobile app security features
    """
    # Generate base feature matrix with more samples
    X, y = make_classification(
        n_samples=n_samples,
        n_features=10,
        n_informative=8,  # Increased informative features
        n_redundant=2,    # Reduced redundant features
        class_sep=1.0,    # Increased class separation
        n_clusters_per_class=3,  # More clusters for better pattern representation
        weights=[0.7, 0.3],  # Imbalanced dataset (70% secure, 30% vulnerable)
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
    
    # Apply realistic constraints and patterns
    df['storage_encryption_level'] = np.clip(df['storage_encryption_level'], 0, 1)
    df['api_security_score'] = np.clip(np.abs(df['api_security_score']), 0, 1)
    
    # Add correlations between features that typically occur together
    df.loc[df['authentication_strength'] < 0.3, 'data_transmission_security'] *= 0.7
    df.loc[df['api_security_score'] < 0.4, 'input_validation_score'] *= 0.8
    
    # Add some known vulnerability patterns
    high_risk_mask = (
        (df['storage_encryption_level'] < 0.4) &
        (df['authentication_strength'] < 0.3) &
        (df['api_security_score'] < 0.5)
    )
    df.loc[high_risk_mask, 'vulnerability_label'] = 1
    
    # Ensure all features are within [0,1] range
    for column in feature_names:
        df[column] = np.clip(df[column], 0, 1)
    
    return df


# Generate and save dataset with more samples
dataset = generate_mobile_app_vulnerability_dataset()
dataset.to_csv('mobile_app_vulnerabilities.csv', index=False)
print("Enhanced dataset generated successfully!")