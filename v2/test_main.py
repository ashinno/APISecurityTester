import pytest
import os
import numpy as np
import tensorflow as tf
from main import MobileAppSecurityFramework

@pytest.fixture
def framework():
    return MobileAppSecurityFramework()

@pytest.fixture
def sample_features():
    return {
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

def test_framework_initialization(framework):
    assert framework.vulnerability_model is None
    assert framework.dataset is None
    assert framework.config is not None
    assert 'model_params' in framework.config
    assert 'training_params' in framework.config

def test_validate_features_valid(framework, sample_features):
    assert framework.validate_features(sample_features) is True

def test_validate_features_invalid_missing():
    framework = MobileAppSecurityFramework()
    invalid_features = {'storage_encryption_level': 0.3}
    with pytest.raises(ValueError):
        framework.validate_features(invalid_features)

def test_validate_features_invalid_type(framework):
    invalid_features = {
        'storage_encryption_level': 'invalid',
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
    with pytest.raises(TypeError):
        framework.validate_features(invalid_features)

def test_validate_features_invalid_range(framework):
    invalid_features = {
        'storage_encryption_level': 1.5,  # Invalid: > 1
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
    with pytest.raises(ValueError):
        framework.validate_features(invalid_features)

def test_dataset_generation(framework):
    df = framework.generate_dataset(n_samples=100)
    assert len(df) == 100
    assert all(col in df.columns for col in [
        'storage_encryption_level',
        'api_security_score',
        'vulnerability_label'
    ])

def test_model_workflow(framework, tmp_path):
    # Generate and load dataset
    dataset_path = os.path.join(tmp_path, "test_dataset.csv")
    df = framework.generate_dataset(n_samples=100)
    df.to_csv(dataset_path, index=False)
    framework.load_dataset(dataset_path)
    
    # Build and train model
    framework.build_ml_model()
    history = framework.train_model()
    
    assert isinstance(history.history, dict)
    assert 'loss' in history.history
    assert 'accuracy' in history.history

def test_model_save_load(framework, tmp_path):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Test save
    model_path = os.path.join(tmp_path, "test_model.h5")
    framework.save_model(model_path)
    assert os.path.exists(model_path)
    
    # Test load
    new_framework = MobileAppSecurityFramework()
    new_framework.load_saved_model(model_path)
    assert isinstance(new_framework.vulnerability_model, tf.keras.Model)

def test_vulnerability_detection(framework, sample_features):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Test detection
    results = framework.detect_vulnerabilities(sample_features)
    assert 'total_vulnerability_score' in results
    assert 'vulnerability_breakdown' in results
    assert isinstance(results['total_vulnerability_score'], float)
    assert 0 <= results['total_vulnerability_score'] <= 1

def test_security_report_generation(framework, sample_features):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Generate report
    results = framework.detect_vulnerabilities(sample_features)
    report = framework.generate_security_report(results)
    
    assert isinstance(report, str)
    assert "Mobile App Security Assessment Report" in report
    assert "Vulnerability Breakdown:" in report

def test_advanced_metrics(framework):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Calculate metrics
    metrics = framework.calculate_advanced_metrics()
    
    assert 'roc_auc' in metrics
    assert 'pr_auc' in metrics
    assert isinstance(metrics['roc_auc'], float)
    assert isinstance(metrics['pr_auc'], float)
    assert 0 <= metrics['roc_auc'] <= 1
    assert 0 <= metrics['pr_auc'] <= 1

def test_model_performance_metrics(framework):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Test model metrics
    metrics = framework.calculate_advanced_metrics()
    model_performance = framework.evaluate_model()
    
    # Verify ROC and PR curves
    assert len(metrics['fpr']) > 0
    assert len(metrics['tpr']) > 0
    assert len(metrics['precision']) > 0
    assert len(metrics['recall']) > 0
    
    # Verify confusion matrix
    assert model_performance['confusion_matrix'].shape == (2, 2)
    
def test_extreme_vulnerability_cases(framework):
    high_risk_features = {
        'storage_encryption_level': 0.1,
        'api_security_score': 0.1,
        'data_transmission_security': 0.1,
        'authentication_strength': 0.1, 
        'input_validation_score': 0.1,
        'network_communication_security': 0.1,
        'third_party_library_risk': 0.9,
        'runtime_permissions_management': 0.1,
        'code_obfuscation_level': 0.1,
        'certificate_pinning_implementation': 0.1
    }
    
    low_risk_features = {
        'storage_encryption_level': 0.9,
        'api_security_score': 0.9,
        'data_transmission_security': 0.9,
        'authentication_strength': 0.9,
        'input_validation_score': 0.9,
        'network_communication_security': 0.9,
        'third_party_library_risk': 0.1,
        'runtime_permissions_management': 0.9,
        'code_obfuscation_level': 0.9,
        'certificate_pinning_implementation': 0.9
    }
    
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Test high risk case
    high_risk_results = framework.detect_vulnerabilities(high_risk_features)
    assert high_risk_results['total_vulnerability_score'] > 0.5
    
    # Test low risk case
    low_risk_results = framework.detect_vulnerabilities(low_risk_features)
    assert low_risk_results['total_vulnerability_score'] < 0.5

def test_advanced_metrics(framework):
    # Setup
    framework.generate_dataset(n_samples=100)
    framework.load_dataset('mobile_app_vulnerabilities.csv')
    framework.build_ml_model()
    framework.train_model()
    
    # Calculate metrics
    metrics = framework.calculate_advanced_metrics()
    
    assert 'roc_auc' in metrics
    assert 'pr_auc' in metrics
    assert isinstance(metrics['roc_auc'], float)
    assert isinstance(metrics['pr_auc'], float)
    assert 0 <= metrics['roc_auc'] <= 1
    assert 0 <= metrics['pr_auc'] <= 1