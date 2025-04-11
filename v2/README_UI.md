# API Security Tester Web Interface

A modern, intuitive web interface for the API Security Tester framework that provides comprehensive security vulnerability detection and analysis for mobile applications.

## Features

- **Vulnerability Detection**: Analyze security features and detect potential vulnerabilities in mobile applications
- **Security Report Generation**: Generate detailed security assessment reports in PDF format
- **Model Training and Evaluation**: Configure, train, and evaluate machine learning models for vulnerability detection
- **Advanced Metrics Visualization**: Visualize model performance metrics including ROC curves, PR curves, and confusion matrices

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/ashinno/APISecurityTester.git
   cd APISecurityTester/v2
   ```

2. Create and activate a virtual environment (recommended):
   ```
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On macOS/Linux
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the web server:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Use the navigation menu to access different features:
   - **Dashboard**: Overview of the framework's capabilities
   - **Vulnerability Detection**: Analyze security features and detect vulnerabilities
   - **Model Training**: Configure and train machine learning models
   - **Visualization**: View advanced metrics and visualizations
   - **Reports**: Generate and download security assessment reports

## Security Features Analysis

The interface allows you to analyze the following security aspects (on a scale of 0-1):

1. **Storage Encryption Level**: Measures how well the app encrypts stored data
2. **API Security Score**: Evaluates the overall security of API implementations
3. **Data Transmission Security**: Assesses the security of data in transit
4. **Authentication Strength**: Measures the strength of authentication mechanisms
5. **Input Validation Score**: Evaluates how well the app validates and sanitizes inputs
6. **Network Communication Security**: Assesses the security of network communications
7. **Third Party Library Risk**: Evaluates the risk associated with third-party libraries
8. **Runtime Permissions Management**: Measures how well the app manages runtime permissions
9. **Code Obfuscation Level**: Assesses the level of code obfuscation
10. **Certificate Pinning Implementation**: Evaluates the implementation of certificate pinning

## Visualization Capabilities

The interface provides the following visualization capabilities:

- **ROC and PR Curves**: Illustrate the model's performance across different threshold settings
- **Confusion Matrix**: Shows the model's classification performance
- **Feature Importance Analysis**: Displays the relative contribution of each security feature
- **Model Architecture Summary**: Shows the layers and parameters of the neural network
- **Training History**: Visualizes the model's loss and accuracy metrics during training

## Report Generation

The interface allows you to generate comprehensive security assessment reports that include:

- Overall vulnerability score
- Detailed breakdown of vulnerability categories
- Risk factor analysis
- Recommendations for security improvements

## Troubleshooting

- **Issue**: Web server fails to start
  - **Solution**: Ensure that port 5000 is not in use by another application

- **Issue**: Visualizations not displaying
  - **Solution**: Ensure that a model has been trained or loaded before attempting to view visualizations

- **Issue**: PDF report generation fails
  - **Solution**: Ensure that the 'reports' directory exists and is writable

## License

This project is licensed under the MIT License - see the LICENSE file for details.