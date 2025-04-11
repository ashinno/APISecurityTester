import os
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import base64
import io
from flask import Flask, render_template, request, jsonify, send_file, Response
from main import MobileAppSecurityFramework
from security_reporter import SecurityReporter

app = Flask(__name__)

# Initialize the framework
framework = MobileAppSecurityFramework()

# Initialize the security reporter
reporter = SecurityReporter()

# Ensure the reports directory exists
os.makedirs('reports', exist_ok=True)

# Ensure the static/images directory exists
os.makedirs('static/images', exist_ok=True)

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/vulnerability-detection')
def vulnerability_detection():
    """Render the vulnerability detection page"""
    return render_template('vulnerability_detection.html')

@app.route('/model-training')
def model_training():
    """Render the model training page"""
    return render_template('model_training.html')

@app.route('/visualization')
def visualization():
    """Render the visualization page"""
    return render_template('visualization.html')

@app.route('/reports')
def reports():
    """Render the reports page"""
    return render_template('reports.html')

@app.route('/api/detect-vulnerabilities', methods=['POST'])
def api_detect_vulnerabilities():
    """API endpoint for vulnerability detection"""
    try:
        # Get security features from request
        app_features = request.json
        
        # Load dataset if not already loaded
        if framework.dataset is None:
            try:
                framework.load_dataset('mobile_app_vulnerabilities.csv')
            except FileNotFoundError:
                framework.generate_dataset()
                framework.load_dataset('mobile_app_vulnerabilities.csv')
        
        # Load or build model if not already loaded
        if framework.vulnerability_model is None:
            try:
                framework.load_saved_model()
            except FileNotFoundError:
                framework.build_ml_model()
                framework.train_model()
                framework.save_model()
        
        # Detect vulnerabilities
        results = framework.detect_vulnerabilities(app_features)
        
        # Generate security report
        report_text = framework.generate_security_report(results)
        
        # Update monitoring data
        reporter.update_monitoring_data(results)
        
        return jsonify({
            'success': True,
            'results': results,
            'report': report_text
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/generate-pdf-report', methods=['POST'])
def api_generate_pdf_report():
    """API endpoint for generating PDF reports"""
    try:
        # Get results and app name from request
        data = request.json
        results = data.get('results')
        app_name = data.get('app_name', 'Mobile App')
        
        # Generate PDF report
        pdf_path = reporter.generate_pdf_report(results, app_name)
        
        return jsonify({
            'success': True,
            'pdf_path': pdf_path
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/download-report/<path:filename>')
def download_report(filename):
    """Download a generated report"""
    try:
        return send_file(os.path.join('reports', os.path.basename(filename)),
                         as_attachment=True)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 404

@app.route('/api/train-model', methods=['POST'])
def api_train_model():
    """API endpoint for model training"""
    try:
        # Get training parameters from request
        params = request.json
        
        # Update configuration if provided
        if params:
            for section in params:
                if section in framework.config:
                    framework.config[section].update(params[section])
        
        # Load dataset if not already loaded
        if framework.dataset is None:
            try:
                framework.load_dataset('mobile_app_vulnerabilities.csv')
            except FileNotFoundError:
                framework.generate_dataset()
                framework.load_dataset('mobile_app_vulnerabilities.csv')
        
        # Build and train model
        framework.build_ml_model()
        history = framework.train_model()
        
        # Save the model
        framework.save_model()
        
        # Plot training history
        framework.plot_training_history(history)
        
        # Calculate advanced metrics
        metrics = framework.calculate_advanced_metrics()
        
        # Plot advanced metrics
        framework.plot_advanced_metrics()
        
        # Plot feature importance
        framework.plot_feature_importance()
        
        return jsonify({
            'success': True,
            'message': 'Model trained successfully',
            'metrics': {
                'roc_auc': float(metrics['roc_auc']),
                'pr_auc': float(metrics['pr_auc'])
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/get-visualization/<viz_type>')
def api_get_visualization(viz_type):
    """API endpoint for getting visualizations"""
    try:
        if viz_type == 'training_history':
            return send_file('training_history.png', mimetype='image/png')
        elif viz_type == 'model_metrics':
            return send_file('model_metrics.png', mimetype='image/png')
        elif viz_type == 'feature_importance':
            return send_file('feature_importance.png', mimetype='image/png')
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid visualization type'
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 404

@app.route('/api/get-model-summary')
def api_get_model_summary():
    """API endpoint for getting model summary"""
    try:
        if framework.vulnerability_model is None:
            try:
                framework.load_saved_model()
            except FileNotFoundError:
                return jsonify({
                    'success': False,
                    'error': 'No model available. Please train a model first.'
                }), 404
        
        # Get model summary
        summary_io = io.StringIO()
        framework.vulnerability_model.summary(print_fn=lambda x: summary_io.write(x + '\n'))
        summary = summary_io.getvalue()
        
        return jsonify({
            'success': True,
            'summary': summary
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/get-config')
def api_get_config():
    """API endpoint for getting current configuration"""
    try:
        return jsonify({
            'success': True,
            'config': framework.config
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)