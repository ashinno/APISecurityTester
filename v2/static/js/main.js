/**
 * Main JavaScript for API Security Tester Interface
 */

// Initialize tooltips across the application
document.addEventListener('DOMContentLoaded', function () {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add active class to current nav item
    const currentPath = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

/**
 * Format a vulnerability score as a percentage with appropriate color class
 * @param {number} score - Vulnerability score (0-1)
 * @returns {Object} - Object containing formatted score and CSS class
 */
function formatVulnerabilityScore(score) {
    const formattedScore = (score * 100).toFixed(1) + '%';
    let riskClass = '';
    let riskLevel = '';

    if (score > 0.7) {
        riskClass = 'risk-high';
        riskLevel = 'High Risk';
    } else if (score > 0.4) {
        riskClass = 'risk-medium';
        riskLevel = 'Medium Risk';
    } else {
        riskClass = 'risk-low';
        riskLevel = 'Low Risk';
    }

    return {
        score: formattedScore,
        class: riskClass,
        level: riskLevel
    };
}

/**
 * Create a gauge chart for vulnerability visualization
 * @param {string} canvasId - ID of the canvas element
 * @param {number} score - Vulnerability score (0-1)
 * @returns {Chart} - Chart.js instance
 */
function createVulnerabilityGauge(canvasId, score) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    // Determine color based on score
    const gaugeColor = score > 0.7 ? '#dc3545' : (score > 0.4 ? '#fd7e14' : '#28a745');

    // Create chart
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 1 - score],
                backgroundColor: [
                    gaugeColor,
                    '#e9ecef'
                ],
                borderWidth: 0
            }]
        },
        options: {
            cutout: '70%',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: false
                }
            }
        }
    });
}

/**
 * Show a loading spinner
 * @param {string} containerId - ID of the container element
 * @param {string} message - Loading message to display
 */
function showLoading(containerId, message = 'Loading...') {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="text-center p-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">${message}</p>
            </div>
        `;
    }
}

/**
 * Show an error message
 * @param {string} containerId - ID of the container element
 * @param {string} message - Error message to display
 */
function showError(containerId, message) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = `
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${message}
            </div>
        `;
    }
}

/**
 * Format a date string
 * @param {string} dateString - Date string to format
 * @returns {string} - Formatted date string
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Create a bar chart for risk factors visualization
 * @param {string} canvasId - ID of the canvas element
 * @param {Object} riskFactors - Risk factors data
 * @returns {Chart} - Chart.js instance
 */
function createRiskFactorsChart(canvasId, riskFactors) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    const labels = [];
    const weights = [];
    const impacts = [];

    for (const [factor, details] of Object.entries(riskFactors)) {
        labels.push(factor.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()));
        weights.push(details.weight);
        impacts.push(details.impact);
    }

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Weight',
                    data: weights,
                    backgroundColor: 'rgba(54, 162, 235, 0.7)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                },
                {
                    label: 'Impact',
                    data: impacts,
                    backgroundColor: 'rgba(255, 99, 132, 0.7)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 1
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Risk Factors Analysis'
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            return context.dataset.label + ': ' + (context.raw * 100).toFixed(1) + '%';
                        }
                    }
                }
            }
        }
    });
}