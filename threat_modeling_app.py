import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import uuid
import json

# Page configuration
st.set_page_config(
    page_title="Threat Model",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS (updated to enhance visual cues for directional flows and boundaries)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    body {
        font-family: 'Inter', sans-serif;
    }

    .main-header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    .boundary-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .threat-item {
        background: rgba(255, 255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid #ff6b6b;
    }
    
    .mitigation-item {
        background: rgba(255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid #51cf66;
    }
    
    .risk-critical { background-color: #dc3545; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-high { background-color: #fd7e14; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-medium { background-color: #ffc107; color: black; padding: 0.3rem; border-radius: 5px; }
    .risk-low { background-color: #28a745; color: white; padding: 0.3rem; border-radius: 5px; }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    
    .stride-category {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    
    .mitigation-card {
        background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .threat-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 25px;
        margin: 30px 0;
    }
    .threat-card {
        background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
        border-radius: 15px;
        padding: 25px;
        box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        border-left: 5px solid;
        transition: transform 0.3s ease;
    }
    .threat-card:hover {
        transform: translateY(-5px);
    }
    .threat-card.critical { border-left-color: #e74c3c; }
    .threat-card.high { border-left-color: #f39c12; }
    .threat-card.medium { border-left-color: #f1c40f; }
    .threat-card.low { border-left-color: #27ae60; }
    .threat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
    }
    .threat-title {
        font-size: 1.3em;
        font-weight: 700;
        color: #2c3e50;
    }
    .risk-score-display {
        padding: 8px 12px;
        border-radius: 25px;
        font-weight: 700;
        font-size: 0.9em;
        color: white;
    }
    .risk-score-display.critical { background: #e74c3c; }
    .risk-score-display.high { background: #f39c12; }
    .risk-score-display.medium { background: #f1c40f; color: black; }
    .risk-score-display.low { background: #27ae60; }
    .threat-content {
        line-height: 1.6;
    }
    .threat-section-card {
        margin-bottom: 15px;
    }
    .threat-section-card h4 {
        color: #34495e;
        margin-bottom: 8px;
        font-size: 1.1em;
    }
    .threat-section-card p {
        margin: 0;
        color: #666;
    }
    .mitigation-list {
        background: #e8f5e8;
        padding: 15px;
        border-radius: 8px;
        margin-top: 10px;
    }
    .mitigation-list ul {
        margin: 0;
        padding-left: 20px;
    }
    .mitigation-list li {
        margin: 5px 0;
        color: #2d5a2d;
    }

    #diagram-container {
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f9f9f9;
        overflow: hidden;
        position: relative;
        height: 600px;
        width: 100%;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    }
    #diagram-svg {
        width: 100%;
        height: 100%;
    }
    .diagram-node-rect {
        cursor: grab;
        stroke: #333;
        stroke-width: 2px;
        transition: all 0.2s ease-in-out;
        filter: drop-shadow(2px 2px 4px rgba(0,0,0,0.1));
    }
    .diagram-node-rect:hover {
        transform: translateY(-3px);
        stroke: #2a5298;
        filter: drop-shadow(3px 3px 6px rgba(0,0,0,0.2));
    }
    .diagram-node-rect.selected {
        stroke: #667eea;
        stroke-width: 4px;
        filter: drop-shadow(4px 4px 8px rgba(0,0,0,0.3));
    }
    .diagram-node-text {
        font-family: 'Inter', sans-serif;
        font-size: 12px;
        fill: #333;
        pointer-events: none;
        text-anchor: middle;
        dominant-baseline: central;
        font-weight: 600;
    }
    .diagram-edge {
        stroke: #764ba2;
        stroke-width: 2px;
        fill: none;
        marker-end: url(#arrowhead);
        stroke-opacity: 0.8;
    }
    .diagram-edge.boundary-cross {
        stroke: #ff6b6b;
        stroke-dasharray: 5,5;
    }
    .diagram-edge-label {
        font-family: 'Inter', sans-serif;
        font-size: 10px;
        fill: #555;
        background-color: rgba(255,255,255,0.9);
        padding: 3px 8px;
        border-radius: 5px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        font-weight: 500;
    }
    .diagram-controls {
        position: absolute;
        top: 15px;
        left: 15px;
        z-index: 10;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }
    .diagram-controls button {
        background-color: #007bff;
        color: white;
        border: none;
        padding: 10px 18px;
        border-radius: 8px;
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        transition: background-color 0.2s ease, transform 0.1s ease;
        box-shadow: 0 3px 8px rgba(0,123,255,0.3);
    }
    .diagram-controls button:hover {
        background-color: #0056b3;
        transform: translateY(-1px);
    }
    .diagram-controls button:disabled {
        background-color: #cccccc;
        cursor: not-allowed;
        box-shadow: none;
    }
    .modal {
        display: none;
        position: fixed;
        z-index: 100;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        overflow: auto;
        background-color: rgba(0,0,0,0.6);
        justify-content: center;
        align-items: center;
    }
    .modal-content {
        background-color: #fefefe;
        margin: auto;
        padding: 30px;
        border-radius: 15px;
        width: 90%;
        max-width: 600px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        display: flex;
        flex-direction: column;
        gap: 20px;
    }
    .modal-content h2 {
        color: #2a5298;
        margin-top: 0;
        font-size: 1.8em;
    }
    .modal-content label {
        font-weight: 600;
        color: #333;
        margin-bottom: 5px;
    }
    .modal-content input, .modal-content select, .modal-content textarea {
        width: calc(100% - 20px);
        padding: 12px;
        margin-top: 5px;
        border: 1px solid #c0c0c0;
        border-radius: 8px;
        font-size: 1em;
    }
    .modal-content textarea {
        min-height: 80px;
        resize: vertical;
    }
    .modal-content button {
        background-color: #28a745;
        color: white;
        padding: 12px 25px;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 1.05em;
        font-weight: 600;
        transition: background-color 0.2s ease;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .modal-content button.cancel {
        background-color: #dc3545;
    }
    .modal-content button.cancel:hover {
        background-color: #c82333;
    }
    .modal-content button:hover {
        background-color: #218838;
    }
    .trust-boundary-rect {
        fill: #e0f7fa;
        fill-opacity: 0.4;
        stroke: #007bff;
        stroke-width: 2px;
        stroke-dasharray: 8 4;
        rx: 10;
        ry: 10;
        cursor: move;
    }
    .trust-boundary-rect.selected {
        stroke: #ff6b6b;
        stroke-width: 3px;
    }
    .trust-boundary-label {
        font-family: 'Inter', sans-serif;
        font-size: 14px;
        fill: #0056b3;
        font-weight: 700;
        pointer-events: none;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to calculate risk level
def calculate_risk(likelihood, impact):
    risk_score = likelihood * impact
    if risk_score >= 15:
        risk_level = 'Critical'
    elif risk_score >= 10:
        risk_level = 'High'
    elif risk_score >= 5:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    return risk_score, risk_level

# Common trust boundaries
COMMON_TRUST_BOUNDARIES = [
    "Internet -> DMZ",
    "DMZ -> Internal App Tier",
    "Internal App Tier -> Database",
    "Customer-Web App Boundary",
    "Web App-Payment Gateway Boundary",
    "Web App-Database Boundary",
    "Web App-Shipping Service Boundary",
    "User -> Application",
    "Application -> API Gateway",
    "API Gateway -> Microservice",
    "Microservice -> Database",
    "On-Premise -> Cloud",
    "External Partner Network"
]

# Default mitigations
DEFAULT_MITIGATIONS = {
    'Phishing Attacks': [
        {'type': 'Preventive', 'control': 'Implement Multi-Factor Authentication (MFA)'},
        {'type': 'Preventive', 'control': 'Deploy strong email filtering and anti-phishing solutions'},
        {'type': 'Detective', 'control': 'Conduct regular security awareness training for users'}
    ],
    'DDoS Attacks': [
        {'type': 'Preventive', 'control': 'Utilize a DDoS protection service (e.g., Cloudflare, Akamai)'},
        {'type': 'Responsive', 'control': 'Implement traffic throttling and rate limiting'},
        {'type': 'Detective', 'control': 'Monitor network traffic for unusual spikes'}
    ],
    'SQL Injection': [
        {'type': 'Preventive', 'control': 'Use parameterized queries or prepared statements'},
        {'type': 'Preventive', 'control': 'Implement strict input validation and sanitization'},
        {'type': 'Preventive', 'control': 'Apply Principle of Least Privilege to database accounts'}
    ],
    'Cross-Site Scripting (XSS)': [
        {'type': 'Preventive', 'control': 'Sanitize all user-supplied input before rendering to HTML'},
        {'type': 'Preventive', 'control': 'Implement Content Security Policy (CSP)'},
        {'type': 'Preventive', 'control': 'Use output encoding for dynamic content'}
    ],
    'Database Injection': [
        {'type': 'Preventive', 'control': 'Use ORMs or parameterized queries'},
        {'type': 'Preventive', 'control': 'Input validation and sanitization'},
        {'type': 'Preventive', 'control': 'Least privilege access to database'}
    ],
    'Data Exfiltration': [
        {'type': 'Preventive', 'control': 'Encrypt data at rest and in transit'},
        {'type': 'Detective', 'control': 'Implement Data Loss Prevention (DLP) solutions'},
        {'type': 'Detective', 'control': 'Monitor database activity for suspicious queries'}
    ],
    'Unauthorized Data Access': [
        {'type': 'Preventive', 'control': 'Implement strong access control policies (RBAC/ABAC)'},
        {'type': 'Preventive', 'control': 'Regularly review and revoke unnecessary access rights'},
        {'type': 'Detective', 'control': 'Audit logging of all data access attempts'}
    ],
    'Lateral Movement': [
        {'type': 'Preventive', 'control': 'Implement network segmentation and micro-segmentation'},
        {'type': 'Preventive', 'control': 'Restrict administrative access and use jump servers'},
        {'type': 'Detective', 'control': 'Monitor internal network traffic for anomalies'}
    ],
    'Internal Service Spoofing': [
        {'type': 'Preventive', 'control': 'Implement mutual TLS (mTLS) for service-to-service communication'},
        {'type': 'Preventive', 'control': 'Use strong authentication mechanisms between internal services'},
        {'type': 'Detective', 'control': 'Log and monitor service authentication failures'}
    ],
    'API Key Exposure': [
        {'type': 'Preventive', 'control': 'Store API keys securely (e.g., in a secrets manager)'},
        {'type': 'Preventive', 'control': 'Rotate API keys regularly'},
        {'type': 'Preventive', 'control': 'Implement API gateway policies for key validation and rate limiting'}
    ],
    'Data Sharing Violation': [
        {'type': 'Preventive', 'control': 'Define clear data sharing agreements and policies'},
        {'type': 'Preventive', 'control': 'Implement data masking or anonymization for sensitive data'},
        {'type': 'Detective', 'control': 'Audit and log all data transfers to external parties'}
    ],
    'Authentication Bypass': [
        {'type': 'Preventive', 'control': 'Enforce strong password policies and MFA'},
        {'type': 'Preventive', 'control': 'Implement robust session management'},
        {'type': 'Detective', 'control': 'Monitor authentication logs for brute-force or unusual login attempts'}
    ],
    'Credential Stuffing': [
        {'type': 'Preventive', 'control': 'Implement rate limiting on login attempts'},
        {'type': 'Preventive', 'control': 'Use CAPTCHA or reCAPTCHA'},
        {'type': 'Detective', 'control': 'Monitor for large numbers of failed login attempts from single IPs'}
    ],
    'Financial Fraud': [
        {'type': 'Preventive', 'control': 'Implement multi-factor authentication for high-value transactions'},
        {'type': 'Detective', 'control': 'Deploy real-time fraud detection systems'},
        {'type': 'Responsive', 'control': 'Establish clear incident response procedures for fraud alerts'}
    ],
    'Transaction Manipulation': [
        {'type': 'Preventive', 'control': 'Implement strong data integrity checks for all transactions'},
        {'type': 'Preventive', 'control': 'Use cryptographic signatures for transaction data'},
        {'type': 'Detective', 'control': 'Reconcile transactions regularly and detect discrepancies'}
    ],
    'Order Repudiation': [
        {'type': 'Preventive', 'control': 'Implement comprehensive audit logging for all order actions'},
        {'type': 'Preventive', 'control': 'Send email/SMS confirmations for critical order states'},
        {'type': 'Preventive', 'control': 'Require digital signatures for high-value orders'}
    ],
    'Payment Gateway Bypass': [
        {'type': 'Preventive', 'control': 'Server-side validation of all payment statuses and callbacks'},
        {'type': 'Preventive', 'control': 'Cryptographic signing and verification of payment gateway communications'},
        {'type': 'Detective', 'control': 'Monitor payment gateway logs for unauthorized access or unusual activity'}
    ]
}

# Initial data structure for the threat model
def get_initial_threat_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        return {}
    
    banking_threat_data = {
        'Internet -> DMZ': {
            'description': 'External users accessing web-facing components of the banking application',
            'components': ['Internet Users', 'Web Application Firewall', 'Load Balancer'],
            'threats': [
                {'id': 'T_Bank_1', 'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': 'M_Bank_1_1', 'type': 'Preventive', 'control': 'Extended Validation SSL certificates'},
                     {'id': 'M_Bank_1_2', 'type': 'Detective', 'control': 'Certificate transparency logs'}
                 ]},
                {'id': 'T_Bank_2', 'name': 'DDoS Attacks', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_2_1', 'type': 'Preventive', 'control': 'DDoS Protection Service'},
                     {'id': 'M_Bank_2_2', 'type': 'Responsive', 'control': 'Traffic throttling'}
                 ]},
            ],
            'boundary_coords': {'x': 50, 'y': 20, 'width': 700, 'height': 250}
        },
        'DMZ -> Internal App Tier': {
            'description': 'Web tier to Application tier - Authenticated requests only for banking',
            'components': ['Web Servers (DMZ)', 'Application Servers', 'Authentication Services'],
            'threats': [
                {'id': 'T_Bank_3', 'name': 'SQL Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_3_1', 'type': 'Preventive', 'control': 'Parameterized queries'},
                     {'id': 'M_Bank_3_2', 'type': 'Preventive', 'control': 'Input validation'}
                 ]},
                {'id': 'T_Bank_4', 'name': 'Lateral Movement', 'category': 'Elevation of Privilege', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_4_1', 'type': 'Preventive', 'control': 'Network segmentation'},
                     {'id': 'M_Bank_4_2', 'type': 'Detective', 'control': 'Network traffic analysis'}
                 ]},
            ],
            'boundary_coords': {'x': 450, 'y': 20, 'width': 700, 'height': 300}
        },
        'Internal App Tier -> Database': {
            'description': 'Application servers accessing database for banking',
            'components': ['Application Servers', 'Database Server'],
            'threats': [
                {'id': 'T_Bank_5', 'name': 'Data Exfiltration', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Bank_5_1', 'type': 'Preventive', 'control': 'Data encryption at rest and in transit'},
                     {'id': 'M_Bank_5_2', 'type': 'Detective', 'control': 'Database activity monitoring'}
                 ]},
            ],
            'boundary_coords': {'x': 750, 'y': 50, 'width': 300, 'height': 200}
        },
    }
    order_processing_threat_data = {
        'Customer-Web App Boundary': {
            'description': 'Customer interaction with the online order processing web application.',
            'components': ['Customer', 'Web Application'],
            'threats': [
                {'id': 'T_Order_1', 'name': 'Phishing Attack (Order System)', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': 'M_Order_1_1', 'type': 'Preventive', 'control': 'Multi-factor authentication (MFA) for login.'},
                     {'id': 'M_Order_1_2', 'type': 'Preventive', 'control': 'Strong email filtering and anti-phishing solutions.'}
                 ]},
                {'id': 'T_Order_2', 'name': 'DoS on Web Application (Order System)', 'category': 'Denial of Service', 'likelihood': 4, 'impact': 2, 'risk_score': 8, 'risk_level': 'Medium',
                 'mitigations': [
                     {'id': 'M_Order_2_1', 'type': 'Preventive', 'control': 'Implement rate limiting and anti-bot measures.'},
                     {'id': 'M_Order_2_2', 'type': 'Preventive', 'control': 'Use a CDN/DDoS protection service.'}
                 ]},
                {'id': 'T_Order_3', 'name': 'Order Repudiation', 'category': 'Repudiation', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Low',
                 'mitigations': [
                     {'id': 'M_Order_3_1', 'type': 'Preventive', 'control': 'Comprehensive audit logging of all order actions.'},
                     {'id': 'M_Order_3_2', 'type': 'Preventive', 'control': 'Email confirmations for order placement and shipment.'}
                 ]},
            ],
            'boundary_coords': {'x': 50, 'y': 350, 'width': 400, 'height': 200}
        },
        'Web App-Payment Gateway Boundary': {
            'description': 'Communication between the web application and the external payment gateway.',
            'components': ['Web Application', 'Payment Gateway'],
            'threats': [
                {'id': 'T_Order_4', 'name': 'Payment Gateway Bypass', 'category': 'Elevation of Privilege', 'likelihood': 3, 'impact': 3, 'risk_score': 9, 'risk_level': 'Medium',
                 'mitigations': [
                     {'id': 'M_Order_4_1', 'type': 'Preventive', 'control': 'Cryptographic signing/verification of payment callbacks.'},
                     {'id': 'M_Order_4_2', 'type': 'Preventive', 'control': 'Server-side validation of all payment statuses.'}
                 ]},
            ],
            'boundary_coords': {'x': 400, 'y': 350, 'width': 300, 'height': 200}
        },
        'Web App-Database Boundary': {
            'description': 'Communication between the web application and the order database.',
            'components': ['Web Application', 'Order Database'],
            'threats': [
                {'id': 'T_Order_5', 'name': 'SQL Injection (Order DB)', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Order_5_1', 'type': 'Preventive', 'control': 'Use parameterized queries/prepared statements.'},
                     {'id': 'M_Order_5_2', 'type': 'Preventive', 'control': 'Implement strict input validation and sanitization.'}
                 ]},
                {'id': 'T_Order_6', 'name': 'Data Exfiltration (Order DB)', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': 'M_Order_6_1', 'type': 'Preventive', 'control': 'Data encryption at rest and in transit.'},
                     {'id': 'M_Order_6_2', 'type': 'Detective', 'control': 'Audit logging and anomaly detection on database access.'}
                 ]},
            ],
            'boundary_coords': {'x': 200, 'y': 400, 'width': 300, 'height': 200}
        },
        'Web App-Shipping Service Boundary': {
            'description': 'Communication between the web application and the shipping service.',
            'components': ['Web Application', 'Shipping Service'],
            'threats': [],
            'boundary_coords': {'x': 400, 'y': 400, 'width': 300, 'height': 200}
        }
    }
    if sample_name == "Banking Application":
        return banking_threat_data
    elif sample_name == "Online Order Processing":
        return order_processing_threat_data
    return {}

# Initial data structure for architecture
def get_initial_architecture_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        return {'components': [], 'connections': [], 'boundaries': []}

    banking_components = [
        {'id': 'customer_bank_id', 'name': 'Bank Customer', 'type': 'User', 'description': 'End-user of the banking application', 'x': 100, 'y': 100},
        {'id': 'waf_id', 'name': 'WAF', 'type': 'Process', 'description': 'Web Application Firewall', 'x': 300, 'y': 50},
        {'id': 'load_balancer_id', 'name': 'Load Balancer', 'type': 'Process', 'description': 'Distributes traffic', 'x': 300, 'y': 150},
        {'id': 'web_server_id', 'name': 'Web Server (Bank)', 'type': 'Process', 'description': 'Serves banking web pages', 'x': 500, 'y': 100},
        {'id': 'login_comp_id', 'name': 'Login Component', 'type': 'Process', 'description': 'Handles user authentication', 'x': 500, 'y': 200},
        {'id': 'app_server_bank_id', 'name': 'App Server (Bank)', 'type': 'Process', 'description': 'Banking business logic', 'x': 700, 'y': 100},
        {'id': 'auth_service_id', 'name': 'Auth Service', 'type': 'Process', 'description': 'External authentication provider', 'x': 700, 'y': 200},
        {'id': 'db_server_bank_id', 'name': 'DB Server (Bank)', 'type': 'Data', 'description': 'Stores banking data', 'x': 900, 'y': 100},
        {'id': 'core_banking_id', 'name': 'Core Banking System', 'type': 'Data', 'description': 'Main banking ledger', 'x': 900, 'y': 200},
        {'id': 'payment_proc_id', 'name': 'Payment Processor', 'type': 'Process', 'description': 'Third-party payment service', 'x': 1100, 'y': 50},
        {'id': 'sms_email_id', 'name': 'SMS/Email Service', 'type': 'Process', 'description': 'Notification service', 'x': 1100, 'y': 150},
        {'id': 'credit_bureau_id', 'name': 'Credit Bureau', 'type': 'Process', 'description': 'Credit check service', 'x': 1100, 'y': 250},
    ]
    banking_connections = [
        {'id': 'conn_bank_1', 'source_id': 'customer_bank_id', 'target_id': 'waf_id', 'data_flow': 'HTTP/S', 'description': 'Customer traffic to WAF', 'trust_boundary_crossing': 'Internet -> DMZ'},
        {'id': 'conn_bank_2', 'source_id': 'customer_bank_id', 'target_id': 'load_balancer_id', 'data_flow': 'HTTP/S', 'description': 'Customer traffic to Load Balancer', 'trust_boundary_crossing': 'Internet -> DMZ'},
        {'id': 'conn_bank_3', 'source_id': 'waf_id', 'target_id': 'web_server_id', 'data_flow': 'HTTP/S', 'description': 'WAF to Web Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_4', 'source_id': 'load_balancer_id', 'target_id': 'web_server_id', 'data_flow': 'HTTP/S', 'description': 'Load Balancer to Web Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_5', 'source_id': 'web_server_id', 'target_id': 'app_server_bank_id', 'data_flow': 'API Call', 'description': 'Web Server to App Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_6', 'source_id': 'web_server_id', 'target_id': 'login_comp_id', 'data_flow': 'Internal API', 'description': 'Web Server to Login Component', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
        {'id': 'conn_bank_7', 'source_id': 'login_comp_id', 'target_id': 'auth_service_id', 'data_flow': 'Auth API', 'description': 'Login Component to Auth Service', 'trust_boundary_crossing': 'Internal App Tier -> External Auth'},
        {'id': 'conn_bank_8', 'source_id': 'app_server_bank_id', 'target_id': 'db_server_bank_id', 'data_flow': 'DB Connection', 'description': 'App Server to DB Server', 'trust_boundary_crossing': 'Internal App Tier -> Database'},
        {'id': 'conn_bank_9', 'source_id': 'app_server_bank_id', 'target_id': 'core_banking_id', 'data_flow': 'Core API', 'description': 'App Server to Core Banking', 'trust_boundary_crossing': 'Internal App Tier -> Core System'},
        {'id': 'conn_bank_10', 'source_id': 'app_server_bank_id', 'target_id': 'payment_proc_id', 'data_flow': 'Payment API', 'description': 'App Server to Payment Processor', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
        {'id': 'conn_bank_11', 'source_id': 'app_server_bank_id', 'target_id': 'sms_email_id', 'data_flow': 'Messaging API', 'description': 'App Server to SMS/Email Service', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
        {'id': 'conn_bank_12', 'source_id': 'app_server_bank_id', 'target_id': 'credit_bureau_id', 'data_flow': 'Credit Check API', 'description': 'App Server to Credit Bureau', 'trust_boundary_crossing': 'Internal App Tier -> External Service'},
    ]
    order_components = [
        {'id': 'customer_order_id', 'name': 'Order Customer', 'type': 'User', 'description': 'End-user of the order system', 'x': 100, 'y': 100},
        {'id': 'web_app_order_id', 'name': 'Web Application (Order)', 'type': 'Process', 'description': 'Online storefront for orders', 'x': 300, 'y': 100},
        {'id': 'payment_gateway_order_id', 'name': 'Payment Gateway (Order)', 'type': 'Process', 'description': 'Handles order payments', 'x': 500, 'y': 100},
        {'id': 'order_db_id', 'name': 'Order Database', 'type': 'Data', 'description': 'Stores order details', 'x': 300, 'y': 250},
        {'id': 'shipping_service_id', 'name': 'Shipping Service', 'type': 'Process', 'description': 'Manages product shipment', 'x': 500, 'y': 250},
    ]
    order_connections = [
        {'id': 'conn_order_1', 'source_id': 'customer_order_id', 'target_id': 'web_app_order_id', 'data_flow': 'Order Details', 'description': 'Customer submits order via web app', 'trust_boundary_crossing': 'Customer-Web App Boundary'},
        {'id': 'conn_order_2', 'source_id': 'web_app_order_id', 'target_id': 'payment_gateway_order_id', 'data_flow': 'Payment Request', 'description': 'Web app sends payment request to gateway', 'trust_boundary_crossing': 'Web App-Payment Gateway Boundary'},
        {'id': 'conn_order_3', 'source_id': 'payment_gateway_order_id', 'target_id': 'web_app_order_id', 'data_flow': 'Payment Confirmation', 'description': 'Payment gateway confirms payment to web app', 'trust_boundary_crossing': 'Web App-Payment Gateway Boundary'},
        {'id': 'conn_order_4', 'source_id': 'web_app_order_id', 'target_id': 'order_db_id', 'data_flow': 'Store Order', 'description': 'Web app stores order in database', 'trust_boundary_crossing': 'Web App-Database Boundary'},
        {'id': 'conn_order_5', 'source_id': 'web_app_order_id', 'target_id': 'shipping_service_id', 'data_flow': 'Shipment Request', 'description': 'Web app requests shipment from service', 'trust_boundary_crossing': 'Web App-Shipping Service Boundary'},
        {'id': 'conn_order_6', 'source_id': 'order_db_id', 'target_id': 'web_app_order_id', 'data_flow': 'Order Status', 'description': 'Web app retrieves order status from database', 'trust_boundary_crossing': 'Web App-Database Boundary'},
    ]

    if sample_name == "Banking Application":
        return {
            'components': banking_components,
            'connections': banking_connections,
            'boundaries': [
                {'id': 'boundary_bank_1', 'name': 'Internet -> DMZ', 'description': 'External users accessing web-facing components', 'x': 50, 'y': 20, 'width': 700, 'height': 250},
                {'id': 'boundary_bank_2', 'name': 'DMZ -> Internal App Tier', 'description': 'Web tier to application tier', 'x': 450, 'y': 20, 'width': 700, 'height': 300},
                {'id': 'boundary_bank_3', 'name': 'Internal App Tier -> Database', 'description': 'Application servers accessing database', 'x': 750, 'y': 50, 'width': 300, 'height': 200}
            ]
        }
    elif sample_name == "Online Order Processing":
        return {
            'components': order_components,
            'connections': order_connections,
            'boundaries': [
                {'id': 'boundary_order_1', 'name': 'Customer-Web App Boundary', 'description': 'Customer interaction with web app', 'x': 50, 'y': 350, 'width': 400, 'height': 200},
                {'id': 'boundary_order_2', 'name': 'Web App-Payment Gateway Boundary', 'description': 'Web app to payment gateway', 'x': 400, 'y': 350, 'width': 300, 'height': 200},
                {'id': 'boundary_order_3', 'name': 'Web App-Database Boundary', 'description': 'Web app to database', 'x': 200, 'y': 400, 'width': 300, 'height': 200},
                {'id': 'boundary_order_4', 'name': 'Web App-Shipping Service Boundary', 'description': 'Web app to shipping service', 'x': 400, 'y': 400, 'width': 300, 'height': 200}
            ]
        }
    return {'components': [], 'connections': [], 'boundaries': []}

# Initialize session state
if 'current_sample' not in st.session_state:
    st.session_state.current_sample = "Banking Application"

if 'threat_model' not in st.session_state:
    st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
if 'architecture' not in st.session_state:
    st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)

if 'show_report_sections' not in st.session_state:
    st.session_state.show_report_sections = False

def main():
    st.markdown("""
    <div class="main-header">
        <h1>🏦 Threat Model Dashboard</h1>
        <p>Comprehensive Threat Model & Data Flow Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.title("⚙️ Options")
    app_mode = st.sidebar.radio(
        "Go to",
        ["Threat Model Dashboard", "Trust Boundary Details"],
        key="app_mode_selector"
    )

    selected_app_type = st.sidebar.radio(
        "Select Application:",
        ("New Empty Model", "Banking Application", "Online Order Processing"),
        key="app_type_selector"
    )

    if selected_app_type != st.session_state.current_sample:
        st.session_state.current_sample = selected_app_type
        st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
        st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
        st.session_state.show_report_sections = False
        st.rerun()

    if st.sidebar.button("🔄 Reset Current Model"):
        st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
        st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
        st.session_state.show_report_sections = False
        st.rerun()
        st.success(f"Current model data reset to '{st.session_state.current_sample}' defaults.")

    if app_mode == "Threat Model Dashboard":
        render_threat_model_dashboard()
    elif app_mode == "Trust Boundary Details":
        render_trust_boundary_details()

def render_threat_model_dashboard():
    st.subheader("🏗️ 1. Define System Architecture")
    st.write("Drag and drop components (User, Process, Data) and define trust boundaries interactively. Connections indicate directional data flows aligned with trust boundaries.")

    all_current_boundaries = set(st.session_state.threat_model.keys())
    all_boundaries_for_js = sorted(list(all_current_boundaries.union(COMMON_TRUST_BOUNDARIES)))
    active_boundaries = list(st.session_state.threat_model.keys())
