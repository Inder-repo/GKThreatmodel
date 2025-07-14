import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import json
import uuid
from io import StringIO

# Page configuration
st.set_page_config(
    page_title="OWASP Threat Model",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

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
        background: rgba(255, 255, 255, 0.1);
        padding: 0.8rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid #51cf66;
    }
    .risk-critical { background-color: #dc3545; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-high { background-color: #fd7e14; color: white; padding: 0.3rem; border-radius: 5px; }
    .risk-medium { background-color: #ffc107; color: black; padding: 0.3rem; border-radius: 5px; }
    .risk-low { background-color: #28a745; color: white; padding: 0.3rem; border-radius: 5px; }
    .stride-category {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions
def calculate_risk(likelihood, impact):
    risk_score = likelihood * impact
    if risk_score >= 15:
        return risk_score, 'Critical'
    elif risk_score >= 10:
        return risk_score, 'High'
    elif risk_score >= 5:
        return risk_score, 'Medium'
    else:
        return risk_score, 'Low'

# STRIDE categories and default mitigations
STRIDE_CATEGORIES = [
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"
]
DEFAULT_MITIGATIONS = {
    'Spoofing': [
        {'type': 'Preventive', 'control': 'Implement Multi-Factor Authentication (MFA)'},
        {'type': 'Detective', 'control': 'Monitor authentication logs'},
    ],
    'Tampering': [
        {'type': 'Preventive', 'control': 'Use parameterized queries'},
        {'type': 'Preventive', 'control': 'Implement input validation'},
    ],
    'Repudiation': [
        {'type': 'Preventive', 'control': 'Implement comprehensive audit logging'},
        {'type': 'Detective', 'control': 'Monitor logs for inconsistencies'},
    ],
    'Information Disclosure': [
        {'type': 'Preventive', 'control': 'Encrypt data at rest and in transit'},
        {'type': 'Detective', 'control': 'Deploy DLP solutions'},
    ],
    'Denial of Service': [
        {'type': 'Preventive', 'control': 'Utilize DDoS protection services'},
        {'type': 'Preventive', 'control': 'Implement rate limiting'},
    ],
    'Elevation of Privilege': [
        {'type': 'Preventive', 'control': 'Implement role-based access control (RBAC)'},
        {'type': 'Detective', 'control': 'Monitor privilege escalation attempts'},
    ]
}

# Initial data for threat models
def get_initial_threat_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        return {}
    banking_threat_data = {
        'Internet -> DMZ': {
            'description': 'External users accessing web-facing components',
            'components': ['Bank Customer', 'WAF', 'Load Balancer'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Phishing Attacks', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Multi-Factor Authentication (MFA)'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Security awareness training'},
                 ]},
                {'id': str(uuid.uuid4()), 'name': 'DDoS Attacks', 'category': 'Denial of Service', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'DDoS Protection Service'},
                     {'id': str(uuid.uuid4()), 'type': 'Responsive', 'control': 'Traffic throttling'},
                 ]},
            ],
            'boundary_coords': {'x': 50, 'y': 20, 'width': 700, 'height': 250}
        },
        'DMZ -> Internal App Tier': {
            'description': 'Web tier to application tier',
            'components': ['Web Server (Bank)', 'App Server (Bank)'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'SQL Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Parameterized queries'},
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Input validation'},
                 ]},
            ],
            'boundary_coords': {'x': 450, 'y': 20, 'width': 700, 'height': 300}
        },
        'Internal App Tier -> Database': {
            'description': 'Application to database',
            'components': ['App Server (Bank)', 'DB Server (Bank)'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Data Exfiltration', 'category': 'Information Disclosure', 'likelihood': 2, 'impact': 5, 'risk_score': 10, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Data encryption'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Database activity monitoring'},
                 ]},
            ],
            'boundary_coords': {'x': 750, 'y': 50, 'width': 300, 'height': 200}
        },
    }
    order_processing_threat_data = {
        'Customer-Web App Boundary': {
            'description': 'Customer interaction with the web application',
            'components': ['Order Customer', 'Web Application (Order)'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Phishing Attack', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Multi-factor authentication'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Anti-phishing email filters'},
                 ]},
                {'id': str(uuid.uuid4()), 'name': 'Order Repudiation', 'category': 'Repudiation', 'likelihood': 2, 'impact': 3, 'risk_score': 6, 'risk_level': 'Low',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Audit logging of orders'},
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Email confirmations'},
                 ]},
            ],
            'boundary_coords': {'x': 50, 'y': 350, 'width': 400, 'height': 200}
        },
        'Web App-Database Boundary': {
            'description': 'Web app to database communication',
            'components': ['Web Application (Order)', 'Order Database'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'SQL Injection', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Parameterized queries'},
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Input sanitization'},
                 ]},
            ],
            'boundary_coords': {'x': 200, 'y': 400, 'width': 300, 'height': 200}
        },
    }
    healthcare_threat_data = {
        'Patient-Portal Boundary': {
            'description': 'Patient interaction with healthcare portal',
            'components': ['Patient', 'Healthcare Portal'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Credential Theft', 'category': 'Spoofing', 'likelihood': 4, 'impact': 5, 'risk_score': 20, 'risk_level': 'Critical',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Multi-factor authentication'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Monitor login attempts'},
                 ]},
                {'id': str(uuid.uuid4()), 'name': 'Session Hijacking', 'category': 'Spoofing', 'likelihood': 3, 'impact': 4, 'risk_score': 12, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Secure session management'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Session anomaly detection'},
                 ]},
            ],
            'boundary_coords': {'x': 50, 'y': 350, 'width': 400, 'height': 200}
        },
        'Portal-EHR Boundary': {
            'description': 'Portal to Electronic Health Record system',
            'components': ['Healthcare Portal', 'EHR System'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Data Tampering', 'category': 'Tampering', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Data integrity checks'},
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Secure APIs'},
                 ]},
            ],
            'boundary_coords': {'x': 400, 'y': 350, 'width': 400, 'height': 200}
        },
        'EHR-Database Boundary': {
            'description': 'EHR system to database',
            'components': ['EHR System', 'Patient Database'],
            'threats': [
                {'id': str(uuid.uuid4()), 'name': 'Data Breach', 'category': 'Information Disclosure', 'likelihood': 3, 'impact': 5, 'risk_score': 15, 'risk_level': 'High',
                 'mitigations': [
                     {'id': str(uuid.uuid4()), 'type': 'Preventive', 'control': 'Encrypt patient data'},
                     {'id': str(uuid.uuid4()), 'type': 'Detective', 'control': 'Database activity monitoring'},
                 ]},
            ],
            'boundary_coords': {'x': 200, 'y': 400, 'width': 300, 'height': 200}
        },
    }
    return {
        "Banking Application": banking_threat_data,
        "Online Order Processing": order_processing_threat_data,
        "Healthcare System": healthcare_threat_data
    }.get(sample_name, {})

# Initial data for architecture
def get_initial_architecture_data(sample_name="Banking Application"):
    if sample_name == "New Empty Model":
        return {'components': [], 'connections': [], 'boundaries': []}
    banking_architecture = {
        'components': [
            {'id': str(uuid.uuid4()), 'name': 'Bank Customer', 'type': 'External Entity', 'description': 'End-user of the banking application', 'x': 100, 'y': 100, 'boundary': 'Internet -> DMZ'},
            {'id': str(uuid.uuid4()), 'name': 'WAF', 'type': 'Process', 'description': 'Web Application Firewall', 'x': 300, 'y': 50, 'boundary': 'Internet -> DMZ'},
            {'id': str(uuid.uuid4()), 'name': 'Web Server (Bank)', 'type': 'Process', 'description': 'Serves banking web pages', 'x': 500, 'y': 100, 'boundary': 'DMZ -> Internal App Tier'},
            {'id': str(uuid.uuid4()), 'name': 'App Server (Bank)', 'type': 'Process', 'description': 'Banking business logic', 'x': 700, 'y': 100, 'boundary': 'DMZ -> Internal App Tier'},
            {'id': str(uuid.uuid4()), 'name': 'DB Server (Bank)', 'type': 'Data Store', 'description': 'Stores banking data', 'x': 900, 'y': 100, 'boundary': 'Internal App Tier -> Database'},
        ],
        'connections': [
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'HTTP/S', 'description': 'Customer traffic to WAF', 'trust_boundary_crossing': 'Internet -> DMZ'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'HTTP/S', 'description': 'WAF to Web Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'API Call', 'description': 'Web Server to App Server', 'trust_boundary_crossing': 'DMZ -> Internal App Tier'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'DB Connection', 'description': 'App Server to DB Server', 'trust_boundary_crossing': 'Internal App Tier -> Database'},
        ],
        'boundaries': [
            {'id': str(uuid.uuid4()), 'name': 'Internet -> DMZ', 'description': 'External users to web-facing components', 'x': 50, 'y': 20, 'width': 700, 'height': 250},
            {'id': str(uuid.uuid4()), 'name': 'DMZ -> Internal App Tier', 'description': 'Web tier to application tier', 'x': 450, 'y': 20, 'width': 700, 'height': 300},
            {'id': str(uuid.uuid4()), 'name': 'Internal App Tier -> Database', 'description': 'Application to database', 'x': 750, 'y': 50, 'width': 300, 'height': 200},
        ]
    }
    order_architecture = {
        'components': [
            {'id': str(uuid.uuid4()), 'name': 'Order Customer', 'type': 'External Entity', 'description': 'End-user of the order system', 'x': 100, 'y': 100, 'boundary': 'Customer-Web App Boundary'},
            {'id': str(uuid.uuid4()), 'name': 'Web Application (Order)', 'type': 'Process', 'description': 'Online storefront for orders', 'x': 300, 'y': 100, 'boundary': 'Customer-Web App Boundary'},
            {'id': str(uuid.uuid4()), 'name': 'Order Database', 'type': 'Data Store', 'description': 'Stores order details', 'x': 300, 'y': 250, 'boundary': 'Web App-Database Boundary'},
        ],
        'connections': [
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'Order Details', 'description': 'Customer submits order', 'trust_boundary_crossing': 'Customer-Web App Boundary'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'Store Order', 'description': 'Web app stores order', 'trust_boundary_crossing': 'Web App-Database Boundary'},
        ],
        'boundaries': [
            {'id': str(uuid.uuid4()), 'name': 'Customer-Web App Boundary', 'description': 'Customer to web app', 'x': 50, 'y': 350, 'width': 400, 'height': 200},
            {'id': str(uuid.uuid4()), 'name': 'Web App-Database Boundary', 'description': 'Web app to database', 'x': 200, 'y': 400, 'width': 300, 'height': 200},
        ]
    }
    healthcare_architecture = {
        'components': [
            {'id': str(uuid.uuid4()), 'name': 'Patient', 'type': 'External Entity', 'description': 'End-user of the healthcare portal', 'x': 100, 'y': 100, 'boundary': 'Patient-Portal Boundary'},
            {'id': str(uuid.uuid4()), 'name': 'Healthcare Portal', 'type': 'Process', 'description': 'Patient-facing web portal', 'x': 300, 'y': 100, 'boundary': 'Patient-Portal Boundary'},
            {'id': str(uuid.uuid4()), 'name': 'EHR System', 'type': 'Process', 'description': 'Electronic Health Record system', 'x': 500, 'y': 100, 'boundary': 'Portal-EHR Boundary'},
            {'id': str(uuid.uuid4()), 'name': 'Patient Database', 'type': 'Data Store', 'description': 'Stores patient data', 'x': 300, 'y': 250, 'boundary': 'EHR-Database Boundary'},
        ],
        'connections': [
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'Patient Data', 'description': 'Patient accesses portal', 'trust_boundary_crossing': 'Patient-Portal Boundary'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'EHR Query', 'description': 'Portal queries EHR', 'trust_boundary_crossing': 'Portal-EHR Boundary'},
            {'id': str(uuid.uuid4()), 'source_id': None, 'target_id': None, 'data_flow': 'DB Query', 'description': 'EHR accesses database', 'trust_boundary_crossing': 'EHR-Database Boundary'},
        ],
        'boundaries': [
            {'id': str(uuid.uuid4()), 'name': 'Patient-Portal Boundary', 'description': 'Patient to portal', 'x': 50, 'y': 350, 'width': 400, 'height': 200},
            {'id': str(uuid.uuid4()), 'name': 'Portal-EHR Boundary', 'description': 'Portal to EHR', 'x': 400, 'y': 350, 'width': 400, 'height': 200},
            {'id': str(uuid.uuid4()), 'name': 'EHR-Database Boundary', 'description': 'EHR to database', 'x': 200, 'y': 400, 'width': 300, 'height': 200},
        ]
    }
    # Update connections with correct source_id and target_id
    for arch in [banking_architecture, order_architecture, healthcare_architecture]:
        for conn in arch['connections']:
            for comp in arch['components']:
                if conn['description'].startswith(comp['name']):
                    conn['source_id'] = comp['id']
                elif conn['description'].endswith(comp['name']):
                    conn['target_id'] = comp['id']
    return {
        "Banking Application": banking_architecture,
        "Online Order Processing": order_architecture,
        "Healthcare System": healthcare_architecture
    }.get(sample_name, {'components': [], 'connections': [], 'boundaries': []})

# Initialize session state
if 'current_sample' not in st.session_state:
    st.session_state.current_sample = "Banking Application"
if 'threat_model' not in st.session_state:
    st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
if 'architecture' not in st.session_state:
    st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
if 'selected_node' not in st.session_state:
    st.session_state.selected_node = None
if 'selected_boundary' not in st.session_state:
    st.session_state.selected_boundary = None

def render_diagram():
    fig = go.Figure()
    # Draw trust boundaries
    for boundary in st.session_state.architecture['boundaries']:
        fig.add_shape(
            type="rect",
            x0=boundary['x'], y0=boundary['y'],
            x1=boundary['x'] + boundary['width'], y1=boundary['y'] + boundary['height'],
            line=dict(color="#007bff", width=2, dash="dash"),
            fillcolor="rgba(224,247,250,0.4)",
            layer="below",
            name=boundary['name']
        )
        fig.add_annotation(
            x=boundary['x'] + 10, y=boundary['y'] + 20,
            text=boundary['name'], showarrow=False,
            font=dict(size=12, color="#0056b3", family="Inter")
        )
    # Draw connections
    for conn in st.session_state.architecture['connections']:
        source = next((c for c in st.session_state.architecture['components'] if c['id'] == conn['source_id']), None)
        target = next((c for c in st.session_state.architecture['components'] if c['id'] == conn['target_id']), None)
        if source and target:
            color = "#ff6b6b" if conn['trust_boundary_crossing'] else "#764ba2"
            fig.add_trace(go.Scatter(
                x=[source['x'], target['x']], y=[source['y'], target['y']],
                mode="lines+text",
                line=dict(color=color, width=2, dash="dash" if conn['trust_boundary_crossing'] else "solid"),
                text=[None, f"{conn['data_flow']} ({conn['trust_boundary_crossing'] or 'N/A'})"],
                textposition="middle center",
                textfont=dict(size=10, color="#555", family="Inter")
            ))
            # Add arrowhead
            dx, dy = target['x'] - source['x'], target['y'] - source['y']
            length = (dx**2 + dy**2)**0.5
            if length > 0:
                arrow_x = target['x'] - 10 * dx / length
                arrow_y = target['y'] - 10 * dy / length
                fig.add_shape(
                    type="path",
                    path=f"M {arrow_x},{arrow_y} L {target['x']},{target['y']} L {arrow_x - 5 * dy / length},{arrow_y + 5 * dx / length} Z",
                    fillcolor=color, line_color=color
                )
    # Draw components
    for comp in st.session_state.architecture['components']:
        color = {"External Entity": "#ff6b6b", "Process": "#4ecdc4", "Data Store": "#ffeaa7", "Data Flow": "#95a5a6"}.get(comp['type'], "#cccccc")
        fig.add_trace(go.Scatter(
            x=[comp['x']], y=[comp['y']],
            mode="markers+text",
            marker=dict(size=40, color=color, symbol="square", line=dict(width=2, color="#333")),
            text=[comp['name']],
            textposition="middle center",
            textfont=dict(size=12, color="#333", family="Inter"),
            customdata=[comp['id']],
            hoverinfo="text",
            name=comp['name']
        ))
    fig.update_layout(
        showlegend=False, dragmode="pan", clickmode="event+select",
        xaxis=dict(range=[0, 1200], showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(range=[0, 600], showgrid=False, zeroline=False, showticklabels=False, scaleanchor="x", scaleratio=1),
        height=600, margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="#f9f9f9"
    )
    # Handle click and drag
    config = {"scrollZoom": True}
    plot = st.plotly_chart(fig, use_container_width=True, config=config)
    if plot:
        selected_points = plot.get("selections", [])
        if selected_points:
            selected_id = selected_points[0].get("customdata", [None])[0]
            st.session_state.selected_node = next((c for c in st.session_state.architecture['components'] if c['id'] == selected_id), None)
            st.session_state.selected_boundary = None
        else:
            st.session_state.selected_node = None
            st.session_state.selected_boundary = None
    return fig

def main():
    st.markdown("""
    <div class="main-header">
        <h1>🔒 OWASP Threat Model Dashboard</h1>
        <p>Comprehensive Threat Modeling using STRIDE and OWASP Guidelines</p>
    </div>
    """, unsafe_allow_html=True)

    st.sidebar.title("⚙️ Options")
    app_mode = st.sidebar.radio("Go to", ["Architecture", "Trust Boundaries", "STRIDE Analysis", "Report"], key="app_mode_selector")
    selected_app_type = st.sidebar.radio("Select Application:", ["New Empty Model", "Banking Application", "Online Order Processing", "Healthcare System"], key="app_type_selector")
    
    if selected_app_type != st.session_state.current_sample:
        st.session_state.current_sample = selected_app_type
        st.session_state.threat_model = get_initial_threat_data(selected_app_type)
        st.session_state.architecture = get_initial_architecture_data(selected_app_type)
        st.session_state.selected_node = None
        st.session_state.selected_boundary = None
        st.rerun()

    if st.sidebar.button("🔄 Reset Current Model"):
        st.session_state.threat_model = get_initial_threat_data(st.session_state.current_sample)
        st.session_state.architecture = get_initial_architecture_data(st.session_state.current_sample)
        st.session_state.selected_node = None
        st.session_state.selected_boundary = None
        st.rerun()
        st.success(f"Model reset to '{st.session_state.current_sample}' defaults.")

    if app_mode == "Architecture":
        st.subheader("🏗️ 1. Define System Architecture (Scope)")
        st.write("Add components, connections, and trust boundaries. Click and drag components in the diagram.")
        render_diagram()
        col1, col2, col3 = st.columns(3)
        with col1:
            with st.form("add_component_form", clear_on_submit=True):
                st.write("**Add Component**")
                name = st.text_input("Name")
                type_ = st.selectbox("Type", ["External Entity", "Process", "Data Store", "Data Flow"])
                description = st.text_area("Description")
                boundary = st.selectbox("Trust Boundary", [""] + list(st.session_state.threat_model.keys()))
                x = st.number_input("X Coordinate", 0, 1200, 100)
                y = st.number_input("Y Coordinate", 0, 600, 100)
                if st.form_submit_button("Add Component"):
                    if name:
                        st.session_state.architecture['components'].append({
                            'id': str(uuid.uuid4()), 'name': name, 'type': type_, 'description': description,
                            'x': x, 'y': y, 'boundary': boundary or None
                        })
                        st.rerun()
                    else:
                        st.error("Component name is required.")
        with col2:
            with st.form("add_connection_form", clear_on_submit=True):
                st.write("**Add Connection**")
                components = {c['name']: c['id'] for c in st.session_state.architecture['components']}
                source = st.selectbox("Source Component", components.keys())
                target = st.selectbox("Target Component", components.keys())
                data_flow = st.text_input("Data Flow Type (e.g., HTTP/S)")
                description = st.text_area("Description")
                trust_boundary = st.selectbox("Trust Boundary Crossed", [""] + list(st.session_state.threat_model.keys()))
                if st.form_submit_button("Add Connection"):
                    if source and target and data_flow and source != target:
                        st.session_state.architecture['connections'].append({
                            'id': str(uuid.uuid4()), 'source_id': components[source], 'target_id': components[target],
                            'data_flow': data_flow, 'description': description, 'trust_boundary_crossing': trust_boundary or "N/A"
                        })
                        st.rerun()
                    else:
                        st.error("Select valid source/target and provide data flow.")
        with col3:
            with st.form("add_boundary_form", clear_on_submit=True):
                st.write("**Add Trust Boundary**")
                name = st.text_input("Boundary Name")
                description = st.text_area("Boundary Description")
                x = st.number_input("X Coordinate", 0, 1200, 50)
                y = st.number_input("Y Coordinate", 0, 600, 50)
                width = st.number_input("Width", 100, 1100, 300)
                height = st.number_input("Height", 100, 500, 200)
                if st.form_submit_button("Add Boundary"):
                    if name:
                        st.session_state.architecture['boundaries'].append({
                            'id': str(uuid.uuid4()), 'name': name, 'description': description,
                            'x': x, 'y': y, 'width': width, 'height': height
                        })
                        st.session_state.threat_model[name] = {'description': description, 'components': [], 'threats': []}
                        st.rerun()
                    else:
                        st.error("Boundary name is required.")
        if st.session_state.selected_node:
            with st.form("edit_component_form", clear_on_submit=True):
                st.write(f"**Edit Component: {st.session_state.selected_node['name']}**")
                name = st.text_input("Name", st.session_state.selected_node['name'])
                type_ = st.selectbox("Type", ["External Entity", "Process", "Data Store", "Data Flow"], index=["External Entity", "Process", "Data Store", "Data Flow"].index(st.session_state.selected_node['type']))
                description = st.text_area("Description", st.session_state.selected_node['description'])
                boundary = st.selectbox("Trust Boundary", [""] + list(st.session_state.threat_model.keys()), index=list(st.session_state.threat_model.keys()).index(st.session_state.selected_node['boundary']) if st.session_state.selected_node['boundary'] else 0)
                x = st.number_input("X Coordinate", 0, 1200, int(st.session_state.selected_node['x']))
                y = st.number_input("Y Coordinate", 0, 600, int(st.session_state.selected_node['y']))
                if st.form_submit_button("Update Component"):
                    if name:
                        for comp in st.session_state.architecture['components']:
                            if comp['id'] == st.session_state.selected_node['id']:
                                comp.update({'name': name, 'type': type_, 'description': description, 'boundary': boundary or None, 'x': x, 'y': y})
                        st.session_state.selected_node = None
                        st.rerun()
                    else:
                        st.error("Component name is required.")
                if st.form_submit_button("Delete Component"):
                    st.session_state.architecture['components'] = [c for c in st.session_state.architecture['components'] if c['id'] != st.session_state.selected_node['id']]
                    st.session_state.architecture['connections'] = [c for c in st.session_state.architecture['connections'] if c['source_id'] != st.session_state.selected_node['id'] and c['target_id'] != st.session_state.selected_node['id']]
                    st.session_state.selected_node = None
                    st.rerun()

    elif app_mode == "Trust Boundaries":
        st.subheader("🔐 2. Trust Boundary Details")
        st.write("Manage threats and mitigations for each trust boundary using STRIDE.")
        for boundary_name, boundary_data in st.session_state.threat_model.items():
            with st.expander(f"{boundary_name}"):
                st.markdown(f"**Description**: {boundary_data.get('description', '')}")
                st.markdown(f"**Components**: {', '.join(boundary_data.get('components', []))}")
                for threat in boundary_data.get('threats', []):
                    st.markdown(f"""
                    <div class="threat-item">
                        <strong>{threat['name']}</strong> ({threat['category']}) - Risk: <span class="risk-{threat['risk_level'].lower()}">{threat['risk_level']}</span>
                        <br>Likelihood: {threat['likelihood']}, Impact: {threat['impact']}
                        <br><strong>Mitigations:</strong> {', '.join([m['control'] for m in threat.get('mitigations', [])])}
                    </div>
                    """, unsafe_allow_html=True)
                    with st.form(f"edit_threat_{threat['id']}", clear_on_submit=True):
                        st.write(f"**Edit Threat: {threat['name']}**")
                        t_name = st.text_input("Threat Name", threat['name'])
                        t_category = st.selectbox("STRIDE Category", STRIDE_CATEGORIES, index=STRIDE_CATEGORIES.index(threat['category']))
                        t_likelihood = st.slider("Likelihood (1-5)", 1, 5, threat['likelihood'])
                        t_impact = st.slider("Impact (1-5)", 1, 5, threat['impact'])
                        t_mitigations = st.multiselect("Select Mitigations", [m['control'] for m in DEFAULT_MITIGATIONS[t_category]], default=[m['control'] for m in threat.get('mitigations', [])])
                        if st.form_submit_button("Update Threat"):
                            risk_score, risk_level = calculate_risk(t_likelihood, t_impact)
                            for b in st.session_state.threat_model.values():
                                for t in b.get('threats', []):
                                    if t['id'] == threat['id']:
                                        t.update({
                                            'name': t_name, 'category': t_category, 'likelihood': t_likelihood,
                                            'impact': t_impact, 'risk_score': risk_score, 'risk_level': risk_level,
                                            'mitigations': [{'id': str(uuid.uuid4()), 'type': DEFAULT_MITIGATIONS[t_category][[m['control'] for m in DEFAULT_MITIGATIONS[t_category]].index(m)]['type'], 'control': m} for m in t_mitigations]
                                        })
                            st.rerun()
                        if st.form_submit_button("Delete Threat"):
                            for b in st.session_state.threat_model.values():
                                b['threats'] = [t for t in b.get('threats', []) if t['id'] != threat['id']]
                            st.rerun()
                with st.form(f"add_threat_{boundary_name}", clear_on_submit=True):
                    st.write("**Add New Threat**")
                    threat_name = st.text_input("Threat Name")
                    threat_category = st.selectbox("STRIDE Category", STRIDE_CATEGORIES)
                    threat_likelihood = st.slider("Likelihood (1-5)", 1, 5, 3)
                    threat_impact = st.slider("Impact (1-5)", 1, 5, 3)
                    mitigations = st.multiselect("Select Mitigations", [m['control'] for m in DEFAULT_MITIGATIONS[threat_category]])
                    if st.form_submit_button("Add Threat"):
                        if threat_name:
                            risk_score, risk_level = calculate_risk(threat_likelihood, threat_impact)
                            boundary_data.setdefault('threats', []).append({
                                'id': str(uuid.uuid4()), 'name': threat_name, 'category': threat_category,
                                'likelihood': threat_likelihood, 'impact': threat_impact,
                                'risk_score': risk_score, 'risk_level': risk_level,
                                'mitigations': [{'id': str(uuid.uuid4()), 'type': DEFAULT_MITIGATIONS[threat_category][[m['control'] for m in DEFAULT_MITIGATIONS[threat_category]].index(m)]['type'], 'control': m} for m in mitigations]
                            })
                            st.rerun()
                        else:
                            st.error("Threat name is required.")

    elif app_mode == "STRIDE Analysis":
        st.subheader("📊 3. STRIDE Analysis")
        st.write("Analyze threats by STRIDE category and risk level.")
        threats = []
        for boundary_data in st.session_state.threat_model.values():
            threats.extend(boundary_data.get('threats', []))
        if threats:
            df = pd.DataFrame(threats)
            fig = go.Figure(data=[
                go.Bar(x=STRIDE_CATEGORIES, y=[len(df[df['category'] == cat]) for cat in STRIDE_CATEGORIES], marker_color='#667eea')
            ])
            fig.update_layout(title="Threat Distribution by STRIDE Category", xaxis_title="STRIDE Category", yaxis_title="Number of Threats")
            st.plotly_chart(fig, use_container_width=True)
            # Risk Heatmap
            heatmap_data = [[len([t for t in threats if t['likelihood'] == l and t['impact'] == i]) for i in range(1, 6)] for l in range(1, 6)]
            fig_heatmap = go.Figure(data=go.Heatmap(
                z=heatmap_data, x=list(range(1, 6)), y=list(range(1, 6)),
                colorscale="Viridis", text=heatmap_data, texttemplate="%{text}", showscale=True
            ))
            fig_heatmap.update_layout(title="Risk Heatmap (Likelihood vs Impact)", xaxis_title="Impact", yaxis_title="Likelihood")
            st.plotly_chart(fig_heatmap, use_container_width=True)

    elif app_mode == "Report":
        st.subheader("📄 4. Threat Model Report")
        st.write("Summary of the threat model and export option.")
        st.markdown(f"**Application**: {st.session_state.current_sample}")
        for boundary_name, boundary_data in st.session_state.threat_model.items():
            st.markdown(f"### {boundary_name}")
            st.markdown(f"**Description**: {boundary_data.get('description', '')}")
            st.markdown(f"**Components**: {', '.join(boundary_data.get('components', []))}")
            st.markdown("**Threats**:")
            for threat in boundary_data.get('threats', []):
                st.markdown(f"""
                <div class="threat-item">
                    <strong>{threat['name']}</strong> ({threat['category']}) - Risk: <span class="risk-{threat['risk_level'].lower()}">{threat['risk_level']}</span>
                    <br>Likelihood: {threat['likelihood']}, Impact: {threat['impact']}
                    <br><strong>Mitigations:</strong> {', '.join([m['control'] for m in threat.get('mitigations', [])])}
                </div>
                """, unsafe_allow_html=True)
        st.download_button(
            label="📥 Download Threat Model (JSON)",
            data=json.dumps({'architecture': st.session_state.architecture, 'threat_model': st.session_state.threat_model}, indent=2),
            file_name=f"{st.session_state.current_sample}_threat_model.json",
            mime="application/json"
        )

if __name__ == "__main__":
    main()
