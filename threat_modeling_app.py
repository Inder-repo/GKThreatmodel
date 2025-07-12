import streamlit as st
import pandas as pd
import json
import base64
import logging
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from PIL import Image as PILImage
import io
import sqlite3
import plotly.express as px
import csv
import streamlit.components.v1 as components

# Configure logging
logging.basicConfig(
    filename="threat_modeling_app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("threat_models.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            architecture TEXT,
            dfd_elements TEXT,
            threats TEXT,
            username TEXT,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            role TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "adminpass", "admin"))
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ("student", "password", "user"))
    conn.commit()
    conn.close()

init_db()

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "dfd_elements" not in st.session_state:
    st.session_state.dfd_elements = []
if "dfd_image" not in st.session_state:
    st.session_state.dfd_image = None
if "theme" not in st.session_state:
    st.session_state.theme = "light"

# Comprehensive STRIDE threat library
stride_library = {
    "Spoofing": [
        {
            "threat": "Unauthorized user impersonation via stolen credentials",
            "vulnerability": "Weak password policies or lack of Multi-Factor Authentication (MFA)",
            "risk": "High",
            "mitigation": "Enforce strong password policies, implement MFA (e.g., TOTP, biometrics), and use account lockout mechanisms.",
            "compliance": "NIST 800-63B, ISO 27001 A.9.4.2"
        },
        {
            "threat": "Session hijacking through stolen session tokens",
            "vulnerability": "Insecure session management or lack of secure cookies",
            "risk": "High",
            "mitigation": "Use secure, HTTP-only cookies, implement short session timeouts, and enforce TLS.",
            "compliance": "OWASP ASVS 3.4"
        },
        {
            "threat": "Man-in-the-Middle (MITM) attack to impersonate server",
            "vulnerability": "Missing or misconfigured TLS certificates",
            "risk": "Medium",
            "mitigation": "Implement proper TLS configurations with HSTS and certificate pinning.",
            "compliance": "PCI DSS 4.1"
        }
    ],
    "Tampering": [
        {
            "threat": "Modification of data in transit",
            "vulnerability": "Lack of encryption or integrity checks for data transmission",
            "risk": "High",
            "mitigation": "Use TLS for data in transit and implement integrity checks (e.g., HMAC, digital signatures).",
            "compliance": "NIST 800-53 SC-8"
        },
        {
            "threat": "Injection attacks (e.g., SQL, Command Injection)",
            "vulnerability": "Improper input validation or sanitization",
            "risk": "Critical",
            "mitigation": "Implement parameterized queries, input validation, and sanitization using allowlists.",
            "compliance": "OWASP Top 10 A03:2021"
        },
        {
            "threat": "Unauthorized modification of database records",
            "vulnerability": "Inadequate access controls or lack of transaction logging",
            "risk": "High",
            "mitigation": "Enforce least privilege access controls and implement audit logging for database changes.",
            "compliance": "ISO 27001 A.12.4.1"
        }
    ],
    "Repudiation": [
        {
            "threat": "Denial of user actions (e.g., transactions)",
            "vulnerability": "Lack of audit logging or non-repudiation mechanisms",
            "risk": "Medium",
            "mitigation": "Implement comprehensive audit logging with timestamps and digital signatures.",
            "compliance": "NIST 800-53 AU-2"
        },
        {
            "threat": "Forged log entries by malicious actors",
            "vulnerability": "Insecure log storage or lack of tamper-proof logging",
            "risk": "Medium",
            "mitigation": "Use tamper-evident logging (e.g., blockchain-based logs or secure log aggregation services).",
            "compliance": "ISO 27001 A.12.4.3"
        }
    ],
    "Information Disclosure": [
        {
            "threat": "Exposure of sensitive data in transit",
            "vulnerability": "Unencrypted communication channels",
            "risk": "High",
            "mitigation": "Enforce TLS 1.3 for all communications and validate certificates.",
            "compliance": "GDPR Article 32"
        },
        {
            "threat": "Unauthorized access to sensitive data at rest",
            "vulnerability": "Unencrypted storage or weak access controls",
            "risk": "High",
            "mitigation": "Encrypt sensitive data at rest (e.g., AES-256) and implement strict access controls.",
            "compliance": "NIST 800-53 SC-28"
        },
        {
            "threat": "Data leakage through error messages",
            "vulnerability": "Verbose error handling exposing system details",
            "risk": "Low",
            "mitigation": "Implement generic error messages and disable debugging in production.",
            "compliance": "OWASP ASVS 4.1"
        }
    ],
    "Denial of Service": [
        {
            "threat": "Resource exhaustion via excessive API requests",
            "vulnerability": "Lack of rate limiting or throttling",
            "risk": "Medium",
            "mitigation": "Implement API rate limiting and throttling mechanisms.",
            "compliance": "NIST 800-53 SC-5"
        },
        {
            "threat": "Distributed Denial of Service (DDoS) attack",
            "vulnerability": "Lack of DDoS protection or insufficient resource scaling",
            "risk": "High",
            "mitigation": "Use DDoS protection services (e.g., Cloudflare, AWS Shield) and auto-scaling infrastructure.",
            "compliance": "ISO 27001 A.12.1.3"
        },
        {
            "threat": "Application layer DoS via slow HTTP requests",
            "vulnerability": "Inadequate request timeout configurations",
            "risk": "Medium",
            "mitigation": "Configure appropriate request timeouts and monitor slow requests.",
            "compliance": "OWASP ASVS 4.2"
        }
    ],
    "Elevation of Privilege": [
        {
            "threat": "Unauthorized admin access via privilege escalation",
            "vulnerability": "Insecure role-based access control (RBAC) or session management",
            "risk": "Critical",
            "mitigation": "Implement least privilege, validate RBAC, and conduct regular access reviews.",
            "compliance": "NIST 800-53 AC-6"
        },
        {
            "threat": "Exploitation of misconfigured cloud permissions",
            "vulnerability": "Overly permissive IAM roles in cloud environments",
            "risk": "High",
            "mitigation": "Use least privilege IAM policies and regularly audit cloud configurations.",
            "compliance": "AWS Well-Architected Framework"
        },
        {
            "threat": "Exploitation of unpatched software vulnerabilities",
            "vulnerability": "Outdated software or missing security patches",
            "risk": "High",
            "mitigation": "Implement a patch management process and regular vulnerability scanning.",
            "compliance": "ISO 27001 A.12.6.1"
        }
    ]
}

# Pre-defined threat models
pre_defined_threat_models = [
    {
        "name": "Online Banking Application",
        "architecture": "A web-based banking application with a React frontend, Node.js backend, and MySQL database, hosted on AWS. Users authenticate via username/password, and sensitive data is transmitted over HTTPS.",
        "threats": [
            stride_library["Spoofing"][0],
            stride_library["Tampering"][0],
            stride_library["Information Disclosure"][0],
            stride_library["Denial of Service"][1],
            stride_library["Elevation of Privilege"][0]
        ]
    },
    {
        "name": "E-Commerce Platform",
        "architecture": "A microservices-based e-commerce platform with an Angular frontend, Spring Boot backend services, MongoDB database, and Stripe for payment processing, hosted on Kubernetes in Azure.",
        "threats": [
            stride_library["Tampering"][1],
            stride_library["Repudiation"][0],
            stride_library["Information Disclosure"][1],
            stride_library["Denial of Service"][0],
            stride_library["Elevation of Privilege"][1]
        ]
    }
]

# DFD Templates
dfd_templates = {
    "Web Application": [
        {"type": "External Entity", "name": "User", "technology": "Browser", "x": 50, "y": 50},
        {"type": "Process", "name": "Web Server", "technology": "Node.js", "x": 200, "y": 150},
        {"type": "Data Store", "name": "Database", "technology": "MySQL", "x": 350, "y": 150},
        {"type": "Data Flow", "name": "User Request", "data_flow": "HTTP request with credentials", "source": "User", "target": "Web Server"},
        {"type": "Data Flow", "name": "Database Query", "data_flow": "SQL query", "source": "Web Server", "target": "Database"},
        {"type": "Trust Boundary", "name": "Network Boundary", "trust_boundary": "Public Internet vs. Internal Network", "x": 150, "y": 100, "width": 300, "height": 200}
    ],
    "Microservices": [
        {"type": "External Entity", "name": "Customer", "technology": "Mobile App", "x": 50, "y": 50},
        {"type": "Process", "name": "API Gateway", "technology": "Spring Cloud Gateway", "x": 200, "y": 150},
        {"type": "Process", "name": "Order Service", "technology": "Spring Boot", "x": 350, "y": 150},
        {"type": "Data Store", "name": "Order Database", "technology": "MongoDB", "x": 500, "y": 150},
        {"type": "Data Flow", "name": "Order Request", "data_flow": "REST API call", "source": "Customer", "target": "API Gateway"},
        {"type": "Data Flow", "name": "Service Call", "data_flow": "Internal API call", "source": "API Gateway", "target": "Order Service"},
        {"type": "Data Flow", "name": "Database Access", "data_flow": "MongoDB query", "source": "Order Service", "target": "Order Database"},
        {"type": "Trust Boundary", "name": "Service Boundary", "trust_boundary": "Public API vs. Internal Services", "x": 250, "y": 100, "width": 300, "height": 200}
    ]
}

# Function to validate inputs
def validate_input(value, field_name, max_length=500):
    if not value or len(value.strip()) == 0:
        logger.error(f"Validation failed: {field_name} is empty")
        return False, f"{field_name} cannot be empty."
    if len(value) > max_length:
        logger.error(f"Validation failed: {field_name} exceeds {max_length} characters")
        return False, f"{field_name} exceeds {max_length} characters."
    return True, ""

# Function to validate DFD structure
def validate_dfd(dfd_elements):
    try:
        processes = [e for e in dfd_elements if e["type"] == "Process"]
        data_stores = [e for e in dfd_elements if e["type"] == "Data Store"]
        data_flows = [e for e in dfd_elements if e["type"] == "Data Flow"]
        if not processes:
            return False, "At least one Process is required in the DFD."
        for flow in data_flows:
            source_exists = any(e["name"] == flow["source"] for e in processes + data_stores + [e for e in dfd_elements if e["type"] == "External Entity"])
            target_exists = any(e["name"] == flow["target"] for e in processes + data_stores)
            if not (source_exists and target_exists):
                return False, f"Data Flow '{flow['name']}' must connect valid source and target components."
        return True, ""
    except Exception as e:
        logger.error(f"DFD validation failed: {str(e)}")
        return False, str(e)

# Function to generate AI-powered threat suggestions
def suggest_threats(architecture, dfd_elements):
    keywords = {
        "web": ["Spoofing", "Tampering", "Information Disclosure"],
        "database": ["Information Disclosure", "Tampering"],
        "api": ["Denial of Service", "Elevation of Privilege"],
        "cloud": ["Elevation of Privilege"],
        "mobile": ["Spoofing", "Information Disclosure"]
    }
    suggested_threats = []
    architecture_lower = architecture.lower()
    for keyword, threat_types in keywords.items():
        if keyword in architecture_lower or any(keyword in e.get("technology", "").lower() for e in dfd_elements):
            for threat_type in threat_types:
                suggested_threats.extend([t for t in stride_library[threat_type] if t not in suggested_threats])
    return suggested_threats

# Function to generate threat model from DFD
def generate_threat_model_from_dfd(dfd_elements, architecture):
    try:
        threats = []
        component_types = [elem["type"] for elem in dfd_elements]
        data_flows = [elem for elem in dfd_elements if elem["type"] == "Data Flow"]
        trust_boundaries = [elem for elem in dfd_elements if elem["type"] == "Trust Boundary"]

        # Graph-based threat mapping
        if "Process" in component_types:
            threats.extend([stride_library["Spoofing"][0], stride_library["Tampering"][1], stride_library["Elevation of Privilege"][0]])
        if "Data Store" in component_types:
            threats.extend([stride_library["Information Disclosure"][1], stride_library["Tampering"][2]])
        if "External Entity" in component_types:
            threats.append(stride_library["Spoofing"][1])
        if data_flows:
            threats.append(stride_library["Information Disclosure"][0])
            for flow in data_flows:
                if any("database" in e.get("technology", "").lower() for e in dfd_elements if e["name"] == flow["target"]):
                    threats.append(stride_library["Tampering"][0])
        if trust_boundaries:
            threats.append(stride_library["Elevation of Privilege"][1])

        # Add AI-suggested threats
        threats.extend(suggest_threats(architecture, dfd_elements))

        # Remove duplicates
        seen = set()
        unique_threats = [t for t in threats if not (t["threat"] in seen or seen.add(t["threat"]))]
        
        logger.info(f"Generated threat model with {len(unique_threats)} threats")
        return unique_threats
    except Exception as e:
        logger.error(f"Error generating threat model from DFD: {str(e)}")
        raise

# Function to create a JSON report
def create_json_report(threat_model_name, architecture, dfd_elements, threats):
    try:
        report = {
            "threat_model_name": threat_model_name,
            "architecture": architecture,
            "dfd_elements": dfd_elements,
            "threats": threats,
            "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "generated_by": st.session_state.username or "Anonymous"
        }
        report_json = json.dumps(report, indent=2)
        b64 = base64.b64encode(report_json.encode()).decode()
        href = f'<a href="data:application/json;base64,{b64}" download="{threat_model_name}_report.json">Download JSON Report</a>'
        return href
    except Exception as e:
        logger.error(f"Error creating JSON report: {str(e)}")
        raise

# Function to create a CSV report
def create_csv_report(threat_model_name, threats):
    try:
        filename = f"{threat_model_name}_report.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"])
            for threat in threats:
                writer.writerow([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]])
        with open(filename, "rb") as f:
            csv_data = f.read()
        b64 = base64.b64encode(csv_data).decode()
        href = f'<a href="data:application/csv;base64,{b64}" download="{filename}">Download CSV Report</a>'
        return href
    except Exception as e:
        logger.error(f"Error creating CSV report: {str(e)}")
        raise

# Function to create a PDF report with DFD image
def create_pdf_report(threat_model_name, architecture, dfd_elements, threats, dfd_image_path=None):
    try:
        filename = f"{threat_model_name}_report.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(f"Threat Model Report: {threat_model_name}", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Paragraph(f"Generated by: {st.session_state.username or 'Anonymous'}", styles["Normal"]))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(f"This threat model for {threat_model_name} identifies {len(threats)} potential threats using the STRIDE methodology. The system architecture and DFD elements have been analyzed to provide actionable mitigations and compliance mappings.", styles["Normal"]))
        story.append(Spacer(1, 12))

        # Architecture Details
        story.append(Paragraph("System Architecture", styles["Heading2"]))
        story.append(Paragraph(architecture, styles["Normal"]))
        story.append(Spacer(1, 12))

        # DFD Elements
        story.append(Paragraph("DFD Elements", styles["Heading2"]))
        dfd_data = [[elem["type"], elem.get("name", ""), elem.get("technology", ""), elem.get("data_flow", ""), elem.get("trust_boundary", ""), elem.get("x", ""), elem.get("y", "")] for elem in dfd_elements]
        dfd_table = Table([["Type", "Name", "Technology", "Data Flow", "Trust Boundary", "X", "Y"]] + dfd_data)
        dfd_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(dfd_table)
        story.append(Spacer(1, 12))

        # DFD Image
        if dfd_image_path:
            story.append(Paragraph("Data Flow Diagram", styles["Heading2"]))
            story.append(Image(dfd_image_path, width=400, height=200))
            story.append(Spacer(1, 12))

        # Threats Table
        story.append(Paragraph("Threats Identified", styles["Heading2"]))
        threat_data = [["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"]]
        for threat in threats:
            threat_data.append([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]])
        threat_table = Table(threat_data)
        threat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(threat_table)

        doc.build(story)
        with open(filename, "rb") as f:
            pdf_data = f.read()
        b64 = base64.b64encode(pdf_data).decode()
        href = f'<a href="data:application/pdf;base64,{b64}" download="{filename}">Download PDF Report</a>'
        return href
    except Exception as e:
        logger.error(f"Error creating PDF report: {str(e)}")
        raise

# Function to create risk distribution chart
def create_risk_chart(threats):
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for threat in threats:
        risk_counts[threat["risk"]] += 1
    df = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
    fig = px.bar(df, x="Risk Level", y="Count", title="Risk Distribution", color="Risk Level")
    return fig

# Drag-and-Drop DFD Editor HTML/JavaScript
dfd_editor_html = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; }
        .toolbar { background: #f0f0f0; padding: 10px; border-bottom: 1px solid #ccc; }
        .toolbar button { margin: 5px; padding: 8px; cursor: move; }
        .canvas { width: 800px; height: 400px; border: 1px solid #000; position: relative; background: #fff; }
        .canvas.dark { background: #2a2a2a; }
        .element { position: absolute; border: 1px solid #000; text-align: center; line-height: 30px; cursor: move; }
        .process { width: 60px; height: 60px; border-radius: 50%; background: #aaffaa; }
        .data-store { width: 100px; height: 40px; background: #aaaaff; }
        .external-entity { width: 100px; height: 40px; background: #ffaaaa; }
        .trust-boundary { border: 2px dashed #000; background: none; }
        .selected { border: 2px solid red; }
        svg { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
    </style>
</head>
<body>
    <div class="toolbar">
        <button draggable="true" data-type="Process">Process</button>
        <button draggable="true" data-type="Data Store">Data Store</button>
        <button draggable="true" data-type="External Entity">External Entity</button>
        <button draggable="true" data-type="Trust Boundary">Trust Boundary</button>
        <button onclick="startDrawingArrow()">Data Flow</button>
        <button onclick="clearCanvas()">Clear Canvas</button>
    </div>
    <div id="canvas" class="canvas"></div>
    <svg id="arrows"></svg>
    <script>
        let elements = [];
        let arrows = [];
        let selectedElement = null;
        let drawingArrow = false;
        let arrowStart = null;
        const canvas = document.getElementById('canvas');
        const arrowsSvg = document.getElementById('arrows');
        
        // Apply theme
        function applyTheme(theme) {
            if (theme === 'dark') {
                canvas.classList.add('dark');
            } else {
                canvas.classList.remove('dark');
            }
        }
        applyTheme('%s');

        // Drag and Drop
        document.querySelectorAll('.toolbar button').forEach(button => {
            button.addEventListener('dragstart', (e) => {
                e.dataTransfer.setData('type', e.target.dataset.type);
            });
        });

        canvas.addEventListener('dragover', (e) => {
            e.preventDefault();
        });

        canvas.addEventListener('drop', (e) => {
            e.preventDefault();
            const type = e.dataTransfer.getData('type');
            if (type && type !== 'Data Flow') {
                const id = 'elem_' + Date.now();
                const x = e.offsetX - (type === 'Process' ? 30 : 50);
                const y = e.offsetY - (type === 'Process' ? 30 : 20);
                const width = type === 'Trust Boundary' ? 150 : (type === 'Process' ? 60 : 100);
                const height = type === 'Trust Boundary' ? 100 : (type === 'Process' ? 60 : 40);
                const element = { id, type, name: type + '_' + elements.length, x, y, width, height, technology: '', data_flow: '', trust_boundary: '' };
                elements.push(element);
                addElementToCanvas(element);
                sendDataToStreamlit();
            }
        });

        function addElementToCanvas(element) {
            const div = document.createElement('div');
            div.id = element.id;
            div.className = 'element ' + element.type.toLowerCase().replace(' ', '-');
            div.style.left = element.x + 'px';
            div.style.top = element.y + 'px';
            div.style.width = element.width + 'px';
            div.style.height = element.height + 'px';
            div.innerText = element.name;
            div.draggable = true;
            div.addEventListener('dragstart', (e) => {
                e.dataTransfer.setData('id', element.id);
            });
            div.addEventListener('click', () => selectElement(element.id));
            canvas.appendChild(div);
        }

        canvas.addEventListener('dragover', (e) => e.preventDefault());
        canvas.addEventListener('drop', (e) => {
            e.preventDefault();
            const id = e.dataTransfer.getData('id');
            const element = elements.find(el => el.id === id);
            if (element) {
                element.x = e.offsetX - element.width / 2;
                element.y = e.offsetY - element.height / 2;
                document.getElementById(id).style.left = element.x + 'px';
                document.getElementById(id).style.top = element.y + 'px';
                updateArrows();
                sendDataToStreamlit();
            }
        });

        function selectElement(id) {
            if (selectedElement) {
                document.getElementById(selectedElement).classList.remove('selected');
            }
            selectedElement = id;
            document.getElementById(id).classList.add('selected');
            window.Streamlit.setComponentValue({ selected: id });
        }

        function startDrawingArrow() {
            drawingArrow = true;
            canvas.addEventListener('click', handleArrowClick);
        }

        function handleArrowClick(e) {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const element = elements.find(el => 
                x >= el.x && x <= el.x + el.width && 
                y >= el.y && y <= el.y + el.height && 
                el.type !== 'Trust Boundary' && el.type !== 'Data Flow'
            );
            if (element) {
                if (!arrowStart) {
                    arrowStart = element;
                } else if (element !== arrowStart) {
                    const arrow = {
                        id: 'arrow_' + Date.now(),
                        source: arrowStart.name,
                        target: element.name,
                        type: 'Data Flow',
                        name: 'Data Flow_' + arrows.length,
                        data_flow: 'Data Flow'
                    };
                    arrows.push(arrow);
                    drawArrow(arrow);
                    arrowStart = null;
                    drawingArrow = false;
                    canvas.removeEventListener('click', handleArrowClick);
                    sendDataToStreamlit();
                }
            }
        }

        function drawArrow(arrow) {
            const source = elements.find(el => el.name === arrow.source);
            const target = elements.find(el => el.name === arrow.target);
            if (source && target) {
                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('id', arrow.id);
                line.setAttribute('x1', source.x + source.width / 2);
                line.setAttribute('y1', source.y + source.height / 2);
                line.setAttribute('x2', target.x + target.width / 2);
                line.setAttribute('y2', target.y + target.height / 2);
                line.setAttribute('stroke', 'black');
                line.setAttribute('stroke-width', '2');
                line.setAttribute('marker-end', 'url(#arrowhead)');
                arrowsSvg.appendChild(line);
            }
        }

        function updateArrows() {
            arrowsSvg.innerHTML = '<defs><marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" /></marker></defs>';
            arrows.forEach(drawArrow);
        }

        function clearCanvas() {
            elements = [];
            arrows = [];
            canvas.innerHTML = '';
            arrowsSvg.innerHTML = '<defs><marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" /></marker></defs>';
            sendDataToStreamlit();
        }

        function sendDataToStreamlit() {
            const dfd_elements = elements.concat(arrows);
            window.Streamlit.setComponentValue({ elements: dfd_elements });
        }

        // Load template elements
        function loadElements(dfd_elements) {
            elements = dfd_elements.filter(el => el.type !== 'Data Flow');
            arrows = dfd_elements.filter(el => el.type === 'Data Flow');
            canvas.innerHTML = '';
            arrowsSvg.innerHTML = '<defs><marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto"><polygon points="0 0, 10 3.5, 0 7" /></marker></defs>';
            elements.forEach(addElementToCanvas);
            arrows.forEach(drawArrow);
            sendDataToStreamlit();
        }
    </script>
</body>
</html>
""" % st.session_state.theme

# Streamlit app
st.set_page_config(page_title="Threat Modeling Platform", layout="wide")
st.title("Threat Modeling Education Platform")
st.markdown("""
This enterprise-grade platform uses the STRIDE methodology to help users create and analyze threat models. Use the drag-and-drop editor to create Data Flow Diagrams (DFDs) and generate comprehensive threat reports with compliance mappings and visualizations.
""")

# Theme toggle
st.sidebar.header("Settings")
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"], index=0 if st.session_state.theme == "light" else 1)
if theme.lower() != st.session_state.theme:
    st.session_state.theme = theme.lower()
    st.experimental_rerun()

# Apply theme
if st.session_state.theme == "dark":
    st.markdown("""
        <style>
        body { background-color: #1a1a1a; color: #ffffff; }
        .stApp { background-color: #1a1a1a; }
        .stTextInput > div > input { background-color: #2a2a2a; color: #ffffff; }
        .stSelectbox > div > select { background-color: #2a2a2a; color: #ffffff; }
        </style>
    """, unsafe_allow_html=True)

# Authentication
if not st.session_state.authenticated:
    st.header("Login")
    username = st.text_input("Username", help="Enter your username (e.g., 'student' or 'admin')")
    password = st.text_input("Password", type="password", help="Enter your password")
    if st.button("Login"):
        conn = sqlite3.connect("threat_models.db")
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username = ? AND password = ?", (username, password))
        result = c.fetchone()
        conn.close()
        if result:
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.role = result[0]
            logger.info(f"User logged in: {username} (Role: {result[0]})")
        else:
            st.error("Invalid username or password.")
            logger.warning(f"Login attempt failed for username: {username}")
            st.session_state.authenticated = False

# Main app logic
if st.session_state.authenticated:
    st.sidebar.title("Navigation")
    options = ["View Pre-defined Threat Models", "Create Custom Threat Model with DFD", "View Saved Models", "Logout"]
    if st.session_state.role == "admin":
        options.append("Manage Users")
    option = st.sidebar.radio("Choose an option:", options)

    if option == "Logout":
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.dfd_elements = []
        st.session_state.dfd_image = None
        st.experimental_rerun()
        logger.info("User logged out")

    elif option == "View Pre-defined Threat Models":
        st.header("Pre-defined Threat Models")
        st.markdown("Explore example threat models for common enterprise applications.")
        for model in pre_defined_threat_models:
            with st.expander(model["name"]):
                st.write(f"**Architecture**: {model['architecture']}")
                st.write("**Threats**:")
                df = pd.DataFrame(model["threats"])
                st.dataframe(df)
                st.plotly_chart(create_risk_chart(model["threats"]))
                st.markdown(create_json_report(model["name"], model["architecture"], [], model["threats"]), unsafe_allow_html=True)
                st.markdown(create_csv_report(model["name"], model["threats"]), unsafe_allow_html=True)
                st.markdown(create_pdf_report(model["name"], model["architecture"], [], model["threats"]), unsafe_allow_html=True)
                st.write("---")

    elif option == "Create Custom Threat Model with DFD":
        st.header("Create Custom Threat Model with Data Flow Diagram")
        st.markdown("""
        Use the drag-and-drop editor to create a Data Flow Diagram (DFD). Drag Processes (circles), Data Stores (rectangles), External Entities (rectangles), or Trust Boundaries (dashed rectangles) from the toolbar. Click 'Data Flow' to draw arrows between components. Annotate elements to generate a threat model.
        """)

        # Template selection
        st.subheader("Select DFD Template (Optional)")
        template = st.selectbox("Choose a template", ["None"] + list(dfd_templates.keys()), help="Select a template to pre-populate DFD elements")
        if template != "None" and st.button("Load Template"):
            st.session_state.dfd_elements = dfd_templates[template]
            st.success(f"Loaded {template} template!")
            logger.info(f"Loaded template: {template}")

        # Drag-and-Drop DFD Editor
        st.subheader("Drag-and-Drop DFD Editor")
        dfd_data = components.html(dfd_editor_html, height=450, scrolling=True)
        if dfd_data and "elements" in dfd_data:
            st.session_state.dfd_elements = dfd_data["elements"]
            # Capture canvas as image (simulated via screenshot of elements)
            img = PILImage.new("RGB", (800, 400), color="white" if st.session_state.theme == "light" else "#2a2a2a")
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format="PNG")
            st.session_state.dfd_image = img_byte_arr.getvalue()

        # Form to annotate DFD elements
        st.subheader("Annotate DFD Elements")
        if st.session_state.dfd_elements:
            selected_id = dfd_data.get("selected", None) if dfd_data else None
            if selected_id:
                selected_element = next((e for e in st.session_state.dfd_elements if e["id"] == selected_id), None)
                if selected_element:
                    with st.form("dfd_elements_form"):
                        st.markdown(f"Editing: {selected_element['name']} ({selected_element['type']})")
                        element_type = selected_element["type"]
                        element_name = st.text_input("Element Name", value=selected_element["name"], placeholder="e.g., Web Server", help="Enter a unique name for the element")
                        technology = st.text_input("Technology (optional)", value=selected_element.get("technology", ""), placeholder="e.g., Node.js, MySQL", help="Specify the technology used")
                        if element_type == "Data Flow":
                            data_flow = st.text_input("Data Flow Description", value=selected_element.get("data_flow", ""), placeholder="e.g., User credentials to server", help="Describe the data flow")
                            source = st.selectbox("Source", [e["name"] for e in st.session_state.dfd_elements if e["type"] != "Data Flow" and e["type"] != "Trust Boundary"], index=[e["name"] for e in st.session_state.dfd_elements if e["type"] != "Data Flow" and e["type"] != "Trust Boundary"].index(selected_element["source"]))
                            target = st.selectbox("Target", [e["name"] for e in st.session_state.dfd_elements if e["type"] in ["Process", "Data Store"]], index=[e["name"] for e in st.session_state.dfd_elements if e["type"] in ["Process", "Data Store"]].index(selected_element["target"]))
                        else:
                            data_flow = selected_element.get("data_flow", "")
                            source = selected_element.get("source", "")
                            target = selected_element.get("target", "")
                        if element_type == "Trust Boundary":
                            trust_boundary = st.text_input("Trust Boundary Description", value=selected_element.get("trust_boundary", ""), placeholder="e.g., Public Internet vs. Internal Network", help="Describe the trust boundary")
                        else:
                            trust_boundary = selected_element.get("trust_boundary", "")
                        update_element = st.form_submit_button("Update Element")

                        if update_element:
                            valid, error = validate_input(element_name, "Element Name", max_length=100)
                            if not valid:
                                st.error(error)
                                logger.warning(error)
                            else:
                                for elem in st.session_state.dfd_elements:
                                    if elem["id"] == selected_id:
                                        elem.update({
                                            "name": element_name,
                                            "technology": technology,
                                            "data_flow": data_flow,
                                            "trust_boundary": trust_boundary,
                                            "source": source,
                                            "target": target
                                        })
                                logger.info(f"Updated DFD element: {element_type} - {element_name}")
                                st.success("Element updated successfully!")

        # Display current DFD elements
        if st.session_state.dfd_elements:
            st.subheader("Current DFD Elements")
            df = pd.DataFrame([
                {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                for elem in st.session_state.dfd_elements
            ])
            st.dataframe(df)

        # Generate threat model
        with st.form("threat_model_form"):
            threat_model_name = st.text_input("Threat Model Name", placeholder="e.g., My Web App", help="Enter a unique name for your threat model")
            architecture = st.text_area("System Architecture", placeholder="Describe your system (e.g., components, technologies, hosting environment).", help="Provide a detailed system description")
            submit = st.form_submit_button("Generate Threat Model")

            if submit:
                validations = [
                    validate_input(threat_model_name, "Threat Model Name"),
                    validate_input(architecture, "System Architecture"),
                ]
                if not st.session_state.dfd_elements:
                    validations.append((False, "At least one DFD element must be added."))
                dfd_valid, dfd_error = validate_dfd(st.session_state.dfd_elements)
                if not dfd_valid:
                    validations.append((False, dfd_error))

                valid = all(v[0] for v in validations)
                if not valid:
                    for is_valid, error in validations:
                        if not is_valid:
                            st.error(error)
                            logger.warning(error)
                else:
                    try:
                        threats = generate_threat_model_from_dfd(st.session_state.dfd_elements, architecture)
                        st.subheader(f"Threat Model: {threat_model_name}")
                        st.write(f"**Architecture**: {architecture}")
                        st.write("**DFD**:")
                        if st.session_state.dfd_image:
                            st.image(st.session_state.dfd_image)
                        st.write("**DFD Elements**:")
                        df = pd.DataFrame([
                            {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                            for elem in st.session_state.dfd_elements
                        ])
                        st.dataframe(df)
                        st.write("**Generated Threats**:")
                        df = pd.DataFrame(threats)
                        st.dataframe(df)
                        st.write("**Risk Distribution**:")
                        st.plotly_chart(create_risk_chart(threats))
                        st.markdown(create_json_report(threat_model_name, architecture, st.session_state.dfd_elements, threats), unsafe_allow_html=True)
                        st.markdown(create_csv_report(threat_model_name, threats), unsafe_allow_html=True)
                        st.markdown(create_pdf_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, st.session_state.dfd_image), unsafe_allow_html=True)

                        # Save to database
                        conn = sqlite3.connect("threat_models.db")
                        c = conn.cursor()
                        c.execute("""
                            INSERT INTO threat_models (name, architecture, dfd_elements, threats, username, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            threat_model_name,
                            architecture,
                            json.dumps(st.session_state.dfd_elements),
                            json.dumps(threats),
                            st.session_state.username,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ))
                        conn.commit()
                        conn.close()
                        logger.info(f"Saved threat model: {threat_model_name}")
                        st.success("Threat model saved successfully!")
                    except Exception as e:
                        st.error(f"An error occurred: {str(e)}")
                        logger.error(f"Threat model generation failed: {str(e)}")

    elif option == "View Saved Models":
        st.header("Saved Threat Models")
        conn = sqlite3.connect("threat_models.db")
        c = conn.cursor()
        if st.session_state.role == "admin":
            c.execute("SELECT id, name, architecture, dfd_elements, threats, username, created_at FROM threat_models")
        else:
            c.execute("SELECT id, name, architecture, dfd_elements, threats, username, created_at FROM threat_models WHERE username = ?", (st.session_state.username,))
        models = c.fetchall()
        conn.close()

        if models:
            for model in models:
                model_id, name, architecture, dfd_elements, threats, username, created_at = model
                with st.expander(f"{name} (Created by {username} on {created_at})"):
                    st.write(f"**Architecture**: {architecture}")
                    dfd_elements = json.loads(dfd_elements)
                    threats = json.loads(threats)
                    st.write("**DFD Elements**:")
                    df = pd.DataFrame([
                        {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                        for elem in dfd_elements
                    ])
                    st.dataframe(df)
                    st.write("**Threats**:")
                    df = pd.DataFrame(threats)
                    st.dataframe(df)
                    st.plotly_chart(create_risk_chart(threats))
                    st.markdown(create_json_report(name, architecture, dfd_elements, threats), unsafe_allow_html=True)
                    st.markdown(create_csv_report(name, threats), unsafe_allow_html=True)
                    st.markdown(create_pdf_report(name, architecture, dfd_elements, threats), unsafe_allow_html=True)
                    if st.session_state.role == "admin" or username == st.session_state.username:
                        if st.button(f"Delete {name}", key=f"delete_{model_id}"):
                            conn = sqlite3.connect("threat_models.db")
                            c = conn.cursor()
                            c.execute("DELETE FROM threat_models WHERE id = ?", (model_id,))
                            conn.commit()
                            conn.close()
                            logger.info(f"Deleted threat model: {name}")
                            st.experimental_rerun()
        else:
            st.info("No saved threat models found.")

    elif option == "Manage Users" and st.session_state.role == "admin":
        st.header("Manage Users")
        st.markdown("Admin can add or delete users.")
        with st.form("user_management_form"):
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            new_role = st.selectbox("Role", ["user", "admin"])
            add_user = st.form_submit_button("Add User")

            if add_user:
                valid, error = validate_input(new_username, "Username", max_length=50)
                if not valid:
                    st.error(error)
                    logger.warning(error)
                else:
                    conn = sqlite3.connect("threat_models.db")
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, new_password, new_role))
                    conn.commit()
                    conn.close()
                    logger.info(f"Added user: {new_username} (Role: {new_role})")
                    st.success(f"User {new_username} added successfully!")

        # Display and delete users
        conn = sqlite3.connect("threat_models.db")
        c = conn.cursor()
        c.execute("SELECT username, role FROM users")
        users = c.fetchall()
        conn.close()
        st.subheader("Current Users")
        for user in users:
            username, role = user
            st.write(f"Username: {username}, Role: {role}")
            if username != st.session_state.username:
                if st.button(f"Delete {username}", key=f"delete_user_{username}"):
                    conn = sqlite3.connect("threat_models.db")
                    c = conn.cursor()
                    c.execute("DELETE FROM users WHERE username = ?", (username,))
                    conn.commit()
                    conn.close()
                    logger.info(f"Deleted user: {username}")
                    st.experimental_rerun()

# Footer
st.markdown("""
---
**About**: This enterprise-grade threat modeling platform uses the STRIDE methodology to educate users on identifying threats, vulnerabilities, risks, and mitigations. Use the drag-and-drop DFD editor to create precise Data Flow Diagrams and generate custom threat models with compliance mappings and visualizations. For more details, refer to the [OWASP Threat Modeling Guide](https://owasp.org/www-community/Threat_Modeling).
""")
