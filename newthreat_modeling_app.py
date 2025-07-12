
#### 2. Optimized Main Python Script
The main script (`threat_modeling_app.py`) is streamlined with caching, reduced reruns, and modularized logic.

<xaiArtifact artifact_id="22760601-32ca-4d99-af0c-b3e39aa4fed2" artifact_version_id="6b66df7b-c65d-417b-b8e2-ae283a0078dc" title="threat_modeling_app.py" contentType="text/python">
```python
import streamlit as st
import pandas as pd
import json
import base64
import logging
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from PIL import Image as PILImage
import io
import sqlite3
import plotly.express as px
import csv
import streamlit.components.v1 as components
import os

# Configure logging
logging.basicConfig(
    filename="threat_modeling_app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.dfd_elements = []
    st.session_state.dfd_image = None
    st.session_state.theme = "light"

# Cache database initialization
@st.cache_resource
def init_db():
    conn = sqlite3.connect("threat_models.db", check_same_thread=False)
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
    return conn

# Cache STRIDE library and templates
@st.cache_data
def load_static_data():
    stride_library = {
        "Spoofing": [
            {"threat": "Unauthorized user impersonation", "vulnerability": "Weak passwords or no MFA", "risk": "High", "mitigation": "Enforce strong passwords, MFA", "compliance": "NIST 800-63B"},
            {"threat": "Session hijacking", "vulnerability": "Insecure session management", "risk": "High", "mitigation": "Secure cookies, short timeouts", "compliance": "OWASP ASVS 3.4"}
        ],
        "Tampering": [
            {"threat": "Data modification in transit", "vulnerability": "No encryption", "risk": "High", "mitigation": "Use TLS, integrity checks", "compliance": "NIST 800-53 SC-8"},
            {"threat": "Injection attacks", "vulnerability": "Improper input validation", "risk": "Critical", "mitigation": "Parameterized queries, sanitization", "compliance": "OWASP Top 10 A03:2021"}
        ],
        "Repudiation": [
            {"threat": "Denial of actions", "vulnerability": "No audit logging", "risk": "Medium", "mitigation": "Audit logging with signatures", "compliance": "NIST 800-53 AU-2"}
        ],
        "Information Disclosure": [
            {"threat": "Data exposure in transit", "vulnerability": "Unencrypted channels", "risk": "High", "mitigation": "Enforce TLS 1.3", "compliance": "GDPR Article 32"},
            {"threat": "Data access at rest", "vulnerability": "Unencrypted storage", "risk": "High", "mitigation": "AES-256 encryption", "compliance": "NIST 800-53 SC-28"}
        ],
        "Denial of Service": [
            {"threat": "Resource exhaustion", "vulnerability": "No rate limiting", "risk": "Medium", "mitigation": "API rate limiting", "compliance": "NIST 800-53 SC-5"},
            {"threat": "DDoS attack", "vulnerability": "No DDoS protection", "risk": "High", "mitigation": "Use Cloudflare, auto-scaling", "compliance": "ISO 27001 A.12.1.3"}
        ],
        "Elevation of Privilege": [
            {"threat": "Privilege escalation", "vulnerability": "Insecure RBAC", "risk": "Critical", "mitigation": "Least privilege, access reviews", "compliance": "NIST 800-53 AC-6"}
        ]
    }
    pre_defined_threat_models = [
        {
            "name": "Online Banking",
            "architecture": "Web app with React, Node.js, MySQL on AWS",
            "threats": [
                stride_library["Spoofing"][0],
                stride_library["Tampering"][0],
                stride_library["Information Disclosure"][0],
                stride_library["Denial of Service"][1],
                stride_library["Elevation of Privilege"][0]
            ]
        },
        {
            "name": "E-Commerce",
            "architecture": "Microservices with Angular, Spring Boot, MongoDB on Azure",
            "threats": [
                stride_library["Tampering"][1],
                stride_library["Repudiation"][0],
                stride_library["Information Disclosure"][1],
                stride_library["Denial of Service"][0],
                stride_library["Elevation of Privilege"][0]
            ]
        }
    ]
    dfd_templates = {
        "Web Application": [
            {"type": "External Entity", "name": "User", "technology": "Browser", "x": 50, "y": 50},
            {"type": "Process", "name": "Web Server", "technology": "Node.js", "x": 200, "y": 150},
            {"type": "Data Store", "name": "Database", "technology": "MySQL", "x": 350, "y": 150},
            {"type": "Data Flow", "name": "User Request", "data_flow": "HTTP request", "source": "User", "target": "Web Server"},
            {"type": "Data Flow", "name": "DB Query", "data_flow": "SQL query", "source": "Web Server", "target": "Database"},
            {"type": "Trust Boundary", "name": "Network Boundary", "trust_boundary": "Public vs. Internal", "x": 150, "y": 100, "width": 300, "height": 200}
        ]
    }
    return stride_library, pre_defined_threat_models, dfd_templates

# Cache report generation
@st.cache_data
def create_json_report(threat_model_name, architecture, dfd_elements, threats):
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
    return f'<a href="data:application/json;base64,{b64}" download="{threat_model_name}_report.json">Download JSON Report</a>'

@st.cache_data
def create_csv_report(threat_model_name, threats):
    filename = f"{threat_model_name}_report.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"])
        for threat in threats:
            writer.writerow([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]])
    with open(filename, "rb") as f:
        csv_data = f.read()
    b64 = base64.b64encode(csv_data).decode()
    return f'<a href="data:application/csv;base64,{b64}" download="{filename}">Download CSV Report</a>'

@st.cache_data
def create_pdf_report(threat_model_name, architecture, dfd_elements, threats, dfd_image_path=None):
    filename = f"{threat_model_name}_report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Threat Model Report: {threat_model_name}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
        Paragraph(f"Generated by: {st.session_state.username or 'Anonymous'}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(f"This threat model identifies {len(threats)} threats using STRIDE.", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("System Architecture", styles["Heading2"]),
        Paragraph(architecture, styles["Normal"]),
        Spacer(1, 12),
        Paragraph("DFD Elements", styles["Heading2"]),
        Table([["Type", "Name", "Technology", "Data Flow", "Trust Boundary", "X", "Y"]] + [
            [elem["type"], elem.get("name", ""), elem.get("technology", ""), elem.get("data_flow", ""), elem.get("trust_boundary", ""), elem.get("x", ""), elem.get("y", "")] 
            for elem in dfd_elements
        ], style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]),
        Spacer(1, 12),
        Paragraph("Threats Identified", styles["Heading2"]),
        Table([["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"]] + [
            [threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]]
            for threat in threats
        ], style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ])
    ]
    doc.build(story)
    with open(filename, "rb") as f:
        pdf_data = f.read()
    b64 = base64.b64encode(pdf_data).decode()
    return f'<a href="data:application/pdf;base64,{b64}" download="{filename}">Download PDF Report</a>'

# Cache risk chart
@st.cache_data
def create_risk_chart(threats):
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for threat in threats:
        risk_counts[threat["risk"]] += 1
    df = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
    return px.bar(df, x="Risk Level", y="Count", title="Risk Distribution", color="Risk Level")

# Validation functions
def validate_input(value, field_name, max_length=500):
    if not value or len(value.strip()) == 0:
        logger.error(f"Validation failed: {field_name} is empty")
        return False, f"{field_name} cannot be empty."
    if len(value) > max_length:
        logger.error(f"Validation failed: {field_name} exceeds {max_length} characters")
        return False, f"{field_name} exceeds {max_length} characters."
    return True, ""

def validate_dfd(dfd_elements):
    processes = [e for e in dfd_elements if e["type"] == "Process"]
    data_stores = [e for e in dfd_elements if e["type"] == "Data Store"]
    data_flows = [e for e in dfd_elements if e["type"] == "Data Flow"]
    if not processes:
        return False, "At least one Process is required."
    for flow in data_flows:
        source_exists = any(e["name"] == flow["source"] for e in processes + data_stores + [e for e in dfd_elements if e["type"] == "External Entity"])
        target_exists = any(e["name"] == flow["target"] for e in processes + data_stores)
        if not (source_exists and target_exists):
            return False, f"Data Flow '{flow['name']}' must connect valid components."
    return True, ""

# Threat generation
def suggest_threats(architecture, dfd_elements, stride_library):
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

def generate_threat_model_from_dfd(dfd_elements, architecture, stride_library):
    threats = []
    component_types = [elem["type"] for elem in dfd_elements]
    data_flows = [elem for elem in dfd_elements if elem["type"] == "Data Flow"]
    trust_boundaries = [elem for elem in dfd_elements if elem["type"] == "Trust Boundary"]
    if "Process" in component_types:
        threats.extend([stride_library["Spoofing"][0], stride_library["Tampering"][1], stride_library["Elevation of Privilege"][0]])
    if "Data Store" in component_types:
        threats.extend([stride_library["Information Disclosure"][1], stride_library["Tampering"][0]])
    if "External Entity" in component_types:
        threats.append(stride_library["Spoofing"][1])
    if data_flows:
        threats.append(stride_library["Information Disclosure"][0])
    if trust_boundaries:
        threats.append(stride_library["Elevation of Privilege"][0])
    threats.extend(suggest_threats(architecture, dfd_elements, stride_library))
    seen = set()
    unique_threats = [t for t in threats if not (t["threat"] in seen or seen.add(t["threat"]))]
    logger.info(f"Generated {len(unique_threats)} threats")
    return unique_threats

# Load static data
stride_library, pre_defined_threat_models, dfd_templates = load_static_data()
conn = init_db()

# Streamlit app
st.set_page_config(page_title="Threat Modeling Platform", layout="wide")
st.title("Threat Modeling Education Platform")
st.markdown("Use the drag-and-drop DFD editor to create threat models with STRIDE.")

# Theme toggle
st.sidebar.header("Settings")
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"], index=0 if st.session_state.theme == "light" else 1)
if theme.lower() != st.session_state.theme:
    st.session_state.theme = theme.lower()

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
    with st.form("login_form"):
        username = st.text_input("Username", help="e.g., 'student' or 'admin'")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE username = ? AND password = ?", (username, password))
            result = c.fetchone()
            if result:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = result[0]
                logger.info(f"User logged in: {username} (Role: {result[0]})")
                st.rerun()
            else:
                st.error("Invalid credentials.")
                logger.warning(f"Login failed: {username}")

# Main app logic
if st.session_state.authenticated:
    st.sidebar.title("Navigation")
    options = ["View Pre-defined Models", "Create Custom Model", "View Saved Models", "Logout"]
    if st.session_state.role == "admin":
        options.append("Manage Users")
    option = st.sidebar.radio("Choose an option:", options)

    if option == "Logout":
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.session_state.dfd_elements = []
        st.session_state.dfd_image = None
        logger.info("User logged out")
        st.rerun()

    elif option == "View Pre-defined Models":
        st.header("Pre-defined Threat Models")
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

    elif option == "Create Custom Model":
        st.header("Create Custom Threat Model")
        st.markdown("Drag Processes, Data Stores, External Entities, or Trust Boundaries. Click 'Data Flow' to draw arrows.")

        # Template selection
        st.subheader("Select DFD Template")
        template = st.selectbox("Choose a template", ["None"] + list(dfd_templates.keys()))
        if template != "None" and st.button("Load Template"):
            st.session_state.dfd_elements = dfd_templates[template]
            logger.info(f"Loaded template: {template}")

        # Load DFD editor
        with open("dfd_editor.html", "r") as f:
            html_content = f.read().replace("{{THEME}}", st.session_state.theme)
        dfd_data = components.html(html_content, height=450, scrolling=True)
        if dfd_data and "elements" in dfd_data:
            st.session_state.dfd_elements = dfd_data["elements"]
            img = PILImage.new("RGB", (800, 400), color="white" if st.session_state.theme == "light" else "#2a2a2a")
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format="PNG")
            st.session_state.dfd_image = img_byte_arr.getvalue()

        # Annotate DFD elements
        st.subheader("Annotate DFD Elements")
        if st.session_state.dfd_elements and dfd_data and "selected" in dfd_data:
            selected_id = dfd_data["selected"]
            selected_element = next((e for e in st.session_state.dfd_elements if e["id"] == selected_id), None)
            if selected_element:
                with st.form("dfd_elements_form"):
                    st.markdown(f"Editing: {selected_element['name']} ({selected_element['type']})")
                    element_type = selected_element["type"]
                    element_name = st.text_input("Name", value=selected_element["name"], placeholder="e.g., Web Server")
                    technology = st.text_input("Technology", value=selected_element.get("technology", ""), placeholder="e.g., Node.js")
                    data_flow = st.text_input("Data Flow Description", value=selected_element.get("data_flow", ""), placeholder="e.g., HTTP request") if element_type == "Data Flow" else ""
                    source = st.selectbox("Source", [e["name"] for e in st.session_state.dfd_elements if e["type"] != "Data Flow" and e["type"] != "Trust Boundary"], index=[e["name"] for e in st.session_state.dfd_elements if e["type"] != "Data Flow" and e["type"] != "Trust Boundary"].index(selected_element["source"]) if element_type == "Data Flow" else 0) if element_type == "Data Flow" else ""
                    target = st.selectbox("Target", [e["name"] for e in st.session_state.dfd_elements if e["type"] in ["Process", "Data Store"]], index=[e["name"] for e in st.session_state.dfd_elements if e["type"] in ["Process", "Data Store"]].index(selected_element["target"]) if element_type == "Data Flow" else 0) if element_type == "Data Flow" else ""
                    trust_boundary = st.text_input("Trust Boundary Description", value=selected_element.get("trust_boundary", ""), placeholder="e.g., Public vs. Internal") if element_type == "Trust Boundary" else ""
                    if st.form_submit_button("Update Element"):
                        valid, error = validate_input(element_name, "Element Name", 100)
                        if not valid:
                            st.error(error)
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
                            logger.info(f"Updated element: {element_type} - {element_name}")
                            st.success("Element updated!")

        # Display DFD elements
        if st.session_state.dfd_elements:
            st.subheader("Current DFD Elements")
            df = pd.DataFrame([
                {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                for elem in st.session_state.dfd_elements
            ])
            st.dataframe(df)

        # Generate threat model
        with st.form("threat_model_form"):
            threat_model_name = st.text_input("Threat Model Name", placeholder="e.g., My Web App")
            architecture = st.text_area("Architecture", placeholder="Describe your system")
            if st.form_submit_button("Generate Threat Model"):
                validations = [
                    validate_input(threat_model_name, "Threat Model Name"),
                    validate_input(architecture, "Architecture"),
                    validate_dfd(st.session_state.dfd_elements) if st.session_state.dfd_elements else (False, "Add at least one DFD element.")
                ]
                if all(v[0] for v in validations):
                    threats = generate_threat_model_from_dfd(st.session_state.dfd_elements, architecture, stride_library)
                    st.subheader(f"Threat Model: {threat_model_name}")
                    st.write(f"**Architecture**: {architecture}")
                    if st.session_state.dfd_image:
                        st.image(st.session_state.dfd_image)
                    st.write("**DFD Elements**:")
                    st.dataframe(pd.DataFrame([
                        {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                        for elem in st.session_state.dfd_elements
                    ]))
                    st.write("**Threats**:")
                    df = pd.DataFrame(threats)
                    st.dataframe(df)
                    st.plotly_chart(create_risk_chart(threats))
                    st.markdown(create_json_report(threat_model_name, architecture, st.session_state.dfd_elements, threats), unsafe_allow_html=True)
                    st.markdown(create_csv_report(threat_model_name, threats), unsafe_allow_html=True)
                    st.markdown(create_pdf_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, st.session_state.dfd_image), unsafe_allow_html=True)

                    c = conn.cursor()
                    c.execute("INSERT INTO threat_models (name, architecture, dfd_elements, threats, username, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                              (threat_model_name, architecture, json.dumps(st.session_state.dfd_elements), json.dumps(threats), st.session_state.username, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit()
                    logger.info(f"Saved threat model: {threat_model_name}")
                    st.success("Threat model saved!")
                else:
                    for is_valid, error in validations:
                        if not is_valid:
                            st.error(error)

    elif option == "View Saved Models":
        st.header("Saved Threat Models")
        c = conn.cursor()
        c.execute("SELECT id, name, architecture, dfd_elements, threats, username, created_at FROM threat_models WHERE username = ? OR ? = 'admin'",
                 (st.session_state.username, st.session_state.role))
        models = c.fetchall()
        if models:
            for model_id, name, architecture, dfd_elements, threats, username, created_at in models:
                with st.expander(f"{name} (Created by {username} on {created_at})"):
                    st.write(f"**Architecture**: {architecture}")
                    dfd_elements = json.loads(dfd_elements)
                    threats = json.loads(threats)
                    st.write("**DFD Elements**:")
                    st.dataframe(pd.DataFrame([
                        {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow", "trust_boundary", "source", "target", "x", "y"]}
                        for elem in dfd_elements
                    ]))
                    st.write("**Threats**:")
                    st.dataframe(pd.DataFrame(threats))
                    st.plotly_chart(create_risk_chart(threats))
                    st.markdown(create_json_report(name, architecture, dfd_elements, threats), unsafe_allow_html=True)
                    st.markdown(create_csv_report(name, threats), unsafe_allow_html=True)
                    st.markdown(create_pdf_report(name, architecture, dfd_elements, threats), unsafe_allow_html=True)
                    if st.session_state.role == "admin" or username == st.session_state.username:
                        if st.button(f"Delete {name}", key=f"delete_{model_id}"):
                            c.execute("DELETE FROM threat_models WHERE id = ?", (model_id,))
                            conn.commit()
                            logger.info(f"Deleted threat model: {name}")
                            st.rerun()
        else:
            st.info("No saved models.")

    elif option == "Manage Users" and st.session_state.role == "admin":
        st.header("Manage Users")
        with st.form("user_management_form"):
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            new_role = st.selectbox("Role", ["user", "admin"])
            if st.form_submit_button("Add User"):
                valid, error = validate_input(new_username, "Username", 50)
                if not valid:
                    st.error(error)
                else:
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, new_password, new_role))
                    conn.commit()
                    logger.info(f"Added user: {new_username}")
                    st.success(f"User {new_username} added!")

        st.subheader("Current Users")
        c = conn.cursor()
        c.execute("SELECT username, role FROM users")
        users = c.fetchall()
        for username, role in users:
            st.write(f"Username: {username}, Role: {role}")
            if username != st.session_state.username:
                if st.button(f"Delete {username}", key=f"delete_user_{username}"):
                    c.execute("DELETE FROM users WHERE username = ?", (username,))
                    conn.commit()
                    logger.info(f"Deleted user: {username}")
                    st.rerun()

# Clean up temporary files
for file in os.listdir():
    if file.endswith("_report.csv") or file.endswith("_report.pdf"):
        os.remove(file)

# Footer
st.markdown("**About**: Use the STRIDE-based drag-and-drop DFD editor to create threat models. See [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling).")
```
