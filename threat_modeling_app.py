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
logging.basicConfig(filename="threat_modeling_app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize session state
if "role" not in st.session_state:
    st.session_state.role = "admin"  # Default to admin for full access
    st.session_state.dfd_elements = []
    st.session_state.dfd_image = None
    st.session_state.theme = "light"
    st.session_state.last_update = 0

# Cache SQLite connection
@st.cache_resource
def init_db():
    conn = sqlite3.connect("threat_models.db", check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS threat_models (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, architecture TEXT, dfd_elements TEXT, threats TEXT, created_at TEXT)")
    conn.commit()
    return conn

# Cache static data
@st.cache_data
def load_static_data():
    stride_library = {
        "Spoofing": [
            {"threat": "Unauthorized impersonation", "vulnerability": "Weak passwords", "risk": "High", "mitigation": "MFA, strong passwords", "compliance": "NIST 800-63B"}
        ],
        "Tampering": [
            {"threat": "Data modification", "vulnerability": "No encryption", "risk": "High", "mitigation": "TLS, integrity checks", "compliance": "NIST 800-53 SC-8"}
        ],
        "Information Disclosure": [
            {"threat": "Data exposure", "vulnerability": "Unencrypted channels", "risk": "High", "mitigation": "TLS 1.3", "compliance": "GDPR Article 32"}
        ],
        "Denial of Service": [
            {"threat": "DDoS attack", "vulnerability": "No DDoS protection", "risk": "High", "mitigation": "Cloudflare, auto-scaling", "compliance": "ISO 27001 A.12.1.3"}
        ],
        "Elevation of Privilege": [
            {"threat": "Privilege escalation", "vulnerability": "Insecure RBAC", "risk": "Critical", "mitigation": "Least privilege", "compliance": "NIST 800-53 AC-6"}
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
            {"type": "Data Flow", "name": "User Request", "data_flow": "HTTP request", "source": "User", "target": "Web Server"}
        ]
    }
    return stride_library, pre_defined_threat_models, dfd_templates

# Cache report generation
@st.cache_data
def create_json_report(threat_model_name, architecture, dfd_elements, threats, _timestamp):
    report = {
        "threat_model_name": threat_model_name,
        "architecture": architecture,
        "dfd_elements": dfd_elements,
        "threats": threats,
        "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "generated_by": "Anonymous"  # No username since login is removed
    }
    report_json = json.dumps(report, indent=2)
    b64 = base64.b64encode(report_json.encode()).decode()
    return f'<a href="data:application/json;base64,{b64}" download="{threat_model_name}_report.json">Download JSON Report</a>'

@st.cache_data
def create_csv_report(threat_model_name, threats, _timestamp):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"])
    for threat in threats:
        writer.writerow([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]])
    csv_data = output.getvalue().encode()
    b64 = base64.b64encode(csv_data).decode()
    return f'<a href="data:application/csv;base64,{b64}" download="{threat_model_name}_report.csv">Download CSV Report</a>'

@st.cache_data
def create_pdf_report(threat_model_name, architecture, dfd_elements, threats, _timestamp):
    filename = f"temp_{threat_model_name}_report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Threat Model: {threat_model_name}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Architecture: {architecture}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Threats", styles["Heading2"]),
        Table([["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance"]] + [
            [threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"]]
            for threat in threats
        ], style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black)
        ])
    ]
    doc.build(story)
    with open(filename, "rb") as f:
        pdf_data = f.read()
    b64 = base64.b64encode(pdf_data).decode()
    os.remove(filename)
    return f'<a href="data:application/pdf;base64,{b64}" download="{threat_model_name}_report.pdf">Download PDF Report</a>'

@st.cache_data
def create_risk_chart(threats, _timestamp):
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for threat in threats:
        risk_counts[threat["risk"]] += 1
    df = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
    return px.bar(df, x="Risk Level", y="Count", title="Risk Distribution", color="Risk Level")

# Validation and threat generation
def validate_input(value, field_name, max_length=100):
    if not value or len(value.strip()) == 0:
        return False, f"{field_name} cannot be empty."
    if len(value) > max_length:
        return False, f"{field_name} exceeds {max_length} characters."
    return True, ""

def validate_dfd(dfd_elements):
    processes = [e for e in dfd_elements if e["type"] == "Process"]
    if not processes:
        return False, "At least one Process is required."
    return True, ""

def generate_threat_model(dfd_elements, architecture, stride_library):
    threats = []
    if any(e["type"] == "Process" for e in dfd_elements):
        threats.extend([stride_library["Spoofing"][0], stride_library["Elevation of Privilege"][0]])
    if any(e["type"] == "Data Store" for e in dfd_elements):
        threats.append(stride_library["Information Disclosure"][0])
    if any(e["type"] == "Data Flow" for e in dfd_elements):
        threats.append(stride_library["Tampering"][0])
    keywords = {"web": ["Spoofing"], "database": ["Information Disclosure"], "api": ["Denial of Service"]}
    architecture_lower = architecture.lower()
    for keyword, threat_types in keywords.items():
        if keyword in architecture_lower or any(keyword in e.get("technology", "").lower() for e in dfd_elements):
            for threat_type in threat_types:
                threats.extend([t for t in stride_library[threat_type] if t not in threats])
    seen = set()
    unique_threats = [t for t in threats if not (t["threat"] in seen or seen.add(t["threat"]))]
    return unique_threats

# Load static data
stride_library, pre_defined_threat_models, dfd_templates = load_static_data()
conn = init_db()

# Streamlit app
st.set_page_config(page_title="Threat Modeling", layout="wide")
st.title("Threat Modeling Platform")
st.markdown("Create STRIDE-based threat models with a drag-and-drop DFD editor.")

# Theme toggle
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"], index=0 if st.session_state.theme == "light" else 1)
if theme.lower() != st.session_state.theme:
    st.session_state.theme = theme.lower()

# Role selection (for testing user vs admin views)
st.session_state.role = st.sidebar.selectbox("Role", ["admin", "user"], index=0 if st.session_state.role == "admin" else 1)

# Apply dark theme CSS
if st.session_state.theme == "dark":
    st.markdown("""
        <style>
        .stApp { background-color: #1a1a1a; color: #ffffff; }
        .stTextInput > div > input, .stSelectbox > div > select { background-color: #2a2a2a; color: #ffffff; }
        </style>
    """, unsafe_allow_html=True)

# Main app
options = ["Pre-defined Models", "Create Model", "Saved Models", "Logout"]
if st.session_state.role == "admin":
    options.append("Manage Users")
option = st.sidebar.radio("Options", options)

if option == "Logout":
    st.session_state.clear()
    st.session_state.role = "admin"  # Reset to admin
    logger.info("User logged out")
    st.rerun()

elif option == "Pre-defined Models":
    st.header("Pre-defined Threat Models")
    for model in pre_defined_threat_models:
        with st.expander(model["name"]):
            st.write(f"**Architecture**: {model['architecture']}")
            df = pd.DataFrame(model["threats"])
            st.dataframe(df)
            st.plotly_chart(create_risk_chart(model["threats"], datetime.now().timestamp()))
            st.markdown(create_json_report(model["name"], model["architecture"], [], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            st.markdown(create_csv_report(model["name"], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            st.markdown(create_pdf_report(model["name"], model["architecture"], [], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)

elif option == "Create Model":
    st.header("Create Threat Model")
    st.markdown("Drag Processes, Data Stores, or External Entities to create a DFD.")

    # Template selection
    template = st.selectbox("Template", ["None"] + list(dfd_templates.keys()))
    if template != "None" and st.button("Load Template"):
        st.session_state.dfd_elements = dfd_templates[template]
        st.session_state.last_update = datetime.now().timestamp()
        logger.info(f"Loaded template: {template}")

    # DFD editor
    with open("dfd_editor.html", "r") as f:
        html_content = f.read().replace("{{THEME}}", st.session_state.theme)
    dfd_data = components.html(html_content, height=450)
    if dfd_data and "elements" in dfd_data:
        current_time = datetime.now().timestamp()
        if current_time - st.session_state.last_update > 1:  # Debounce updates (1-second delay)
            st.session_state.dfd_elements = dfd_data["elements"]
            st.session_state.last_update = current_time
            img = PILImage.new("RGB", (800, 400), color="white" if st.session_state.theme == "light" else "#2a2a2a")
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format="PNG")
            st.session_state.dfd_image = img_byte_arr.getvalue()

    # Annotate elements
    if st.session_state.dfd_elements and dfd_data and "selected" in dfd_data:
        selected_id = dfd_data["selected"]
        selected_element = next((e for e in st.session_state.dfd_elements if e["id"] == selected_id), None)
        if selected_element:
            with st.form("dfd_form"):
                st.markdown(f"Editing: {selected_element['name']} ({selected_element['type']})")
                element_name = st.text_input("Name", value=selected_element["name"], placeholder="e.g., Web Server")
                technology = st.text_input("Technology", value=selected_element.get("technology", ""), placeholder="e.g., Node.js")
                data_flow = st.text_input("Data Flow", value=selected_element.get("data_flow", ""), placeholder="e.g., HTTP request") if selected_element["type"] == "Data Flow" else ""
                if st.form_submit_button("Update"):
                    valid, error = validate_input(element_name, "Name")
                    if valid:
                        for elem in st.session_state.dfd_elements:
                            if elem["id"] == selected_id:
                                elem.update({"name": element_name, "technology": technology, "data_flow": data_flow})
                        logger.info(f"Updated element: {element_name}")
                        st.success("Element updated!")
                    else:
                        st.error(error)

    # Display DFD elements
    if st.session_state.dfd_elements:
        st.subheader("DFD Elements")
        st.dataframe(pd.DataFrame([
            {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
            for elem in st.session_state.dfd_elements
        ]))

    # Generate threat model
    with st.form("threat_model_form"):
        threat_model_name = st.text_input("Name", placeholder="e.g., My App")
        architecture = st.text_area("Architecture", placeholder="Describe your system")
        if st.form_submit_button("Generate"):
            validations = [
                validate_input(threat_model_name, "Name"),
                validate_input(architecture, "Architecture"),
                validate_dfd(st.session_state.dfd_elements) if st.session_state.dfd_elements else (False, "Add DFD elements.")
            ]
            if all(v[0] for v in validations):
                threats = generate_threat_model(st.session_state.dfd_elements, architecture, stride_library)
                st.subheader(f"Threat Model: {threat_model_name}")
                st.write(f"**Architecture**: {architecture}")
                if st.session_state.dfd_image:
                    st.image(st.session_state.dfd_image)
                st.write("**DFD Elements**:")
                st.dataframe(pd.DataFrame([
                    {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
                    for elem in st.session_state.dfd_elements
                ]))
                st.write("**Threats**:")
                df = pd.DataFrame(threats)
                st.dataframe(df)
                timestamp = datetime.now().timestamp()
                st.plotly_chart(create_risk_chart(threats, timestamp))
                st.markdown(create_json_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, timestamp), unsafe_allow_html=True)
                st.markdown(create_csv_report(threat_model_name, threats, timestamp), unsafe_allow_html=True)
                st.markdown(create_pdf_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, timestamp), unsafe_allow_html=True)

                c = conn.cursor()
                c.execute("INSERT INTO threat_models (name, architecture, dfd_elements, threats, created_at) VALUES (?, ?, ?, ?, ?)",
                          (threat_model_name, architecture, json.dumps(st.session_state.dfd_elements), json.dumps(threats), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                st.success("Threat model saved!")
            else:
                for _, error in validations:
                    st.error(error)

elif option == "Saved Models":
    st.header("Saved Threat Models")
    c = conn.cursor()
    c.execute("SELECT id, name, architecture, dfd_elements, threats, created_at FROM threat_models")
    models = c.fetchall()
    if models:
        for model_id, name, architecture, dfd_elements, threats, created_at in models:
            with st.expander(f"{name} ({created_at})"):
                st.write(f"**Architecture**: {architecture}")
                dfd_elements = json.loads(dfd_elements)
                threats = json.loads(threats)
                st.dataframe(pd.DataFrame([
                    {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
                    for elem in dfd_elements
                ]))
                st.dataframe(pd.DataFrame(threats))
                timestamp = datetime.now().timestamp()
                st.plotly_chart(create_risk_chart(threats, timestamp))
                st.markdown(create_json_report(name, architecture, dfd_elements, threats, timestamp), unsafe_allow_html=True)
                st.markdown(create_csv_report(name, threats, timestamp), unsafe_allow_html=True)
                st.markdown(create_pdf_report(name, architecture, dfd_elements, threats, timestamp), unsafe_allow_html=True)
                if st.session_state.role == "admin":
                    if st.button(f"Delete", key=f"delete_{model_id}"):
                        c.execute("DELETE FROM threat_models WHERE id = ?", (model_id,))
                        conn.commit()
                        logger.info(f"Deleted model: {name}")
                        st.rerun()
    else:
        st.info("No saved models.")

elif option == "Manage Users" and st.session_state.role == "admin":
    st.header("Manage Users")
    with st.form("user_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["user", "admin"])
        if st.form_submit_button("Add User"):
            valid, error = validate_input(new_username, "Username", 50)
            if valid:
                c = conn.cursor()
                c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)")
                c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", (new_username, new_password, new_role))
                conn.commit()
                st.success(f"User {new_username} added!")
                logger.info(f"Added user: {new_username}")
            else:
                st.error(error)

    c = conn.cursor()
    c.execute("SELECT username, role FROM users")
    users = c.fetchall()
    for username, role in users:
        st.write(f"Username: {username}, Role: {role}")
        if st.button(f"Delete {username}", key=f"delete_user_{username}"):
            c.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            logger.info(f"Deleted user: {username}")
            st.rerun()

# Clean up temporary files
for file in os.listdir():
    if file.startswith("temp_") and file.endswith(".pdf"):
        os.remove(file)
