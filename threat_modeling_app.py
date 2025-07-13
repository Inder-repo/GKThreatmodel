import streamlit as st
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
    st.session_state.role = "admin"
    st.session_state.dfd_elements = []
    st.session_state.dfd_image = None
    st.session_state.theme = "light"
    st.session_state.last_update = 0
    st.session_state.tutorial_step = 0
    st.session_state.quiz_answers = {}

# Apply Cloudscape-inspired CSS
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;700&display=swap');
    .stApp {
        font-family: 'Noto Sans', sans-serif;
        background-color: #f8f9fa;
        color: #0f1a44;
    }
    .stButton > button {
        background-color: #0073bb;
        color: white;
        border-radius: 4px;
        padding: 8px 16px;
        font-weight: 500;
        border: none;
        transition: background-color 0.2s ease-in-out;
        margin: 4px;
    }
    .stButton > button:hover {
        background-color: #005ea2;
    }
    .stButton > button.secondary {
        background-color: #ffffff;
        color: #0f1a44;
        border: 1px solid #0073bb;
    }
    .stButton > button.secondary:hover {
        background-color: #e9ecef;
    }
    .stTextInput > div > input, .stSelectbox > div > select, .stTextArea > div > textarea {
        border: 1px solid #d5dbdb;
        border-radius: 4px;
        padding: 8px;
        background-color: white;
        color: #0f1a44;
        transition: border-color 0.2s;
    }
    .stTextInput > div > input:focus, .stSelectbox > div > select:focus, .stTextArea > div > textarea:focus {
        border-color: #0073bb;
        box-shadow: 0 0 0 2px rgba(0, 115, 187, 0.3);
    }
    .stSidebar {
        background-color: #ffffff;
        border-right: 1px solid #d5dbdb;
        padding: 16px;
    }
    .stSidebar h2 {
        color: #0f1a44;
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 16px;
    }
    .stExpander {
        border: 1px solid #d5dbdb;
        border-radius: 4px;
        background-color: #ffffff;
        margin-bottom: 8px;
    }
    .stExpander > div > div {
        padding: 8px 16px;
    }
    h1, h2, h3 {
        color: #0f1a44;
        font-weight: 700;
        margin-top: 16px;
    }
    .aws-divider {
        border-top: 1px solid #d5dbdb;
        margin: 16px 0;
    }
    .stTable {
        border-collapse: collapse;
        width: 100%;
        background-color: #ffffff;
        border: 1px solid #d5dbdb;
        border-radius: 4px;
    }
    .stTable th, .stTable td {
        border: 1px solid #d5dbdb;
        padding: 8px;
        text-align: left;
    }
    .stTable th {
        background-color: #e9ecef;
        font-weight: 500;
        color: #0f1a44;
    }
    .aws-button {
        display: inline-block;
        padding: 8px 16px;
        background-color: #0073bb;
        color: white;
        border-radius: 4px;
        text-decoration: none;
        font-weight: 500;
        margin-right: 8px;
    }
    .aws-button:hover {
        background-color: #005ea2;
    }
    </style>
""", unsafe_allow_html=True)

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
            {"threat": "Unauthorized impersonation", "vulnerability": "Weak authentication", "risk": "High", "mitigation": "Implement MFA, strong passwords", "compliance": "NIST 800-63B", "example": "An attacker uses stolen credentials to access a banking portal."}
        ],
        "Tampering": [
            {"threat": "Data modification", "vulnerability": "Lack of integrity checks", "risk": "High", "mitigation": "Use TLS, checksums", "compliance": "NIST 800-53 SC-8", "example": "An attacker alters transaction data in an unencrypted API call."}
        ],
        "Information Disclosure": [
            {"threat": "Data exposure", "vulnerability": "Unencrypted channels", "risk": "High", "mitigation": "Use TLS 1.3, encrypt data at rest", "compliance": "GDPR Article 32", "example": "SQL injection exposes user data from a database."}
        ],
        "Denial of Service": [
            {"threat": "DDoS attack", "vulnerability": "No rate limiting", "risk": "High", "mitigation": "Implement Cloudflare, rate limiting", "compliance": "ISO 27001 A.12.1.3", "example": "A botnet floods an e-commerce site, causing downtime."}
        ],
        "Elevation of Privilege": [
            {"threat": "Privilege escalation", "vulnerability": "Insecure RBAC", "risk": "Critical", "mitigation": "Apply least privilege, audit roles", "compliance": "NIST 800-53 AC-6", "example": "An attacker exploits a misconfigured role to gain admin access."}
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
        },
        {
            "name": "IoT Smart Home",
            "architecture": "IoT devices with MQTT, cloud backend on Azure",
            "threats": [
                stride_library["Spoofing"][0],
                stride_library["Information Disclosure"][0],
                stride_library["Denial of Service"][0]
            ]
        },
        {
            "name": "Mobile Banking App",
            "architecture": "Mobile app with REST API, PostgreSQL on GCP",
            "threats": [
                stride_library["Tampering"][0],
                stride_library["Information Disclosure"][0],
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
        ],
        "IoT System": [
            {"type": "External Entity", "name": "User", "technology": "Mobile App", "x": 50, "y": 50},
            {"type": "Process", "name": "IoT Gateway", "technology": "MQTT", "x": 200, "y": 150},
            {"type": "Data Store", "name": "Cloud Storage", "technology": "Azure Blob", "x": 350, "y": 150},
            {"type": "Data Flow", "name": "Sensor Data", "data_flow": "MQTT publish", "source": "User", "target": "IoT Gateway"}
        ],
        "Mobile App": [
            {"type": "External Entity", "name": "User", "technology": "Mobile Device", "x": 50, "y": 50},
            {"type": "Process", "name": "API Server", "technology": "REST API", "x": 200, "y": 150},
            {"type": "Data Store", "name": "Database", "technology": "PostgreSQL", "x": 350, "y": 150},
            {"type": "Data Flow", "name": "API Request", "data_flow": "HTTPS", "source": "User", "target": "API Server"}
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
        "generated_by": "Anonymous"
    }
    report_json = json.dumps(report, indent=2)
    b64 = base64.b64encode(report_json.encode()).decode()
    return f'<a href="data:application/json;base64,{b64}" download="{threat_model_name}_report.json" class="aws-button">Download JSON Report</a>'

@st.cache_data
def create_csv_report(threat_model_name, threats, _timestamp):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance", "Example"])
    for threat in threats:
        writer.writerow([threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"], threat["example"]])
    csv_data = output.getvalue().encode()
    b64 = base64.b64encode(csv_data).decode()
    return f'<a href="data:application/csv;base64,{b64}" download="{threat_model_name}_report.csv" class="aws-button">Download CSV Report</a>'

@st.cache_data
def create_pdf_report(threat_model_name, architecture, dfd_elements, threats, dfd_image, _timestamp):
    filename = f"temp_{threat_model_name}_report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Threat Model: {threat_model_name}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Architecture: {architecture}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Threats", styles["Heading2"]),
        Table([["Threat", "Vulnerability", "Risk", "Mitigation", "Compliance", "Example"]] + [
            [threat["threat"], threat["vulnerability"], threat["risk"], threat["mitigation"], threat["compliance"], threat["example"]]
            for threat in threats
        ], style=[
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black)
        ])
    ]
    if dfd_image:
        img = PILImage.open(io.BytesIO(dfd_image))
        img = img.resize((400, 200))
        story.insert(2, Spacer(1, 12))
        story.insert(2, Paragraph("DFD Diagram", styles["Heading2"]))
        story.insert(3, reportlab.platypus.Image(io.BytesIO(dfd_image), width=400, height=200))
    doc.build(story)
    with open(filename, "rb") as f:
        pdf_data = f.read()
    b64 = base64.b64encode(pdf_data).decode()
    os.remove(filename)
    return f'<a href="data:application/pdf;base64,{b64}" download="{threat_model_name}_report.pdf" class="aws-button">Download PDF Report</a>'

@st.cache_data
def create_risk_chart(threats, _timestamp):
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for threat in threats:
        risk_counts[threat["risk"]] += 1
    df = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
    fig = px.bar(df, x="Risk Level", y="Count", title="Risk Distribution", color="Risk Level")
    fig.update_layout(
        plot_bgcolor="#ffffff",
        paper_bgcolor="#ffffff",
        font_color="#0f1a44",
        title_font_color="#0f1a44",
        title_font_size=16,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return fig

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
    keywords = {
        "web": ["Spoofing", "Tampering"],
        "database": ["Information Disclosure"],
        "api": ["Denial of Service"],
        "iot": ["Spoofing", "Information Disclosure"],
        "mobile": ["Tampering", "Elevation of Privilege"],
        "cloud": ["Denial of Service", "Information Disclosure"]
    }
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
st.set_page_config(page_title="Learn Threat Modeling", layout="wide")
st.markdown('<h1 style="color: #0f1a44;">Learn Threat Modeling</h1>', unsafe_allow_html=True)
st.markdown("Master STRIDE-based threat modeling with an interactive DFD editor and guided tutorials.")
st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)

# Theme toggle
theme = st.sidebar.selectbox("Theme", ["Light", "Dark"], index=0 if st.session_state.theme == "light" else 1, label_visibility="collapsed")
if theme.lower() != st.session_state.theme:
    st.session_state.theme = theme.lower()

# Role selection
st.session_state.role = st.sidebar.selectbox("Role", ["admin", "user"], index=0 if st.session_state.role == "admin" else 1, label_visibility="collapsed")

# Apply dark theme CSS
if st.session_state.theme == "dark":
    st.markdown("""
        <style>
        .stApp { background-color: #0f1a44; color: #ffffff; }
        .stSidebar { background-color: #1a2a6c; border-right: 1px solid #3b4a8b; }
        .stTextInput > div > input, .stSelectbox > div > select, .stTextArea > div > textarea { background-color: #2a3a7b; color: #ffffff; border: 1px solid #3b4a8b; }
        .stTextInput > div > input:focus, .stSelectbox > div > select:focus, .stTextArea > div > textarea:focus { border-color: #ff6200; box-shadow: 0 0 0 2px rgba(255, 98, 0, 0.3); }
        .stButton > button { background-color: #0073bb; }
        .stButton > button:hover { background-color: #005ea2; }
        .stButton > button.secondary { background-color: #2a3a7b; color: #ffffff; border: 1px solid #3b4a8b; }
        .stButton > button.secondary:hover { background-color: #3b4a8b; }
        .stExpander { background-color: #1a2a6c; border: 1px solid #3b4a8b; }
        .stTable { background-color: #1a2a6c; border: 1px solid #3b4a8b; }
        .stTable th { background-color: #3b4a8b; color: #ffffff; }
        .stTable td { color: #ffffff; }
        .aws-button { background-color: #0073bb; }
        .aws-button:hover { background-color: #005ea2; }
        h1, h2, h3 { color: #ffffff; }
        .aws-divider { border-top: 1px solid #3b4a8b; }
        </style>
    """, unsafe_allow_html=True)

# Interactive Tutorial
def show_tutorial():
    st.sidebar.markdown('<h2 style="color: #0f1a44;">Tutorial: Learn Threat Modeling</h2>', unsafe_allow_html=True)
    tutorial_steps = [
        {
            "title": "What is Threat Modeling?",
            "content": "Threat modeling identifies security risks in a system using the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Start by creating a Data Flow Diagram (DFD).",
            "action": "Go to 'Create Model' and select the 'Web Application' template."
        },
        {
            "title": "Building a DFD",
            "content": "A DFD includes Processes (e.g., servers), Data Stores (e.g., databases), External Entities (e.g., users), and Data Flows (e.g., HTTP requests). Drag elements onto the canvas and connect them with Data Flows.",
            "action": "Add a Process and a Data Flow in the DFD editor."
        },
        {
            "title": "Identifying Threats",
            "content": "The app uses STRIDE to suggest threats based on your DFD and architecture. For example, a database may face Information Disclosure risks like SQL injection.",
            "action": "Enter a system description (e.g., 'web app with database') and click 'Generate'."
        },
        {
            "title": "Review and Mitigate",
            "content": "Review generated threats, their risks, and mitigations. Download reports to document your findings.",
            "action": "Download a PDF report and review the mitigations."
        }
    ]
    step = st.session_state.tutorial_step
    if step < len(tutorial_steps):
        with st.sidebar.expander(tutorial_steps[step]["title"], expanded=True):
            st.write(tutorial_steps[step]["content"])
            if st.button("Next Step", key="tutorial_next"):
                st.session_state.tutorial_step += 1
                st.rerun()
    else:
        st.sidebar.success("Tutorial completed! Explore the app or take the quiz.")

# STRIDE Explanations
def show_stride_info():
    st.markdown('<h2 style="color: #0f1a44;">Understanding STRIDE</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    for category, threats in stride_library.items():
        with st.expander(category):
            st.markdown(f"<p><strong>Description</strong>: {threats[0]['threat']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Vulnerability</strong>: {threats[0]['vulnerability']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Risk</strong>: {threats[0]['risk']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Mitigation</strong>: {threats[0]['mitigation']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Compliance</strong>: {threats[0]['compliance']}</p>", unsafe_allow_html=True)
            st.markdown(f"<p><strong>Example</strong>: {threats[0]['example']}</p>", unsafe_allow_html=True)

# Quiz Mode
def show_quiz():
    st.markdown('<h2 style="color: #0f1a44;">Test Your Knowledge</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    questions = [
        {
            "question": "What does the 'S' in STRIDE stand for?",
            "options": ["Security", "Spoofing", "System", "Standard"],
            "correct": "Spoofing",
            "explanation": "Spoofing involves impersonating a user or system to gain unauthorized access."
        },
        {
            "question": "Which STRIDE category addresses data exposure?",
            "options": ["Tampering", "Repudiation", "Information Disclosure", "Denial of Service"],
            "correct": "Information Disclosure",
            "explanation": "Information Disclosure involves unauthorized access to sensitive data, like SQL injection."
        },
        {
            "question": "What is a key mitigation for Elevation of Privilege?",
            "options": ["Encryption", "Rate limiting", "Least privilege", "MFA"],
            "correct": "Least privilege",
            "explanation": "Least privilege ensures users have only the permissions needed, reducing escalation risks."
        }
    ]
    with st.container():
        for i, q in enumerate(questions):
            st.markdown(f"<h3 style='color: #0f1a44;'>Question {i+1}: {q['question']}</h3>", unsafe_allow_html=True)
            answer = st.radio(f"Select an answer for question {i+1}", q["options"], key=f"quiz_q{i}", label_visibility="collapsed")
            st.session_state.quiz_answers[f"q{i}"] = answer
        if st.button("Submit Quiz"):
            score = sum(1 for i, q in enumerate(questions) if st.session_state.quiz_answers.get(f"q{i}") == q["correct"])
            st.markdown(f"<p><strong>Score</strong>: {score}/{len(questions)}</p>", unsafe_allow_html=True)
            for i, q in enumerate(questions):
                if st.session_state.quiz_answers.get(f"q{i}") != q["correct"]:
                    st.markdown(f"<p><strong>Question {i+1}</strong>: Incorrect. {q['explanation']}</p>", unsafe_allow_html=True)
            st.session_state.quiz_answers = {}
            logger.info(f"Quiz completed with score: {score}/{len(questions)}")

# Main app
options = ["Tutorial", "STRIDE Info", "Pre-defined Models", "Create Model", "Saved Models", "Quiz", "Logout"]
if st.session_state.role == "admin":
    options.append("Manage Users")
option = st.sidebar.radio("Options", options, label_visibility="collapsed")

if option == "Tutorial":
    show_tutorial()

elif option == "STRIDE Info":
    show_stride_info()

elif option == "Logout":
    st.session_state.clear()
    st.session_state.role = "admin"
    st.session_state.tutorial_step = 0
    logger.info("User logged out")
    st.rerun()

elif option == "Pre-defined Models":
    st.markdown('<h2 style="color: #0f1a44;">Pre-defined Threat Models</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    for model in pre_defined_threat_models:
        with st.expander(model["name"]):
            st.markdown(f"<p><strong>Architecture</strong>: {model['architecture']}</p>", unsafe_allow_html=True)
            st.table([
                {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                for threat in model["threats"]
            ])
            st.plotly_chart(create_risk_chart(model["threats"], datetime.now().timestamp()))
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                st.markdown(create_json_report(model["name"], model["architecture"], [], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            with col2:
                st.markdown(create_csv_report(model["name"], model["threats"], datetime.now().timestamp()), unsafe_allow_html=True)
            with col3:
                st.markdown(create_pdf_report(model["name"], model["architecture"], [], model["threats"], None, datetime.now().timestamp()), unsafe_allow_html=True)

elif option == "Create Model":
    st.markdown('<h2 style="color: #0f1a44;">Create Threat Model</h2>', unsafe_allow_html=True)
    st.markdown("Drag Processes, Data Stores, or External Entities to create a DFD. Use templates to start quickly.")
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)

    # Template selection
    col1, col2 = st.columns([2, 1])
    with col1:
        template = st.selectbox("Template", ["None"] + list(dfd_templates.keys()), label_visibility="collapsed")
    with col2:
        if st.button("Load Template", type="secondary"):
            if template != "None":
                st.session_state.dfd_elements = dfd_templates[template]
                st.session_state.last_update = datetime.now().timestamp()
                logger.info(f"Loaded template: {template}")

    # DFD editor
    col1, col2 = st.columns([3, 2])
    with col1:
        try:
            with open("dfd_editor.html", "r") as f:
                html_content = f.read().replace("{{THEME}}", st.session_state.theme)
            dfd_data = components.html(html_content, height=450)
        except FileNotFoundError:
            st.error("Error: dfd_editor.html not found. Please ensure the file is in the project directory.")
            logger.error("dfd_editor.html not found")
            dfd_data = {}
        except Exception as e:
            st.error("Error loading DFD editor. Please try again.")
            logger.error(f"Error loading DFD editor: {str(e)}")
            dfd_data = {}

        # Process DFD data
        try:
            if isinstance(dfd_data, dict) and "elements" in dfd_data:
                current_time = datetime.now().timestamp()
                if current_time - st.session_state.last_update > 1:
                    st.session_state.dfd_elements = dfd_data["elements"]
                    st.session_state.last_update = current_time
                    if "image" in dfd_data and dfd_data["image"]:
                        try:
                            st.session_state.dfd_image = base64.b64decode(dfd_data["image"].split(",")[1])
                        except Exception as e:
                            logger.error(f"Error decoding DFD image: {str(e)}")
                            st.session_state.dfd_image = None
            else:
                logger.warning(f"Invalid dfd_data: {type(dfd_data)} {dfd_data}")
        except Exception as e:
            logger.error(f"Error processing dfd_data: {str(e)}")
            st.error("Error processing DFD data. Please refresh and try again.")

    # Annotate elements
    with col2:
        if st.session_state.dfd_elements and isinstance(dfd_data, dict) and "selected" in dfd_data:
            selected_id = dfd_data["selected"]
            selected_element = next((e for e in st.session_state.dfd_elements if e["id"] == selected_id), None)
            if selected_element:
                st.markdown(f"<p><strong>Editing: {selected_element['name']} ({selected_element['type']})</strong></p>", unsafe_allow_html=True)
                element_name = st.text_input("Name", value=selected_element["name"], placeholder="e.g., Web Server", label_visibility="collapsed")
                technology = st.text_input("Technology", value=selected_element.get("technology", ""), placeholder="e.g., Node.js", label_visibility="collapsed")
                data_flow = st.text_input("Data Flow", value=selected_element.get("data_flow", ""), placeholder="e.g., HTTP request", label_visibility="collapsed") if selected_element["type"] == "Data Flow" else ""
                if st.button("Update", type="primary"):
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
        st.markdown('<h3 style="color: #0f1a44;">DFD Elements</h3>', unsafe_allow_html=True)
        st.table([
            {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
            for elem in st.session_state.dfd_elements
        ])

    # Generate threat model
    with st.container():
        st.markdown('<h3 style="color: #0f1a44;">Generate Threat Model</h3>', unsafe_allow_html=True)
        threat_model_name = st.text_input("Name", placeholder="e.g., My App", label_visibility="collapsed")
        architecture = st.text_area("Architecture", placeholder="Describe your system (e.g., web app with database)", label_visibility="collapsed")
        if st.button("Generate", type="primary"):
            validations = [
                validate_input(threat_model_name, "Name"),
                validate_input(architecture, "Architecture"),
                validate_dfd(st.session_state.dfd_elements) if st.session_state.dfd_elements else (False, "Add DFD elements.")
            ]
            if all(v[0] for v in validations):
                threats = generate_threat_model(st.session_state.dfd_elements, architecture, stride_library)
                st.markdown(f"<h3 style='color: #0f1a44;'>Threat Model: {threat_model_name}</h3>", unsafe_allow_html=True)
                st.markdown(f"<p><strong>Architecture</strong>: {architecture}</p>", unsafe_allow_html=True)
                if st.session_state.dfd_image:
                    st.image(st.session_state.dfd_image)
                st.markdown("<p><strong>DFD Elements</strong>:</p>", unsafe_allow_html=True)
                st.table([
                    {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
                    for elem in st.session_state.dfd_elements
                ])
                st.markdown("<p><strong>Threats</strong>:</p>", unsafe_allow_html=True)
                st.table([
                    {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                    for threat in threats
                ])
                timestamp = datetime.now().timestamp()
                st.plotly_chart(create_risk_chart(threats, timestamp))
                col1, col2, col3 = st.columns([1, 1, 1])
                with col1:
                    st.markdown(create_json_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, timestamp), unsafe_allow_html=True)
                with col2:
                    st.markdown(create_csv_report(threat_model_name, threats, timestamp), unsafe_allow_html=True)
                with col3:
                    st.markdown(create_pdf_report(threat_model_name, architecture, st.session_state.dfd_elements, threats, st.session_state.dfd_image, timestamp), unsafe_allow_html=True)

                c = conn.cursor()
                c.execute("INSERT INTO threat_models (name, architecture, dfd_elements, threats, created_at) VALUES (?, ?, ?, ?, ?)",
                          (threat_model_name, architecture, json.dumps(st.session_state.dfd_elements), json.dumps(threats), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()
                st.success("Threat model saved!")
            else:
                for _, error in validations:
                    st.error(error)

elif option == "Saved Models":
    st.markdown('<h2 style="color: #0f1a44;">Saved Threat Models</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    c = conn.cursor()
    c.execute("SELECT id, name, architecture, dfd_elements, threats, created_at FROM threat_models")
    models = c.fetchall()
    if models:
        for model_id, name, architecture, dfd_elements, threats, created_at in models:
            with st.expander(f"{name} ({created_at})"):
                st.markdown(f"<p><strong>Architecture</strong>: {architecture}</p>", unsafe_allow_html=True)
                dfd_elements = json.loads(dfd_elements)
                threats = json.loads(threats)
                st.table([
                    {k: v for k, v in elem.items() if k in ["type", "name", "technology", "data_flow"]}
                    for elem in dfd_elements
                ])
                st.table([
                    {k: v for k, v in threat.items() if k in ["threat", "vulnerability", "risk", "mitigation", "compliance", "example"]}
                    for threat in threats
                ])
                timestamp = datetime.now().timestamp()
                st.plotly_chart(create_risk_chart(threats, timestamp))
                col1, col2, col3 = st.columns([1, 1, 1])
                with col1:
                    st.markdown(create_json_report(name, architecture, dfd_elements, threats, timestamp), unsafe_allow_html=True)
                with col2:
                    st.markdown(create_csv_report(name, threats, timestamp), unsafe_allow_html=True)
                with col3:
                    st.markdown(create_pdf_report(name, architecture, dfd_elements, threats, None, timestamp), unsafe_allow_html=True)
                if st.session_state.role == "admin":
                    if st.button(f"Delete", key=f"delete_{model_id}", type="secondary"):
                        c.execute("DELETE FROM threat_models WHERE id = ?", (model_id,))
                        conn.commit()
                        logger.info(f"Deleted model: {name}")
                        st.rerun()
    else:
        st.info("No saved models.")

elif option == "Quiz":
    show_quiz()

elif option == "Manage Users" and st.session_state.role == "admin":
    st.markdown('<h2 style="color: #0f1a44;">Manage Users</h2>', unsafe_allow_html=True)
    st.markdown('<div class="aws-divider"></div>', unsafe_allow_html=True)
    with st.container():
        new_username = st.text_input("Username", placeholder="Enter username", label_visibility="collapsed")
        new_password = st.text_input("Password", type="password", placeholder="Enter password", label_visibility="collapsed")
        new_role = st.selectbox("Role", ["user", "admin"], label_visibility="collapsed")
        if st.button("Add User", type="primary"):
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
            st.markdown(f"<p>Username: {username}, Role: {role}</p>", unsafe_allow_html=True)
            if st.button(f"Delete {username}", key=f"delete_user_{username}", type="secondary"):
                c.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                logger.info(f"Deleted user: {username}")
                st.rerun()

# Clean up temporary files
for file in os.listdir():
    if file.startswith("temp_") and file.endswith(".pdf"):
        os.remove(file)
