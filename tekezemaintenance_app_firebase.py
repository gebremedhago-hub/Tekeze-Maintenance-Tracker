import streamlit as st
import bcrypt
import firebase_admin
from firebase_admin import credentials, firestore
import json
from datetime import datetime
import uuid
import os
import pandas as pd

# --- Firebase Initialization ---
def initialize_firebase():
    if not firebase_admin._apps:
        try:
            if os.path.exists("firebase_config.json"):
                with open("firebase_config.json") as f:
                    firebase_config = json.load(f)
                cred = credentials.Certificate(firebase_config)
                firebase_admin.initialize_app(cred)
                st.session_state.db = firestore.client()
                return True
            elif "firebase_config" in st.secrets:
                cred = credentials.Certificate(st.secrets["firebase_config"])
                firebase_admin.initialize_app(cred)
                st.session_state.db = firestore.client()
                return True
            else:
                st.error("Firebase configuration not found. Please set `firebase_config.json` locally or set the `firebase_config` secret.")
                return False
        except Exception as e:
            st.error(f"Error initializing Firebase: {e}")
            st.info("Please ensure your Firebase configuration is correctly set up.")
            return False
    return True

if initialize_firebase():
    st.session_state.authenticated = True
else:
    st.session_state.authenticated = False


# --- Firebase Functions ---
def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user_ref = st.session_state.db.collection('users').document(username)
    user_ref.set({
        'username': username,
        'password': hashed_password.decode('utf-8')
    })
    return True

def login_user(username, password):
    user_ref = st.session_state.db.collection('users').document(username)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        stored_password = user_data['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            return True
    return False

def insert_report(report_data):
    reports_ref = st.session_state.db.collection('reports')
    reports_ref.add({
        **report_data,
        'timestamp': datetime.utcnow()
    })
    return True

def get_reports():
    reports_ref = st.session_state.db.collection('reports')
    all_reports = reports_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
    reports_list = [report.to_dict() for report in all_reports]
    return reports_list

def calculate_dynamic_weights(reports):
    """Calculates the dynamic weight for each report based on its total resources."""
    if not reports:
        return []

    # Calculate total resource sum for all completed tasks
    total_resource_sum = 0
    for report in reports:
        if report.get('status') == "Completed" and 'planned_manpower' in report:
            try:
                resource_sum = report.get('planned_manpower', 0) + report.get('planned_time', 0) + report.get('planned_activities', 0)
                total_resource_sum += resource_sum
            except (ValueError, TypeError):
                continue
    
    if total_resource_sum == 0:
        return reports

    # Calculate weight for each report
    updated_reports = []
    for report in reports:
        if report.get('status') == "Completed" and 'planned_manpower' in report:
            try:
                resource_sum = report.get('planned_manpower', 0) + report.get('planned_time', 0) + report.get('planned_activities', 0)
                report['given_weight'] = (resource_sum / total_resource_sum) * 100
            except (ValueError, TypeError):
                report['given_weight'] = 0
        updated_reports.append(report)
        
    return updated_reports

def calculate_adjusted_metric(planned, actual):
    """Calculates adjusted metric based on punishment/reward formula."""
    if planned == 0:
        return actual
    diff = abs(actual - planned)
    if actual > planned:
        # Punishment
        return actual - diff * (1 + diff / planned)
    else:
        # Reward
        return actual + diff * (1 + diff / planned)

# --- Streamlit UI ---
st.set_page_config(layout="wide", page_title="Tekeze Maintenance Tracker")

if 'username' not in st.session_state:
    st.session_state.username = None
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'db' not in st.session_state:
    st.session_state.db = None
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Title and Logo section
col_logo, col_dam, col_title = st.columns([1, 2, 4])
with col_logo:
    try:
        st.image("eep_logo.png", width=100)
    except FileNotFoundError:
        st.image("https://placehold.co/100x100/A1C4FD/ffffff?text=TKZ", width=100)
with col_dam:
    try:
        st.image("dam.jpg", width=300)
    except FileNotFoundError:
        st.warning("dam.jpg not found. Using a placeholder image.")
        st.image("https://placehold.co/600x200/A1C4FD/ffffff?text=Dam+Image", width=300)
with col_title:
    st.markdown("<h1 style='text-align: center; color: #1E90FF;'>Tekeze Maintenance Tracker</h1>", unsafe_allow_html=True)
st.markdown("<hr style='border: 2px solid #1E90FF;'>", unsafe_allow_html=True)

# Main app logic
if st.session_state.logged_in:
    # Developer info at the top right of the sidebar
    with st.sidebar:
        try:
            st.sidebar.image("developer.jpg", width=100)
        except FileNotFoundError:
            st.sidebar.warning("developer.jpg not found.")
            st.sidebar.image("https://placehold.co/150x150/A1C4FD/ffffff?text=Gebremedhin+Hagos", width=100)
        st.markdown("<p style='text-align: center;'><b>Developed by:</b> Gebremedhin Hagos</p>", unsafe_allow_html=True)
        st.markdown("<hr>", unsafe_allow_html=True)
        
    st.sidebar.header(f"Welcome, {st.session_state.username}")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    st.header("Submit New Maintenance Report")
    
    with st.form("maintenance_form"):
        unique_id = str(uuid.uuid4())[:8]
        report_id = st.text_input("Report ID (Auto-generated)", value=f"TKZ-{unique_id}", disabled=True)
        device_name = st.text_input("Device Name", help="e.g., HVAC Unit 3, Server Rack 5")
        
        # Updated fields with new options
        functional_location_options = ["powerhouse", "dam", "Switch Yard", "Access road", "Garage", "Dwelling", "others"]
        functional_location = st.selectbox("Functional Location", options=functional_location_options)
        
        specific_location_options = ["unit 1", "unit 2", "unit 3", "unit 4", "common system", "spillway", "intake gate", "trash rack crane", "diesel generator", "bonnet gate", "substation", "SYD control room", "step down transformer", "water supply", "road", "employee camp", "China camp", "wanboo camp", "garage", "others"]
        specific_location = st.selectbox("Specific Location", options=specific_location_options)

        # New field: Maintenance Type
        maintenance_type_options = ["inspection", "preventive maintenance", "breakdown/emergency/corrective"]
        maintenance_type = st.selectbox("Maintenance Type", options=maintenance_type_options)
        
        col_issue, col_priority, col_status, col_safety = st.columns(4)
        with col_issue:
            issue_type = st.selectbox("Type of Issue", ["Mechanical", "Electrical", "Software", "Network", "Other"])
        with col_priority:
            priority = st.radio("Priority", ["Low", "Medium", "High"], horizontal=True)
        with col_status:
            status_options = ["fully functional", "functional but need monitoring", "temporarily functional( risk present)", "unfunctional"]
            status = st.selectbox("Status", options=status_options)
        with col_safety:
            safety_condition_options = ["Safely accomplished", "sign of unsafe environment observed", "maintenance platform was not safe", "totally unsafe"]
            safety_condition = st.selectbox("Safety Condition", options=safety_condition_options)

        description = st.text_area("Description of the Problem", help="Provide a detailed description of the issue.")
        conditions_observed = st.text_area("Conditions Observed", help="What were the conditions when the issue was found?")
        diagnosis_undertaken = st.text_area("Diagnosis Undertaken", help="How was the issue diagnosed?")
        action_taken = st.text_area("Action Taken", help="What actions were taken to resolve the issue?")
        personnel_participated = st.text_area("Personnel Participated", help="List the names of personnel involved.")
        
        # --- Planned Activities Field (accessible to all) ---
        planned_activities = st.number_input("Planned Activities", min_value=0, step=1, help="Number of activities planned for this task.")
        
        # --- New fields for all reporters ---
        actual_manpower = st.number_input("Actual Manpower Used", min_value=0, step=1)
        actual_time = st.number_input("Actual Time Used (hours)", min_value=0.0)
        actual_activities = st.number_input("Actual Activities Done", min_value=0, step=1)


        # --- Manager-specific fields ---
        planned_manpower, planned_time = 0, 0
        
        if st.session_state.username == 'seyoum.h':
            st.markdown("---")
            st.subheader("Manager-Only Fields")
            col_p1, col_p2 = st.columns(2)
            with col_p1:
                planned_manpower = st.number_input("Planned Manpower", min_value=0, step=1, help="Manager-only field.")
            with col_p2:
                planned_time = st.number_input("Planned Time (hours)", min_value=0.0, help="Manager-only field.")
            
        # --- File Upload Section (Conceptual) ---
        st.markdown("---")
        st.subheader("Attach Files")
        st.info("Note: File uploads require a separate backend service like Firebase Storage to persist. The Streamlit component below is for demonstration.")
        # uploaded_file = st.file_uploader("Upload a file")
        # if uploaded_file is not None:
        #    # This is where you would write the logic to upload the file
        #    # to Firebase Storage using the Firebase Storage SDK.
        #    st.success("File upload component is ready.")

        reported_by = st.text_input("Reported By", value=st.session_state.username, disabled=True)
        
        submitted = st.form_submit_button("Submit Report")
        
        if submitted:
            if not all([device_name, functional_location, specific_location, issue_type, priority, status, safety_condition, description, conditions_observed, diagnosis_undertaken, action_taken, personnel_participated, planned_activities]):
                st.error("Please fill in all the required fields.")
            else:
                report_data = {
                    "id": report_id,
                    "device_name": device_name,
                    "functional_location": functional_location,
                    "specific_location": specific_location,
                    "maintenance_type": maintenance_type, # New field
                    "issue_type": issue_type,
                    "description": description,
                    "priority": priority,
                    "status": status,
                    "safety_condition": safety_condition,
                    "conditions_observed": conditions_observed,
                    "diagnosis_undertaken": diagnosis_undertaken,
                    "action_taken": action_taken,
                    "personnel_participated": personnel_participated,
                    "reported_by": reported_by,
                    "planned_activities": planned_activities,
                    "actual_manpower": actual_manpower, # New field for all reporters
                    "actual_time": actual_time, # New field for all reporters
                    "actual_activities": actual_activities # New field for all reporters
                }
                
                if st.session_state.username == 'seyoum.h':
                    report_data["planned_manpower"] = planned_manpower
                    report_data["planned_time"] = planned_time
                    
                    if status == "Completed":
                        # Apply custom efficiency formulas
                        adj_manpower = calculate_adjusted_metric(planned_manpower, report_data.get('actual_manpower', 0))
                        adj_time = calculate_adjusted_metric(planned_time, report_data.get('actual_time', 0))
                        adj_activities = report_data.get('actual_activities', 0)

                        total_planned_resources = planned_manpower + planned_time + planned_activities
                        total_actual_resources = adj_manpower + adj_time + adj_activities
                        
                        if total_planned_resources > 0:
                            performance_score = (total_actual_resources / total_planned_resources) * 100
                            report_data["performance_score"] = f"{performance_score:.2f}%"
                        else:
                            report_data["performance_score"] = "Calculation Error: Planned resources sum is zero."

                if insert_report(report_data):
                    st.success("Report submitted successfully!")
                    st.rerun()
                else:
                    st.error("Failed to submit report.")

    st.markdown("<hr>", unsafe_allow_html=True)
    st.header("Recent Maintenance Reports")
    
    reports = get_reports()
    
    # Calculate and add dynamic weights for display
    reports_with_weights = calculate_dynamic_weights(reports)
    
    if reports_with_weights:
        # Create a DataFrame to export
        df = pd.DataFrame(reports_with_weights)
        
        # Reorder columns to place performance metrics at the end
        metrics_cols = ['given_weight', 'performance_score']
        other_cols = [col for col in df.columns if col not in metrics_cols]
        new_order = other_cols + metrics_cols
        
        df = df.reindex(columns=new_order)
        
        col_view, col_export = st.columns([4,1])
        with col_export:
            st.download_button(
                label="Export Reports to CSV",
                data=df.to_csv(index=False).encode('utf-8'),
                file_name='maintenance_reports.csv',
                mime='text/csv',
                help="Download all reports as a CSV file"
            )

        for report in reports_with_weights:
            with st.expander(f"Report ID: {report['id']} - Device: {report['device_name']}"):
                st.write(f"**Functional Location:** {report.get('functional_location', 'N/A')}")
                st.write(f"**Specific Location:** {report.get('specific_location', 'N/A')}")
                st.write(f"**Maintenance Type:** {report.get('maintenance_type', 'N/A')}") # New field display
                st.write(f"**Issue Type:** {report.get('issue_type', 'N/A')}")
                st.write(f"**Priority:** {report.get('priority', 'N/A')}")
                st.write(f"**Status:** {report.get('status', 'N/A')}")
                st.write(f"**Safety Condition:** {report.get('safety_condition', 'N/A')}")
                st.write(f"**Description:** {report.get('description', 'N/A')}")
                st.write(f"**Conditions Observed:** {report.get('conditions_observed', 'N/A')}")
                st.write(f"**Diagnosis Undertaken:** {report.get('diagnosis_undertaken', 'N/A')}")
                st.write(f"**Action Taken:** {report.get('action_taken', 'N/A')}")
                st.write(f"**Personnel Participated:** {report.get('personnel_participated', 'N/A')}")

                # Display fields for all reports
                st.write(f"**Planned Activities:** {report.get('planned_activities', 'N/A')}")
                st.write(f"**Actual Manpower:** {report.get('actual_manpower', 'N/A')}")
                st.write(f"**Actual Time (hours):** {report.get('actual_time', 'N/A')}")
                st.write(f"**Actual Activities:** {report.get('actual_activities', 'N/A')}")

                # Display dynamic weights and performance score
                if "given_weight" in report:
                    st.markdown("---")
                    st.write(f"**Planned Manpower:** {report.get('planned_manpower', 'N/A')}")
                    st.write(f"**Planned Time (hours):** {report.get('planned_time', 'N/A')}")
                    
                    st.write(f"**Given Weight:** {report.get('given_weight', 0):.2f}%")
                    st.write(f"**Performance Score:** {report.get('performance_score', 'N/A')}")
                
                st.write(f"**Reported By:** {report.get('reported_by', 'N/A')}")
                st.write(f"**Submitted On:** {report.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        st.info("No reports found.")

else:
    # Login/Register page
    st.header("Login or Register")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_user")
        login_password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if not st.session_state.authenticated:
                st.error("Cannot connect to database. Please check Firebase configuration.")
            elif login_user(login_username, login_password):
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with col2:
        st.subheader("Register")
        reg_username = st.text_input("New Username", key="reg_user")
        reg_password = st.text_input("New Password", type="password", key="reg_pass")
        if st.button("Register"):
            if not st.session_state.authenticated:
                st.error("Cannot connect to database. Please check Firebase configuration.")
            else:
                try:
                    add_user(reg_username, reg_password)
                    st.success("Registration successful! You can now log in.")
                except Exception as e:
                    st.error(f"Registration failed: {e}")