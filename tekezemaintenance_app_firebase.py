import streamlit as st 
import firebase_admin
from firebase_admin import credentials, firestore, auth
import bcrypt
import pandas as pd
import json
import datetime
import math
import base64
import io
import os  # NEW: for basename on uploaded files

# Try to import reportlab for PDF generation; we’ll gracefully fall back if unavailable
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# --- ⚙️ Streamlit Session State ---
# These variables persist across user interactions in the app.
if 'page' not in st.session_state:
    st.session_state['page'] = 'home'
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'user' not in st.session_state:
    st.session_state['user'] = None
if 'db' not in st.session_state:
    st.session_state['db'] = None
if 'firebase_initialized' not in st.session_state:
    st.session_state['firebase_initialized'] = False
if 'selected_report_id' not in st.session_state:
    st.session_state['selected_report_id'] = None

# --- Firebase Setup ---

def initialize_firebase():
    """
    Initializes Firebase credentials from Streamlit secrets.
    Returns True if successful, False otherwise.
    """
    if st.session_state.firebase_initialized:
        return True
    
    try:
        firebase_config = st.secrets["firebase_config"]
        if not firebase_admin._apps:
            cred = credentials.Certificate(dict(firebase_config))
            firebase_admin.initialize_app(cred)
            
        st.session_state.db = firestore.client()
        st.session_state.firebase_initialized = True
        return True
    except KeyError:
        st.error("Firebase configuration not found. Please ensure 'firebase_config' is set in Streamlit Secrets.")
        return False
    except Exception as e:
        st.error(f"Error initializing Firebase: {e}")
        return False

# --- 🔢 Sequential Report ID (NEW) ---

def _initialize_counter_if_needed(transaction, db):
    counter_ref = db.collection('meta').document('report_counter')
    snapshot = counter_ref.get(transaction=transaction)
    if not snapshot.exists:
        # Initialize based on current count to avoid clashes with existing docs
        current_count = len(list(db.collection('maintenance_reports').stream()))
        transaction.set(counter_ref, {'current': int(current_count)})
def _get_next_report_id():
    """
    Atomically increments and returns the next 5-digit report ID as a zero-padded string.
    """
    db = st.session_state.db
    transaction = db.transaction()

    @firestore.transactional
    def txn(tx):
        counter_ref = db.collection('meta').document('report_counter')
        _initialize_counter_if_needed(tx, db)
        snapshot = counter_ref.get(transaction=tx)
        current = snapshot.get('current') or 0
        next_val = int(current) + 1
        tx.update(counter_ref, {'current': next_val})
        return f"{next_val:05d}"

    return txn(transaction)

# --- 📄 PDF Generation for Single Report (NEW) ---

def _report_to_pdf_bytes(report_dict) -> bytes:
    """
    Generates a PDF of the provided report dict. If reportlab is not installed,
    returns a minimal text-based PDF-like fallback.
    """
    if REPORTLAB_AVAILABLE:
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        x_left = 20 * mm
        y = height - 20 * mm
        line_gap = 7 * mm

        def draw_line(lbl, val):
            nonlocal y
            text = f"{lbl}: {val if val not in [None, ''] else 'N/A'}"
            c.drawString(x_left, y, text[:110])  # simple clipping
            y -= line_gap

        c.setTitle(f"Report {report_dict.get('id', '')}")
        c.setFont("Helvetica-Bold", 14)
        c.drawString(x_left, y, f"Tekeze Hydropower Plant - Maintenance Report")
        y -= line_gap * 1.5
        c.setFont("Helvetica", 11)

        sections = [
            ("Report ID", report_dict.get('id', '')),
            ("Reporter", report_dict.get('reporter', '')),
            ("Report Date", report_dict.get('report_date', '')),
            ("Functional Location", report_dict.get('functional_location', '')),
            ("Specific Location", report_dict.get('specific_location', '')),
            ("Maintenance Type", report_dict.get('maintenance_type', '')),
            ("Equipment", report_dict.get('equipment', '')),
            ("Affected Part", report_dict.get('affected_part', '')),
            ("Condition Observed", report_dict.get('condition_observed', '')),
            ("Diagnosis", report_dict.get('diagnosis', '')),
            ("Damage Type", report_dict.get('damage_type', '')),
            ("Action Taken", report_dict.get('action_taken', '')),
            ("Status", report_dict.get('status', '')),
            ("Safety Condition", report_dict.get('safety_condition', '')),
            ("Planned Activities", report_dict.get('planned_activities', '')),
            ("Actual Activities Done", report_dict.get('actual_activities', '')),
            ("Manpower Used", report_dict.get('manpower_used', '')),
            ("Total Time Used (hours)", report_dict.get('total_time', '')),
            ("Planned Manpower", report_dict.get('planned_manpower', '')),
            ("Planned Time", report_dict.get('planned_time', '')),
        ]

        for lbl, val in sections:
            # Make multiline for long fields
            if isinstance(val, str) and len(val) > 110:
                # split about every 100 chars
                first = True
                while val:
                    part = val[:100]
                    draw_line(lbl if first else "", part)
                    val = val[100:]
                    first = False
            else:
                draw_line(lbl, val)

            if y < 30 * mm:
                c.showPage()
                y = height - 20 * mm
                c.setFont("Helvetica", 11)

        # Attached file info
        attached = report_dict.get('attached_file', {})
        if attached:
            if y < 40 * mm:
                c.showPage()
                y = height - 20 * mm
                c.setFont("Helvetica", 11)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x_left, y, "Attachment")
            y -= line_gap
            c.setFont("Helvetica", 11)
            def _report_to_pdf_bytes(report):
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50

    def draw_line(label, value):
        nonlocal y
        c.drawString(50, y, f"{label}: {value}")
        y -= 20

    # Example fields (keep what you already had)
    draw_line("Report ID", report.get('id', 'N/A'))
    draw_line("Created By", report.get('created_by', 'N/A'))

    # Safely handle attachments
    attachments = report.get('attachments', [])
    if not isinstance(attachments, list):
        attachments = [attachments]

    for attached in attachments:
        # ✅ fixed line 171
        draw_line("File Name", attached.get('filename', 'N/A') if isinstance(attached, dict) else str(attached))

    c.showPage()
    c.save()
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


        c.showPage()
        c.save()
        buffer.seek(0)
        return buffer.read()

    # Fallback: very simple pseudo-PDF (still a valid PDF header/body, minimal content)
    # Note: This is intentionally tiny; for best results, add 'reportlab' to your environment.
    text_content = []
    for k, v in report_dict.items():
        if k == 'attached_file':
            af = v or {}
            text_content.append(f"{k}.filename: {af.get('filename','')}")
            text_content.append(f"{k}.filetype: {af.get('filetype','')}")
        else:
            text_content.append(f"{k}: {v}")
    content_str = "\n".join(text_content)
    fake_pdf = f"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<<>> >>endobj\n4 0 obj<</Length {len(content_str)+35}>>stream\nBT /F1 12 Tf 72 720 Td ({content_str[:1000]}) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000115 00000 n \n0000000270 00000 n \ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n400\n%%EOF"
    return fake_pdf.encode("latin-1", errors="ignore")

# --- User Authentication & Management Functions ---

def login_user(username, password):
    """
    Authenticates a user against the Firestore database.
    """
    user_ref = st.session_state.db.collection('users').document(username)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        hashed_password = user_data.get('password')
        if hashed_password and bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            st.session_state.logged_in = True
            st.session_state.user = user_data
            return True
    return False

def register_user(username, password, first_name, last_name, user_type, email):
    """Registers a new user in the Firestore database."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_data = {
        'username': username,
        'password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'user_type': user_type,
        'email': email
    }
    user_ref = st.session_state.db.collection('users').document(username)
    user_ref.set(user_data)
    st.success("Registration successful! Please log in.")
    return True

def change_password(username, old_password, new_password):
    """Changes the password for a logged-in user."""
    user_ref = st.session_state.db.collection('users').document(username)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        hashed_password = user_data.get('password')
        
        if hashed_password and bcrypt.checkpw(old_password.encode('utf-8'), hashed_password.encode('utf-8')):
            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user_ref.update({'password': new_hashed_password})
            return True
    return False

# --- Data Handling Functions for Firestore ---

def insert_report(data):
    """Inserts a new maintenance report into the Firestore database with a sequential ID (NEW)."""
    try:
        # Assign sequential ID
        new_id = _get_next_report_id()
        data['id'] = new_id  # keep inside document as well
        data['report_id'] = new_id  # optional alias

        # Write document with custom ID
        st.session_state.db.collection('maintenance_reports').document(new_id).set(data)
        return True
    except Exception as e:
        st.error(f"Failed to submit report: {e}")
        return False

def update_report(report_id, planned_manpower, planned_time):
    """Updates planned manpower and time for a specific report in Firestore."""
    try:
        report_ref = st.session_state.db.collection('maintenance_reports').document(report_id)
        report_ref.update({
            'planned_manpower': planned_manpower,
            'planned_time': planned_time
        })
        return True
    except Exception as e:
        st.error(f"Failed to update report: {e}")
        return False

def update_full_report(report_id, updated_fields):
    """Updates full editable fields of a report (for reporters to edit their own) (NEW)."""
    try:
        report_ref = st.session_state.db.collection('maintenance_reports').document(report_id)
        report_ref.update(updated_fields)
        return True
    except Exception as e:
        st.error(f"Failed to update report: {e}")
        return False

def delete_report(report_id):
    """Deletes a report from the Firestore database."""
    try:
        # Delete the report document
        st.session_state.db.collection('maintenance_reports').document(report_id).delete()
        # Also delete any associated comments
        comments_ref = st.session_state.db.collection('comments').where('report_id', '==', report_id)
        for comment_doc in comments_ref.stream():
            comment_doc.reference.delete()
        return True
    except Exception as e:
        st.error(f"Failed to delete report: {e}")
        return False

def get_reports(username=None):
    """Fetches reports from the Firestore database. Fetches all if username is None."""
    reports_ref = st.session_state.db.collection('maintenance_reports')
    if username:
        query = reports_ref.where('reporter', '==', username).order_by('report_date', direction=firestore.Query.DESCENDING)
    else:
        query = reports_ref.order_by('report_date', direction=firestore.Query.DESCENDING)

    reports_list = []
    for doc in query.stream():
        report = doc.to_dict()
        report['id'] = doc.id  # ensure ID reflects custom ID
        reports_list.append(report)
    
    return pd.DataFrame(reports_list)

def add_comment_to_report(report_id, user, comment):
    """Adds a new comment to a specific report."""
    try:
        comment_data = {
            'report_id': report_id,
            'user': user,
            'comment': comment,
            'timestamp': firestore.SERVER_TIMESTAMP
        }
        st.session_state.db.collection('comments').add(comment_data)
        return True
    except Exception as e:
        st.error(f"Failed to add comment: {e}")
        return False

def get_comments_for_report(report_id):
    """Fetches all comments for a specific report in real-time."""
    comments_ref = st.session_state.db.collection('comments').where('report_id', '==', report_id).order_by('timestamp')
    comments = comments_ref.stream()
    return [comment.to_dict() for comment in comments]

# --- 📊 Data Analysis Functions ---

def calculate_adjusted_value(planned, actual):
    """
    Calculates the adjusted value based on the user's reward/punishment formula.
    - Punishes over-utilization
    - Rewards under-utilization
    """
    # Use a small number to prevent division by zero
    epsilon = 1e-9
    
    # Perfect match
    if abs(planned - actual) < epsilon:
        return actual
    
    difference = actual - planned
    
    # Punishment for over-utilization
    if difference > 0:
        return actual - difference * (1 + difference / (planned + epsilon))
    # Reward for under-utilization
    else:
        return actual + abs(difference) * (1 + abs(difference) / (planned + epsilon))

def calculate_metrics(df):
    """
    Calculates all efficiency and weighted efficiency metrics based on
    the user's specified formulas.
    """
    df_metrics = df.copy()

    # Fill NaN values to prevent errors in calculations
    df_metrics['planned_manpower'] = df_metrics['planned_manpower'].fillna(0)
    df_metrics['planned_time'] = df_metrics['planned_time'].fillna(0)
    df_metrics['planned_activities'] = df_metrics['planned_activities'].fillna(0)
    df_metrics['manpower_used'] = df_metrics['manpower_used'].fillna(0)
    df_metrics['total_time'] = df_metrics['total_time'].fillna(0)
    df_metrics['actual_activities'] = df_metrics['actual_activities'].fillna(0)
    
    # Calculate Given Weight based on planned values. The sum of Given Weights will be 100%.
    df_metrics['total_planned_resource'] = df_metrics['planned_activities'] + df_metrics['planned_manpower'] + df_metrics['planned_time']
    total_planned_resource_sum = df_metrics['total_planned_resource'].sum()

    if total_planned_resource_sum > 0:
        df_metrics["Given Weight"] = (df_metrics['total_planned_resource'] / total_planned_resource_sum) * 100
    else:
        df_metrics["Given Weight"] = 0
    
    # Calculate Adjusted Actual values based on user's formula.
    df_metrics['adjusted_manpower'] = df_metrics.apply(
        lambda row: calculate_adjusted_value(row['planned_manpower'], row['manpower_used']), axis=1
    )
    df_metrics['adjusted_time'] = df_metrics.apply(
        lambda row: calculate_adjusted_value(row['planned_time'], row['total_time']), axis=1
    )
    df_metrics['adjusted_activities'] = df_metrics['actual_activities']
    
    # Calculate Actual Resource Sum for each task
    df_metrics['total_actual_resource'] = df_metrics['adjusted_activities'] + df_metrics['adjusted_manpower'] + df_metrics['adjusted_time']
    
    # Calculate Actual Weight as a proportion of the Given Weight
    # based on the ratio of actual to planned resources for that task
    df_metrics['Actual Weight'] = df_metrics.apply(
        lambda row: (row['total_actual_resource'] / row['total_planned_resource']) * row['Given Weight'] if row['total_planned_resource'] > 0 else 0,
        axis=1
    )
    
    # Calculate Efficiency (%) based on Actual and Given Weight.
    # The upper limit is no longer capped at 100%.
    df_metrics['Efficiency (%)'] = df_metrics.apply(
        lambda row: (row['Actual Weight'] / row['Given Weight']) * 100 if row['Given Weight'] > 0 else 0, axis=1
    )

    # --- NEW: expose attachment columns for manager visibility & CSV ---
    df_metrics['attached_file_filename'] = df_metrics.get('attached_file', pd.Series([{}]*len(df_metrics))).apply(
        lambda f: (f or {}).get('filename') if isinstance(f, dict) else None
    )
    df_metrics['attached_file_filetype'] = df_metrics.get('attached_file', pd.Series([{}]*len(df_metrics))).apply(
        lambda f: (f or {}).get('filetype') if isinstance(f, dict) else None
    )
    df_metrics['attached_file_data_b64'] = df_metrics.get('attached_file', pd.Series([{}]*len(df_metrics))).apply(
        lambda f: (f or {}).get('data_b64') if isinstance(f, dict) else None
    )
    
    cols = ['id', 'reporter', 'report_date', 'functional_location', 'specific_location',
            'maintenance_type', 'equipment', 'affected_part',
            'condition_observed', 'diagnosis', 'damage_type', 'action_taken',
            'status', 'safety_condition',
            'planned_activities', 'actual_activities', 'manpower_used', 'total_time',
            'planned_manpower', 'planned_time', 'Given Weight', 'Actual Weight', 'Efficiency (%)',
            'attached_file_filename', 'attached_file_filetype', 'attached_file_data_b64']
    
    return df_metrics[cols]

def create_csv_download_link(df, filename="reports.csv"):
    """Generates a link to download the given DataFrame as a CSV file."""
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download all reports as CSV</a>'
    return href

def show_detailed_report(report_id, df):
    """Displays a detailed view of a single report with comments."""
    report = df[df['id'] == report_id].iloc[0]
    st.header(f"Report Details: {report['id']}")
    
    # --- NEW: Download this report as PDF ---
    pdf_bytes = _report_to_pdf_bytes(report.to_dict())
    st.download_button(
        label="📄 Download Report as PDF",
        data=pdf_bytes,
        file_name=f"report_{report['id']}.pdf",
        mime="application/pdf",
        key=f"pdf_dl_{report['id']}"
    )

    if st.button("⬅️ Back to Reports"):
        st.session_state.selected_report_id = None
        st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("General Information")
        st.write(f"**Reporter:** {report.get('reporter', 'N/A')}")
        st.write(f"**Report Date:** {report.get('report_date', 'N/A')}")
        st.write(f"**Functional Location:** {report.get('functional_location', 'N/A')}")
        st.write(f"**Specific Location:** {report.get('specific_location', 'N/A')}")
        st.write(f"**Maintenance Type:** {report.get('maintenance_type', 'N/A')}")

    with col2:
        st.subheader("Problem & Action")
        st.write(f"**Equipment:** {report.get('equipment', 'N/A')}")
        st.write(f"**Affected Part:** {report.get('affected_part', 'N/A')}")
        st.write(f"**Condition Observed:** {report.get('condition_observed', 'N/A')}")
        st.write(f"**Diagnosis:** {report.get('diagnosis', 'N/A')}")
        st.write(f"**Damage Type:** {report.get('damage_type', 'N/A')}")
        st.write(f"**Action Taken:** {report.get('action_taken', 'N/A')}")

    st.subheader("Status and Metrics")
    st.write(f"**Status:** {report.get('status', 'N/A')}")
    st.write(f"**Safety Condition:** {report.get('safety_condition', 'N/A')}")
    st.write(f"**Planned Activities:** {report.get('planned_activities', 'N/A')}")
    st.write(f"**Actual Activities Done:** {report.get('actual_activities', 'N/A')}")
    st.write(f"**Manpower Used:** {report.get('manpower_used', 'N/A')}")
    st.write(f"**Total Time Used (hours):** {report.get('total_time', 'N/A')}")
    
    # Display and allow download of attached file
    if 'attached_file' in report and report['attached_file']:
        file_info = report['attached_file']
        st.subheader("Attached File")
        try:
            file_bytes = base64.b64decode(file_info['data_b64'])
            if file_info['filetype'].startswith('image'):
                st.image(file_bytes, caption=file_info['filename'])
            else:
                st.info(f"File: {file_info['filename']} ({file_info['filetype']})")
            
            st.download_button(
                label="Download Attached File",
                data=file_bytes,
                file_name=file_info['filename'],
                mime=file_info['filetype'],
                key=f"dl_{report_id}"
            )
        except (base64.binascii.Error, TypeError) as e:
            st.warning(f"Could not display attached file. Data may be corrupted. {e}")

    # --- Comments Section ---
    st.subheader("Comments")
    comment_box = st.text_area("Add a comment:", key=f"comment_box_{report_id}")
    if st.button("Post Comment", key=f"post_comment_button_{report_id}"):
        if comment_box:
            add_comment_to_report(report_id, st.session_state.user['username'], comment_box)
            st.rerun()

    # Display comments in real-time
    comments = get_comments_for_report(report_id)
    if comments:
        for comment in comments:
            st.markdown(f"**{comment['user']}**: {comment['comment']}", unsafe_allow_html=True)
    else:
        st.info("No comments yet. Be the first to add one!")


# --- 🖥️ Streamlit UI Components ---

def show_login_signup():
    """Displays the login and signup forms in the sidebar."""
    st.markdown(
        """
        <style>
        .title-font {
            font-family: "Times New Roman";
            font-size: 20px;
        }
        .body-font {
            font-family: "Times New Roman";
            font-size: 16px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    col1 = st.columns([1])[0]
    
    with col1:
        st.markdown("<h3 class='title-font'>Introduction</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>The Tekeze Hydropower Plant Maintenance Tracker is a digital platform designed to modernize maintenance reporting and coordination. It enables real-time tracking of mechanical, electrical, and civil activities, reduces paperwork, and enhances accountability. If proven reliable and fully functional at Tekeze, the system can be scaled across Ethiopian Electric Power (EEP) to standardize maintenance processes, strengthen performance monitoring, and improve decision-making for all power generation plants.</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>🌍 Vision</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>“To be a model of smart, reliable, and transparent maintenance management that ensures the sustainable performance of Tekeze Hydropower Plant and sets a foundation for system-wide adoption across EEP.”</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>🎯 Mission</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>“To simplify, digitalize, and enhance maintenance reporting by fostering accountability, efficiency, and data-driven decision-making across all teams — with the potential to unify and standardize maintenance practices throughout Ethiopian Electric Power.”</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>Strategic Benefits of the Maintenance Tracker</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>The Maintenance Tracker provides EEP with improved reliability by minimizing downtime, reducing paperwork, and enhancing staff efficiency. It ensures accountability and transparency across mechanical, electrical, and civil teams while offering real-time data for better decision-making. By lowering maintenance costs, supporting knowledge retention, and creating a scalable system that can be expanded to other power plants, this tool delivers strategic value to EEP in achieving operational excellence.</p>", unsafe_allow_html=True)
    
    st.sidebar.markdown(
        """
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; margin-bottom: 20px;">
            <div style="text-align: center;">
                <img src="https://placehold.co/100x100/A1C4FD/ffffff?text=EEP+Logo" alt="EEP Logo" style="width: 100px; height: 100px; margin-bottom: 10px;">
                <span style="font-size: 14px; font-weight: bold;">Gebremedhin Hagos</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.sidebar.subheader("Login / Sign Up")
    menu = ["Login", "Sign Up"]
    choice = st.sidebar.radio("Menu", menu)

    if choice == "Sign Up":
        st.sidebar.subheader("Create New Account")
        new_user = st.sidebar.text_input("Username", key="reg_user")
        new_pass = st.sidebar.text_input("Password", type="password", key="reg_pass")
        new_first_name = st.sidebar.text_input("First Name", key="reg_first")
        new_last_name = st.sidebar.text_input("Last Name", key="reg_last")
        new_email = st.sidebar.text_input("Email", key="reg_email")
        new_user_type = st.sidebar.selectbox("User Type", ["Maintenance Staff", "Operator", "Manager"])
        if st.sidebar.button("Create Account"):
            try:
                if register_user(new_user, new_pass, new_first_name, new_last_name, new_user_type, new_email):
                    st.rerun()
            except Exception as e:
                st.error(f"Registration failed: {e}")

    elif choice == "Login":
        st.sidebar.subheader("Login to your Account")
        username = st.sidebar.text_input("Username", key="login_user")
        password = st.sidebar.text_input("Password", type="password", key="login_pass")
        if st.sidebar.button("Login"):
            try:
                if login_user(username, password):
                    st.rerun()
                else:
                    st.sidebar.error("Invalid username or password.")
            except Exception as e:
                st.error(f"Login failed: {e}")

def show_main_app():
    """Displays the main application interface after a user logs in."""
    st.sidebar.write(f"Logged in as: **{st.session_state.user['first_name']} {st.session_state.user['last_name']}**")
    
    app_mode = st.sidebar.radio("Navigation", ["Submit Report", "My Reports", "Manager Dashboard", "Account Settings"])
    
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    if app_mode == "Submit Report":
        show_report_form()
    elif app_mode == "My Reports":
        show_my_reports(st.session_state.user['username'])
    elif app_mode == "Manager Dashboard":
        if st.session_state.user['user_type'] == "Manager":
            show_manager_dashboard()
        else:
            st.error("You do not have permission to view this dashboard.")
    elif app_mode == "Account Settings":
        show_account_settings()

def show_account_settings():
    """Displays the account settings page for a user to change their password."""
    st.header("🔑 Change Your Password")
    
    with st.form("change_password_form"):
        old_password = st.text_input("Enter your old password", type="password")
        new_password = st.text_input("Enter your new password", type="password")
        confirm_password = st.text_input("Confirm your new password", type="password")
        
        submitted = st.form_submit_button("Change Password")
        
        if submitted:
            if not old_password or not new_password or not confirm_password:
                st.error("All fields are required.")
            elif new_password != confirm_password:
                st.error("New passwords do not match.")
            else:
                if change_password(st.session_state.user['username'], old_password, new_password):
                    st.success("✅ Password changed successfully!")
                else:
                    st.error("❌ Failed to change password. Please check your old password and try again.")
    st.info("To recover a forgotten password, please contact an administrator.")

def show_report_form():
    """Displays the maintenance report submission form."""
    try:
        st.image("dam.jpg", use_container_width=True)
    except FileNotFoundError:
        st.image("https://placehold.co/600x200/A1C4FD/ffffff?text=Dam+Image", use_container_width=True)

    st.title("🛠️ Maintenance Report Form")

    with st.form("report_form", clear_on_submit=True):
        st.header("Report Details")
        start_date = st.date_input("Date of duty start", datetime.date.today())
        functional_location = st.selectbox("Functional Location", ["Powerhouse", "Dam", "Switch Yard", "Access road", "Garage", "Dwelling"])
        specific_location = st.selectbox("Specific Location", ["Unit 1", "Unit 2", "Unit 3", "Unit 4", "Common system", "Spillway", "Intake gate", "Trash rack crane", "Diesel generator", "Bonnet gate", "Substation", "SYD control room", "Step down transformer", "Water supply", "Road", "Employee camp", "China camp", "Wanboo camp", "Garage", "Others"])
        maintenance_type = st.selectbox("Maintenance Type", ["Inspection", "Preventive Maintenance", "Emergency/Breakdown/Corrective"])

        st.header("Problem and Action")
        equipment = st.text_input("Name of Equipment")
        affected_part = st.text_input("Affected Part")
        condition_observed = st.text_area("Condition Observed")
        diagnosis = st.text_area("Diagnosis")
        damage_type = st.text_input("Damage Type")
        action_taken = st.text_area("Action Taken")
        
        st.header("Status and Safety")
        status = st.selectbox("Status", ["Fully functional", "Functional but needs monitoring", "Temporarily functional (risk present)", "Not functional"])
        safety_condition = st.selectbox("Safety Condition", ["Safely completed", "Unsafe condition was observed", "Maintenance planform was not good"])
        
        st.header("Resources and Metrics")
        planned_activities = st.number_input("Planned Activities", min_value=0, step=1)
        manpower_used = st.number_input("Manpower Used", min_value=0, step=1)
        total_time = st.number_input("Total Time Used (hours)", min_value=0.0, step=0.5)
        actual_activities = st.number_input("Actual Activities Done", min_value=0, step=1)
        
        st.header("Attachments")
        uploaded_file = st.file_uploader("Attach Photo/Document", type=["jpg", "jpeg", "png", "pdf"], help="Supports JPG, PNG, and PDF. Max 1 MB file size per file.")
        
        submitted = st.form_submit_button("Submit Report")

        if submitted:
            report_data = {
                'reporter': st.session_state.user['username'],
                'report_date': start_date.isoformat(),
                'functional_location': functional_location,
                'specific_location': specific_location,
                'maintenance_type': maintenance_type,
                'equipment': equipment,
                'affected_part': affected_part,
                'condition_observed': condition_observed,
                'diagnosis': diagnosis,
                'damage_type': damage_type,
                'action_taken': action_taken,
                'status': status,
                'safety_condition': safety_condition,
                'planned_activities': planned_activities,
                'manpower_used': manpower_used,
                'total_time': total_time,
                'actual_activities': actual_activities,
                'planned_manpower': 0,
                'planned_time': 0.0,
            }
            if uploaded_file is not None:
                file_bytes = uploaded_file.getvalue()
                if len(file_bytes) > 1024 * 1024:
                    st.error("❌ The attached file is too large. Please upload a file smaller than 1 MB.")
                else:
                    # NEW: ensure filename is not a long path
                    safe_name = os.path.basename(uploaded_file.name)
                    encoded_string = base64.b64encode(file_bytes).decode('utf-8')
                    report_data['attached_file'] = {
                        'filename': safe_name,
                        'filetype': uploaded_file.type,
                        'data_b64': encoded_string
                    }
                    if insert_report(report_data):
                        st.success("✅ Report submitted successfully!")
                    else:
                        st.error("❌ Failed to submit report. Please try again.")
            else:
                if insert_report(report_data):
                    st.success("✅ Report submitted successfully!")
                else:
                    st.error("❌ Failed to submit report. Please try again.")

def show_my_reports(username):
    """Displays a table of the user's submitted reports with search and filter, plus edit/delete (NEW)."""
    
    st.subheader("My Reports")
    
    if st.session_state.selected_report_id:
        df = get_reports(username)
        show_detailed_report(st.session_state.selected_report_id, df)
        return

    df = get_reports(username)
    if not df.empty:
        # Filtering and Search
        search_query = st.text_input("Search reports by equipment or location...", "")
        filtered_df = df[df.apply(lambda row: search_query.lower() in str(row['equipment']).lower() or search_query.lower() in str(row['functional_location']).lower(), axis=1)]
        
        # Display the filtered dataframe
        if not filtered_df.empty:
            st.markdown("---")
            st.subheader("All My Submitted Reports")
            
            # Use st.expander to show details, edit, delete for each report
            for index, row in filtered_df.iterrows():
                with st.expander(f"[{row['id']}] {row['equipment']} — {row['report_date']}", expanded=False):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Report ID:** {row['id']}")
                        st.write(f"**Functional Location:** {row['functional_location']}")
                        st.write(f"**Specific Location:** {row['specific_location']}")
                        st.write(f"**Maintenance Type:** {row['maintenance_type']}")
                        st.write(f"**Equipment:** {row['equipment']}")
                        st.write(f"**Affected Part:** {row['affected_part']}")
                        st.write(f"**Condition Observed:** {row['condition_observed']}")
                    with col2:
                        st.write(f"**Diagnosis:** {row['diagnosis']}")
                        st.write(f"**Damage Type:** {row['damage_type']}")
                        st.write(f"**Action Taken:** {row['action_taken']}")
                        st.write(f"**Status:** {row['status']}")
                        st.write(f"**Safety Condition:** {row['safety_condition']}")
                        st.write(f"**Planned Activities:** {row['planned_activities']}")
                        st.write(f"**Actual Activities Done:** {row['actual_activities']}")
                        st.write(f"**Manpower Used:** {row['manpower_used']}")
                        st.write(f"**Total Time Used (hours):** {row['total_time']}")
                        if 'attached_file' in row and row['attached_file']:
                            st.write(f"**Attached File:** {row['attached_file'].get('filename')}")

                    # --- NEW: Edit form for reporter ---
                    with st.form(key=f"edit_form_{row['id']}"):
                        st.markdown("**Edit Your Report**")
                        e_start_date = st.date_input("Date of duty start", datetime.date.fromisoformat(row['report_date']) if row.get('report_date') else datetime.date.today(), key=f"ed_date_{row['id']}")
                        e_functional_location = st.selectbox("Functional Location", ["Powerhouse", "Dam", "Switch Yard", "Access road", "Garage", "Dwelling"], index=max(0, ["Powerhouse", "Dam", "Switch Yard", "Access road", "Garage", "Dwelling"].index(row['functional_location']) if row.get('functional_location') in ["Powerhouse", "Dam", "Switch Yard", "Access road", "Garage", "Dwelling"] else 0), key=f"ed_funloc_{row['id']}")
                        e_specific_location = st.selectbox("Specific Location", ["Unit 1", "Unit 2", "Unit 3", "Unit 4", "Common system", "Spillway", "Intake gate", "Trash rack crane", "Diesel generator", "Bonnet gate", "Substation", "SYD control room", "Step down transformer", "Water supply", "Road", "Employee camp", "China camp", "Wanboo camp", "Garage", "Others"], index=max(0, ["Unit 1", "Unit 2", "Unit 3", "Unit 4", "Common system", "Spillway", "Intake gate", "Trash rack crane", "Diesel generator", "Bonnet gate", "Substation", "SYD control room", "Step down transformer", "Water supply", "Road", "Employee camp", "China camp", "Wanboo camp", "Garage", "Others"].index(row['specific_location']) if row.get('specific_location') in ["Unit 1", "Unit 2", "Unit 3", "Unit 4", "Common system", "Spillway", "Intake gate", "Trash rack crane", "Diesel generator", "Bonnet gate", "Substation", "SYD control room", "Step down transformer", "Water supply", "Road", "Employee camp", "China camp", "Wanboo camp", "Garage", "Others"] else 0), key=f"ed_specloc_{row['id']}")
                        e_maintenance_type = st.selectbox("Maintenance Type", ["Inspection", "Preventive Maintenance", "Emergency/Breakdown/Corrective"], index=max(0, ["Inspection", "Preventive Maintenance", "Emergency/Breakdown/Corrective"].index(row['maintenance_type']) if row.get('maintenance_type') in ["Inspection", "Preventive Maintenance", "Emergency/Breakdown/Corrective"] else 0), key=f"ed_mtype_{row['id']}")
                        e_equipment = st.text_input("Name of Equipment", value=row.get('equipment', ''), key=f"ed_eq_{row['id']}")
                        e_affected_part = st.text_input("Affected Part", value=row.get('affected_part', ''), key=f"ed_aff_{row['id']}")
                        e_condition_observed = st.text_area("Condition Observed", value=row.get('condition_observed', ''), key=f"ed_cond_{row['id']}")
                        e_diagnosis = st.text_area("Diagnosis", value=row.get('diagnosis', ''), key=f"ed_diag_{row['id']}")
                        e_damage_type = st.text_input("Damage Type", value=row.get('damage_type', ''), key=f"ed_dmg_{row['id']}")
                        e_action_taken = st.text_area("Action Taken", value=row.get('action_taken', ''), key=f"ed_act_{row['id']}")
                        e_status = st.selectbox("Status", ["Fully functional", "Functional but needs monitoring", "Temporarily functional (risk present)", "Not functional"], index=max(0, ["Fully functional", "Functional but needs monitoring", "Temporarily functional (risk present)", "Not functional"].index(row['status']) if row.get('status') in ["Fully functional", "Functional but needs monitoring", "Temporarily functional (risk present)", "Not functional"] else 0), key=f"ed_status_{row['id']}")
                        e_safety_condition = st.selectbox("Safety Condition", ["Safely completed", "Unsafe condition was observed", "Maintenance planform was not good"], index=max(0, ["Safely completed", "Unsafe condition was observed", "Maintenance planform was not good"].index(row['safety_condition']) if row.get('safety_condition') in ["Safely completed", "Unsafe condition was observed", "Maintenance planform was not good"] else 0), key=f"ed_safe_{row['id']}")
                        e_planned_activities = st.number_input("Planned Activities", min_value=0, step=1, value=int(row.get('planned_activities', 0)), key=f"ed_plact_{row['id']}")
                        e_manpower_used = st.number_input("Manpower Used", min_value=0, step=1, value=int(row.get('manpower_used', 0)), key=f"ed_manu_{row['id']}")
                        e_total_time = st.number_input("Total Time Used (hours)", min_value=0.0, step=0.5, value=float(row.get('total_time', 0.0)), key=f"ed_ttime_{row['id']}")
                        e_actual_activities = st.number_input("Actual Activities Done", min_value=0, step=1, value=int(row.get('actual_activities', 0)), key=f"ed_actact_{row['id']}")

                        # Optional: replace attachment when editing
                        e_uploaded_file = st.file_uploader("Replace Attachment (optional)", type=["jpg", "jpeg", "png", "pdf"], key=f"ed_upload_{row['id']}")

                        save_changes = st.form_submit_button("💾 Save Changes")
                        if save_changes:
                            updated = {
                                'report_date': e_start_date.isoformat(),
                                'functional_location': e_functional_location,
                                'specific_location': e_specific_location,
                                'maintenance_type': e_maintenance_type,
                                'equipment': e_equipment,
                                'affected_part': e_affected_part,
                                'condition_observed': e_condition_observed,
                                'diagnosis': e_diagnosis,
                                'damage_type': e_damage_type,
                                'action_taken': e_action_taken,
                                'status': e_status,
                                'safety_condition': e_safety_condition,
                                'planned_activities': int(e_planned_activities),
                                'manpower_used': int(e_manpower_used),
                                'total_time': float(e_total_time),
                                'actual_activities': int(e_actual_activities),
                            }
                            if e_uploaded_file is not None:
                                bytes_new = e_uploaded_file.getvalue()
                                if len(bytes_new) > 1024 * 1024:
                                    st.error("❌ The attached file is too large. Please upload a file smaller than 1 MB.")
                                else:
                                    updated['attached_file'] = {
                                        'filename': os.path.basename(e_uploaded_file.name),
                                        'filetype': e_uploaded_file.type,
                                        'data_b64': base64.b64encode(bytes_new).decode('utf-8')
                                    }
                            if update_full_report(row['id'], updated):
                                st.success("✅ Report updated.")
                                st.rerun()
                            else:
                                st.error("❌ Failed to update report.")

                    # --- NEW: Delete button for reporter ---
                    del_col1, del_col2 = st.columns(2)
                    with del_col1:
                        if st.button("🗑️ Delete This Report", key=f"del_{row['id']}"):
                            if delete_report(row['id']):
                                st.success(f"Report {row['id']} deleted.")
                                st.rerun()
                            else:
                                st.error("❌ Delete failed.")
                    with del_col2:
                        if st.button("🔍 View Details", key=f"view_{row['id']}"):
                            st.session_state.selected_report_id = row['id']
                            st.rerun()

            st.markdown("---")
            # CSV download link for reporters
            st.markdown(create_csv_download_link(filtered_df), unsafe_allow_html=True)
        else:
            st.info("No reports found matching your search criteria.")
    else:
        st.info("You haven't submitted any reports yet.")

def show_manager_dashboard():
    """Displays the manager dashboard with all reports, efficiency metrics, charts, and data export."""
    st.subheader("Manager Dashboard")

    if st.session_state.selected_report_id:
        df = get_reports()
        show_detailed_report(st.session_state.selected_report_id, df)
        return

    df_all = get_reports()
    if not df_all.empty:
        df_metrics = calculate_metrics(df_all)

        # --- Search and Filters ---
        search_query = st.text_input("Search reports by equipment or reporter...", "")
        
        locations = ["All"] + list(df_metrics['functional_location'].unique())
        selected_location = st.selectbox("Filter by Functional Location", locations)

        # Apply filters
        filtered_df = df_metrics[df_metrics.apply(lambda row: search_query.lower() in str(row['equipment']).lower() or search_query.lower() in str(row['reporter']).lower(), axis=1)]
        if selected_location != "All":
            filtered_df = filtered_df[filtered_df['functional_location'] == selected_location]
        
        if not filtered_df.empty:
            
            # --- Performance Metrics and Charts ---
            st.header("Performance Analytics")
            avg_efficiency = filtered_df["Efficiency (%)"].mean()
            st.metric("Overall Average Efficiency", f"{avg_efficiency:.2f}%")

            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Efficiency per Reporter")
                reporter_eff = filtered_df.groupby("reporter")["Efficiency (%)"].mean().reset_index()
                st.bar_chart(reporter_eff.set_index("reporter"))

            with col2:
                st.subheader("Efficiency Trends")
                filtered_df['report_date'] = pd.to_datetime(filtered_df['report_date'])
                daily_eff = filtered_df.groupby(filtered_df['report_date'].dt.date)["Efficiency (%)"].mean().reset_index()
                st.line_chart(daily_eff.set_index("report_date"))
            
            st.subheader("Breakdown of Maintenance Types")
            maintenance_counts = filtered_df['maintenance_type'].value_counts()
            st.bar_chart(maintenance_counts)
            
            # --- Data Editing and Export ---
            st.header("All Reports (Editable)")
            
            # Make a copy to avoid modifying the original DataFrame
            edited_df = filtered_df.copy()

            # Display the data editor without buttons as a separate feature
            st.markdown("Edit the **Planned Manpower** and **Planned Time** for any report below:")
            edited_data = st.data_editor(
                edited_df[['id', 'reporter', 'report_date', 'functional_location', 'equipment',
                           'planned_manpower', 'planned_time', 'manpower_used', 'total_time', 
                           'actual_activities', 'action_taken',
                           'Given Weight', 'Actual Weight', 'Efficiency (%)',
                           'attached_file_filename', 'attached_file_filetype']],
                disabled=('id', 'reporter', 'report_date', 'functional_location', 'equipment',
                          'manpower_used', 'total_time', 'actual_activities', 'action_taken',
                          'Given Weight', 'Actual Weight', 'Efficiency (%)',
                          'attached_file_filename', 'attached_file_filetype'),
                hide_index=True,
                use_container_width=True,
                key="manager_data_editor"
            )

            # Process the edited data and update Firestore
            if not edited_data[['planned_manpower', 'planned_time']].equals(edited_df[['planned_manpower', 'planned_time']]):
                for index, row in edited_data.iterrows():
                    original_row = edited_df.loc[edited_df['id'] == row['id']].iloc[0]
                    if row['planned_manpower'] != original_row['planned_manpower'] or row['planned_time'] != original_row['planned_time']:
                        update_report(row['id'], row['planned_manpower'], row['planned_time'])
                        st.success(f"Updated planned values for report {row['id']}")
                st.rerun()

            st.markdown("---")
            st.subheader("Report Actions")
            
            # Create a selection box to choose a report to view or delete
            report_options = {row['id']: f"{row['report_date']} - {row['equipment']} ({row['id']})" for _, row in filtered_df.iterrows()}
            selected_id = st.selectbox("Select a report to view or delete", options=list(report_options.keys()), format_func=lambda x: report_options[x], key="report_selector")
            
            col_view, col_delete = st.columns(2)
            with col_view:
                if st.button("View Details of Selected Report"):
                    st.session_state.selected_report_id = selected_id
                    st.rerun()
            with col_delete:
                if st.button("Delete Selected Report"):
                    if delete_report(selected_id):
                        st.success(f"Report {selected_id} and its comments have been deleted.")
                        st.session_state.selected_report_id = None
                        st.rerun()

            # --- CSV Export with Metrics at the end ---
            st.markdown("---")
            st.subheader("Download All Reports")

            # Include attachment info in the exported CSV (already part of df_metrics)
            main_csv_string = df_metrics.to_csv(index=False)
            
            # Create a summary DataFrame
            metrics_summary = pd.DataFrame([
                ['Total Reports', len(df_all)],
                ['Total Planned Manpower', df_all['planned_manpower'].sum()],
                ['Total Manpower Used', df_all['manpower_used'].sum()],
                ['Overall Avg. Efficiency (%)', df_metrics["Efficiency (%)"].mean()],
            ], columns=['Metric', 'Value'])
            
            # Convert the summary to a CSV string to append
            summary_csv_string = "\n\nPerformance Metrics Summary\n" + metrics_summary.to_csv(index=False)
            
            # Combine the main CSV and the summary CSV
            full_csv_string = main_csv_string + summary_csv_string
            
            # Create the download link with the combined content
            b64_full = base64.b64encode(full_csv_string.encode()).decode()
            href_full = f'<a href="data:file/csv;base64,{b64_full}" download="reports_with_metrics.csv">Download All Reports with Metrics as CSV</a>'
            st.markdown(href_full, unsafe_allow_html=True)
            # --- End CSV Export ---
            
        else:
            st.info("No reports found matching your search and filter criteria.")

    else:
        st.info("No reports have been submitted yet.")

# --- 🚀 Main Application Logic ---

def main():
    """Main function to run the Streamlit application."""
    # --- PWA Configuration (Added to the beginning of main) ---
    st.markdown("""
        <link rel="manifest" href="/manifest.json">
        <script>
          if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/service-worker.js').then(function(reg) {
              console.log('Service Worker registered!');
            }).catch(function(err) {
              console.log('Service Worker registration failed: ', err);
            });
          }
        </script>
    """, unsafe_allow_html=True)
    # --- App UI ---
    st.set_page_config(
        page_title="Tekeze Maintenance Tracker",
        page_icon="🛠️",
        layout="wide"
    )

    try:
        st.image("dam.jpg", use_container_width=True)
    except FileNotFoundError:
        st.warning("dam.jpg not found. Using a placeholder image.")
        st.image("https://placehold.co/600x200/A1C4FD/ffffff?text=Dam+Image", use_container_width=True)
        
    st.title("Tekeze Hydropower Plant")
    st.subheader("Maintenance Tracker")

    st.markdown("---")
    
    if not st.session_state.firebase_initialized:
        with st.spinner("Connecting to the database..."):
            if not initialize_firebase():
                return
    
    if not st.session_state.logged_in:
        show_login_signup()
    else:
        show_main_app()

if __name__ == "__main__":
    main()






























