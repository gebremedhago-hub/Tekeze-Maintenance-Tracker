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
    """Inserts a new maintenance report into the Firestore database."""
    try:
        st.session_state.db.collection('maintenance_reports').add(data)
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
        report['id'] = doc.id
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

def calculate_effective_manpower(row):
    """Calculates effective manpower based on planned vs. actual."""
    manpower_used = row["manpower_used"] if pd.notna(row["manpower_used"]) else 0
    planned_manpower = row["planned_manpower"] if pd.notna(row["planned_manpower"]) else 0

    if planned_manpower == 0:
        return 0
    
    manpower_diff = manpower_used - planned_manpower
    factor = abs(manpower_diff) / planned_manpower
    
    if manpower_diff > 0:
        return manpower_used - manpower_diff * (1 + factor)
    elif manpower_diff < 0:
        return manpower_used + abs(manpower_diff) * (1 + factor)
    else:
        return manpower_used

def calculate_effective_time(row):
    """Calculates effective time based on planned vs. actual."""
    total_time = row["total_time"] if pd.notna(row["total_time"]) else 0
    planned_time = row["planned_time"] if pd.notna(row["planned_time"]) else 0

    if planned_time == 0:
        return 0
    
    time_diff = total_time - planned_time
    factor = abs(time_diff) / planned_time
    
    if time_diff > 0:
        return total_time - time_diff * (1 + factor)
    elif time_diff < 0:
        return total_time + abs(time_diff) * (1 + factor)
    else:
        return total_time

def calculate_metrics(df):
    """Calculates all efficiency and weighted efficiency metrics."""
    df_metrics = df.copy()
    
    df_metrics['total_planned_resource'] = df_metrics['planned_manpower'].fillna(0) + df_metrics['planned_time'].fillna(0) + df_metrics['planned_activities'].fillna(0)

    last_month_start = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
    df_metrics['report_date'] = df_metrics['report_date'].apply(lambda x: x.isoformat() if isinstance(x, datetime.date) else x)
    df_last_month = df_metrics[df_metrics['report_date'] >= last_month_start].copy()
    
    total_resource_sum = df_last_month['total_planned_resource'].sum()

    df_metrics["effective_manpower"] = df_metrics.apply(calculate_effective_manpower, axis=1)
    df_metrics["effective_time"] = df_metrics.apply(calculate_effective_time, axis=1)
    df_metrics['actual_activities'] = df_metrics['actual_activities'].fillna(0)

    # Calculate Given Weight based on total planned resources
    if total_resource_sum > 0:
        df_metrics["Given Weight"] = (df_metrics['total_planned_resource'] / total_resource_sum) * 100
    else:
        df_metrics["Given Weight"] = 0
    
    # Calculate Actual Weight based on effective resources
    actual_resource_sum = (df_metrics['effective_manpower'] + df_metrics['effective_time'] + df_metrics['actual_activities']).sum()
    if actual_resource_sum > 0:
        df_metrics['Actual Weight'] = (df_metrics['effective_manpower'] + df_metrics['effective_time'] + df_metrics['actual_activities']) / actual_resource_sum * 100
    else:
        df_metrics['Actual Weight'] = 0

    df_metrics["Efficiency (%)"] = df_metrics.apply(
        lambda row: (row["Actual Weight"] / row["Given Weight"]) * 100
        if row["Given Weight"] > 0 else 0,
        axis=1
    )
    
    cols = ['id', 'reporter', 'report_date', 'functional_location', 'specific_location',
             'maintenance_type', 'equipment', 'affected_part',
             'condition_observed', 'diagnosis', 'damage_type', 'action_taken',
             'status', 'safety_condition',
             'planned_activities', 'actual_activities', 'manpower_used', 'total_time',
             'planned_manpower', 'planned_time', 'Given Weight', 'Actual Weight', 'Efficiency (%)']
    
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
                label="Download File",
                data=file_bytes,
                file_name=file_info['filename'],
                mime=file_info['filetype']
            )
        except (base64.binascii.Error, TypeError) as e:
            st.warning(f"Could not display attached file. Data may be corrupted. {e}")

    # --- Comments Section ---
    st.subheader("Comments")
    comment_box = st.text_area("Add a comment:", key="comment_box")
    if st.button("Post Comment", key="post_comment_button"):
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
        st.markdown("<h3 class='title-font'>Welcome</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>The Tekeze Hydropower Plant Maintenance Tracker app allows technicians to log field activities and equipment conditions in real time, enables engineers to verify technical details and diagnose issues, provides managers with clear oversight for decision-making and resource allocation, and supports planners & report writers in compiling accurate records for performance evaluation and future planning.</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>Mission</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>To provide reliable and sustainable electric power through innovation technology, continuous learning, fairness and commitment.</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>Vision</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>To be the power hub of africa</p>", unsafe_allow_html=True)

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
        uploaded_file = st.file_uploader("Attach Photo/Document", type=["jpg", "jpeg", "png", "pdf"], help="Supports JPG, PNG, and PDF. Max 20 MB file size per file.")
        
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
                    encoded_string = base64.b64encode(file_bytes).decode('utf-8')
                    report_data['attached_file'] = {
                        'filename': uploaded_file.name,
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
    """Displays a table of the user's submitted reports with search and filter."""
    
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
            # Display a data editor for reporters to view their reports
            st.markdown("---")
            st.subheader("All Reports (View-Only)")
            
            # Use st.data_editor with disabled columns for a read-only view
            st.data_editor(
                filtered_df[['id', 'reporter', 'report_date', 'functional_location', 'equipment', 'status', 'action_taken']],
                column_order=['reporter', 'report_date', 'functional_location', 'equipment', 'status', 'action_taken'],
                disabled=True,
                hide_index=True,
                use_container_width=True
            )
            
            # CSV download link for reporters
            st.markdown(create_csv_download_link(filtered_df), unsafe_allow_html=True)
            st.markdown("---")

            for index, row in filtered_df.iterrows():
                with st.expander(f"Report for: {row['equipment']} on {row['report_date']}"):
                    show_detailed_report(row['id'], filtered_df)
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

            # The original code has an error here. Streamlit doesn't have a direct `st.column_config.ButtonColumn`.
            # We'll use the button functionality with a key based on the index to handle clicks.
            st.info("To view or delete a report, use the buttons below the data table.")
            
            # Define which columns are editable
            column_config = {
                "planned_manpower": st.column_config.NumberColumn("Planned Manpower", required=True),
                "planned_time": st.column_config.NumberColumn("Planned Time (hrs)", required=True),
            }

            # Display the data editor
            editable_cols = ['id', 'reporter', 'report_date', 'functional_location', 'equipment',
                             'planned_manpower', 'planned_time', 'Given Weight', 'Actual Weight',
                             'Efficiency (%)']
            
            edited_data = st.data_editor(
                edited_df[editable_cols],
                column_config=column_config,
                hide_index=True,
                use_container_width=True
            )

            # Process the edited data
            if not edited_data.equals(edited_df[editable_cols]):
                st.write("Processing updates...")
                for index, row in edited_data.iterrows():
                    original_row = edited_df.loc[edited_df['id'] == row['id']].iloc[0]
                    if row['planned_manpower'] != original_row['planned_manpower'] or row['planned_time'] != original_row['planned_time']:
                        update_report(row['id'], row['planned_manpower'], row['planned_time'])
                        st.success(f"Updated planned values for report {row['id']}")
                st.rerun()

            # Handle button clicks separately
            st.markdown("---")
            st.subheader("Report Actions")
            col_buttons = st.columns(2)
            
            # Create an action for each row to view/delete
            for index, row in filtered_df.iterrows():
                with col_buttons[index % 2]: # Distribute buttons across two columns
                    if st.button(f"View Details: {row['equipment']}", key=f"view_{row['id']}"):
                        st.session_state.selected_report_id = row['id']
                        st.rerun()
                    if st.button(f"Delete Report: {row['equipment']}", key=f"delete_{row['id']}"):
                        if delete_report(row['id']):
                            st.success(f"Report {row['id']} and its comments have been deleted.")
                            st.rerun()
            
            # CSV Download Link
            st.markdown("---")
            st.markdown(create_csv_download_link(filtered_df), unsafe_allow_html=True)

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
              console.error('Service Worker registration failed:', err);
            });
          }
        </script>
    """, unsafe_allow_html=True)

    st.set_page_config(
        page_title="Tekeze Maintenance Tracker",
        page_icon="🛠️",
        layout="wide"
    )

    if initialize_firebase():
        if not st.session_state.logged_in:
            show_login_signup()
        else:
            show_main_app()

if __name__ == "__main__":
    main()











