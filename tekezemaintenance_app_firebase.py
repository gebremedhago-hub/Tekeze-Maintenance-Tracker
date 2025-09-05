import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import pandas as pd
import json
import datetime
import math

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

# --- Firebase Setup ---

def initialize_firebase():
    """
    Initializes Firebase credentials from Streamlit secrets.
    Returns True if successful, False otherwise.
    
    This function first checks if Firebase is already initialized to avoid
    re-initializing it every time a user interacts with the app.
    
    It then attempts to load the `firebase_config` from Streamlit's secrets,
    which is the secure way to manage credentials in a hosted environment.
    """
    if st.session_state.firebase_initialized:
        return True
    
    try:
        # Step 1: Access the secure Firebase configuration from Streamlit Secrets.
        # This will fail if the `firebase_config` key is not in your secrets.toml file.
        firebase_config = st.secrets["firebase_config"]
        
        # Step 2: Check if a Firebase app instance has already been created.
        # `_apps` is an internal dictionary of initialized apps.
        if not firebase_admin._apps:
            # Step 3: Create a credentials object from the config dictionary.
            # This is what Firebase uses to authenticate with your project.
            cred = credentials.Certificate(firebase_config)
            
            # Step 4: Initialize the Firebase app with the credentials.
            firebase_admin.initialize_app(cred)
            
        # Step 5: Get a Firestore client instance and store it in session state.
        st.session_state.db = firestore.client()
        st.session_state.firebase_initialized = True
        return True
    except KeyError:
        # This is the error you are currently facing. It means Streamlit can't
        # find the `firebase_config` key in the secrets.
        st.error("Firebase configuration not found. Please ensure 'firebase_config' is set in Streamlit Secrets.")
        return False
    except Exception as e:
        # A more general catch for other potential errors during initialization.
        st.error(f"Error initializing Firebase: {e}")
        return False

# --- User Authentication Functions ---

def login_user(username, password):
    """
    Authenticates a user against the Firestore database.
    """
    # Use Firestore to get the document for the given username.
    user_ref = st.session_state.db.collection('users').document(username)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        hashed_password = user_data.get('password')
        # Use bcrypt to securely check the entered password against the stored hash.
        if hashed_password and bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            st.session_state.logged_in = True
            st.session_state.user = user_data
            return True
    return False

def register_user(username, password, first_name, last_name, user_type):
    """Registers a new user in the Firestore database."""
    # Hash the password before saving for security.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_data = {
        'username': username,
        'password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'user_type': user_type
    }
    # Save the new user document to the 'users' collection.
    user_ref = st.session_state.db.collection('users').document(username)
    user_ref.set(user_data)
    st.success("Registration successful! Please log in.")
    return True

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

def get_reports(username=None):
    """Fetches reports from the Firestore database. Fetches all if username is None."""
    reports_ref = st.session_state.db.collection('maintenance_reports')
    if username:
        # Build a query to fetch reports for a specific user.
        query = reports_ref.where('reporter', '==', username).order_by('report_date', direction=firestore.Query.DESCENDING)
    else:
        # Build a query to fetch all reports.
        query = reports_ref.order_by('report_date', direction=firestore.Query.DESCENDING)

    reports_list = []
    # Stream the documents from the query result.
    for doc in query.stream():
        report = doc.to_dict()
        report['id'] = doc.id
        reports_list.append(report)
    
    return pd.DataFrame(reports_list)

# --- 📊 Data Analysis Functions ---

def calculate_metrics(df):
    """Calculates all efficiency and weighted efficiency metrics based on the new logic."""
    df_metrics = df.copy()
    
    # Calculate total planned resources for each report first
    df_metrics['total_planned_resource'] = df_metrics['planned_manpower'].fillna(0) + df_metrics['planned_time'].fillna(0) + df_metrics['planned_activities'].fillna(0)

    # Filter reports for the last 30 days
    last_month_start = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
    # Ensure 'report_date' is a string before comparison
    df_metrics['report_date'] = df_metrics['report_date'].apply(lambda x: x.isoformat() if isinstance(x, datetime.date) else x)
    df_last_month = df_metrics[df_metrics['report_date'] >= last_month_start].copy()
    
    # Calculate the sum of total planned resources for the last month only
    total_resource_sum = df_last_month['total_planned_resource'].sum()

    # Apply the dynamic factors for manpower and time
    def calculate_effective_manpower(row):
        manpower_diff = row["manpower_used"].fillna(0) - row["planned_manpower"].fillna(0)
        if row["planned_manpower"].fillna(0) == 0:
            return 0
        
        factor = abs(manpower_diff) / row["planned_manpower"]
        
        if manpower_diff > 0: # Over-used manpower (punish)
            return row["manpower_used"] - manpower_diff * (1 + factor)
        elif manpower_diff < 0: # Under-used manpower (reward)
            return row["manpower_used"] + abs(manpower_diff) * (1 + factor)
        else: # Perfect match
            return row["manpower_used"]

    def calculate_effective_time(row):
        time_diff = row["total_time"].fillna(0) - row["planned_time"].fillna(0)
        if row["planned_time"].fillna(0) == 0:
            return 0
        
        factor = abs(time_diff) / row["planned_time"]
        
        if time_diff > 0: # Over-used time (punish)
            return row["total_time"] - time_diff * (1 + factor)
        elif time_diff < 0: # Under-used time (reward)
            return row["total_time"] + abs(time_diff) * (1 + factor)
        else: # Perfect match
            return row["total_time"]
            
    df_metrics["effective_manpower"] = df_metrics.apply(calculate_effective_manpower, axis=1)
    df_metrics["effective_time"] = df_metrics.apply(calculate_effective_time, axis=1)
    df_metrics['actual_activities'] = df_metrics['actual_activities'].fillna(0)

    if total_resource_sum > 0:
        # Calculate Given Weight for each report in the last month
        df_metrics["Given Weight"] = (df_metrics['total_planned_resource'] / total_resource_sum) * 100
        
        # Calculate Actual Weight using effective resources
        df_metrics['actual_resource_sum'] = df_metrics['effective_manpower'] + df_metrics['effective_time'] + df_metrics['actual_activities']
        df_metrics["Actual Weight"] = (df_metrics['actual_resource_sum'] / total_resource_sum) * 100
        
    else:
        df_metrics["Given Weight"] = 0
        df_metrics["Actual Weight"] = 0

    # Calculate final efficiency
    df_metrics["Efficiency (%)"] = df_metrics.apply(
        lambda row: (row["Actual Weight"] / row["Given Weight"]) * 100
        if row["Given Weight"] > 0 else 0,
        axis=1
    )
    
    # Re-order columns for better viewing
    cols = ['id', 'reporter', 'start_date', 'functional_location', 'specific_location',
            'maintenance_type', 'equipment', 'affected_part',
            'condition_observed', 'diagnosis', 'damage_type', 'action_taken',
            'status', 'safety_condition',
            'planned_activities', 'actual_activities', 'manpower_used', 'total_time',
            'planned_manpower', 'planned_time', 'Given Weight', 'Actual Weight', 'Efficiency (%)']
    
    return df_metrics[cols]

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
    
    # Place text and developer info in columns
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("<h3 class='title-font'>Welcome</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>The Tekeze Hydropower Plant Maintenance Tracker app allows technicians to log field activities and equipment conditions in real time, enables engineers to verify technical details and diagnose issues, provides managers with clear oversight for decision-making and resource allocation, and supports planners & report writers in compiling accurate records for performance evaluation and future planning.</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>Mission</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>To provide reliable and sustainable electric power through innovation technology, continuous learning, fairness and commitment.</p>", unsafe_allow_html=True)
        st.markdown("<h3 class='title-font'>Vision</h3>", unsafe_allow_html=True)
        st.markdown("<p class='body-font'>To be the power hub of africa</p>", unsafe_allow_html=True)

    with col2:
        st.markdown(
            """
            <div style="display: flex; align-items: center; justify-content: flex-end; margin-top: 10px;">
                <img src="https://placehold.co/30x30/000000/FFFFFF/png?text=GH" alt="Developer" style="width: 30px; height: 30px; border-radius: 50%; margin-right: 5px;">
                <span style="font-size: 14px;">Gebremedhin Hagos</span>
            </div>
            """,
            unsafe_allow_html=True
        )
        
    st.sidebar.subheader("Login / Sign Up")
    menu = ["Login", "Sign Up"]
    choice = st.sidebar.radio("Menu", menu)

    if choice == "Sign Up":
        st.sidebar.subheader("Create New Account")
        new_user = st.sidebar.text_input("Username")
        new_pass = st.sidebar.text_input("Password", type="password")
        new_first_name = st.sidebar.text_input("First Name")
        new_last_name = st.sidebar.text_input("Last Name")
        new_user_type = st.sidebar.selectbox("User Type", ["Maintenance Staff", "Operator", "Manager"])
        if st.sidebar.button("Create Account"):
            try:
                if register_user(new_user, new_pass, new_first_name, new_last_name, new_user_type):
                    st.rerun()
            except Exception as e:
                st.error(f"Registration failed: {e}")

    elif choice == "Login":
        st.sidebar.subheader("Login to your Account")
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
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
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    if st.session_state.user['user_type'] == "Manager":
        app_mode = st.sidebar.radio("Navigation", ["Submit Report", "My Reports", "Manager Dashboard"])
    else:
        app_mode = st.sidebar.radio("Navigation", ["Submit Report", "My Reports"])

    if app_mode == "Submit Report":
        show_report_form()
    elif app_mode == "My Reports":
        show_my_reports(st.session_state.user['username'])
    elif app_mode == "Manager Dashboard":
        if st.session_state.user['user_type'] == "Manager":
            show_manager_dashboard()
        else:
            st.error("You do not have permission to view this dashboard.")

def show_report_form():
    """Displays the maintenance report submission form."""
    try:
        st.image("dam.jpg", width='stretch')
    except FileNotFoundError:
        st.image("https://placehold.co/600x200/A1C4FD/ffffff?text=Dam+Image", width='stretch')

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
                'planned_manpower': 0, # Placeholder for manager input
                'planned_time': 0.0, # Placeholder for manager input
            }
            if insert_report(report_data):
                st.success("✅ Report submitted successfully!")
            else:
                st.error("❌ Failed to submit report. Please try again.")

def show_my_reports(username):
    """Displays a table of the user's submitted reports."""
    st.subheader("My Reports")
    df = get_reports(username)
    if not df.empty:
        df_metrics = calculate_metrics(df)
        st.dataframe(df_metrics[['id', 'start_date', 'reporter', 'functional_location',
                                'planned_activities', 'actual_activities', 'Efficiency (%)',
                                'total_time', 'planned_manpower', 'manpower_used', 'planned_time',
                                'action_taken']])
    else:
        st.info("You haven't submitted any reports yet.")

def show_manager_dashboard():
    """Displays the manager dashboard with all reports and efficiency metrics."""
    st.subheader("All Reports (Manager Dashboard)")
    df_all = get_reports()
    if not df_all.empty:
        df_metrics = calculate_metrics(df_all)

        # Use st.data_editor to enable editing and save changes
        edited_df = st.data_editor(
            df_metrics,
            column_config={
                "id": st.column_config.NumberColumn("Report ID", help="Unique ID for each report", disabled=True),
                "planned_manpower": st.column_config.NumberColumn("Planned Manpower", help="Number of people planned for the task", min_value=0, format="%d"),
                "planned_time": st.column_config.NumberColumn("Planned Time (hrs)", help="Planned time to complete the task", min_value=0.0, format="%.2f"),
                "Given Weight": st.column_config.NumberColumn("Given Weight", disabled=True, format="%.2f"),
                "Actual Weight": st.column_config.NumberColumn("Actual Weight", disabled=True, format="%.2f"),
                "Efficiency (%)": st.column_config.NumberColumn("Efficiency (%)", disabled=True, format="%.2f"),
            },
            hide_index=True
        )

        # Detect changes and update the database
        if not edited_df.equals(df_metrics):
            diff_df = edited_df.loc[(edited_df['planned_manpower'] != df_metrics['planned_manpower']) | 
                                    (edited_df['planned_time'] != df_metrics['planned_time'])]
            
            for index, row in diff_df.iterrows():
                update_report(row['id'], row['planned_manpower'], row['planned_time'])
            
            st.success("Reports updated successfully!")
            st.rerun()

        # Display performance metrics
        avg_efficiency = edited_df["Efficiency (%)"].mean()
        
        st.header("Performance Metrics")
        st.metric("Average Efficiency", f"{avg_efficiency:.2f}%")
        
        st.subheader("Efficiency per Reporter")
        reporter_eff = edited_df.groupby("reporter")["Efficiency (%)"].mean().reset_index()
        reporter_eff.columns = ["Reporter", "Average Efficiency (%)"]
        st.bar_chart(reporter_eff.set_index("Reporter"))
    else:
        st.info("No reports have been submitted yet.")

# --- 🚀 Main Application Logic ---

def main():
    """Main function to run the Streamlit application."""

    # Title and Logo section
    col_logo, col_dam, col_title = st.columns([1, 2, 4])
    with col_logo:
        try:
            st.image("EEP_logo.png", width=100)
        except FileNotFoundError:
            st.image("https://placehold.co/100x100/A1C4FD/ffffff?text=TKZ", width=100)
    with col_dam:
        try:
            st.image("dam.jpg", width=300)
        except FileNotFoundError:
            st.warning("dam.jpg not found. Using a placeholder image.")
            st.image("https://placehold.co/600x200/A1C4FD/ffffff?text=Dam+Image", width=300)
    with col_title:
        st.title("Tekeze Hydropower Plant")
        st.subheader("Maintenance Tracker")

    st.markdown("---")
    
    # Step 1: Check Firebase initialization status
    if not st.session_state.firebase_initialized:
        with st.spinner("Connecting to the database..."):
            # Step 2: Call the initialization function. If it fails, the app stops here.
            if not initialize_firebase():
                return
    
    # Step 3: Now that Firebase is guaranteed to be initialized, proceed with the app
    if not st.session_state.logged_in:
        show_login_signup()
    else:
        show_main_app()

if __name__ == "__main__":
    main()




