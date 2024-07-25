import streamlit as st
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Hospital Accreditation Management System")

DATABASE_URL = "sqlite:///./hospital_accreditation.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
Base.metadata.create_all(bind=engine)

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()
def create_user(db: Session, username: str, email: str, password: str, is_admin: bool = False):
    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db_user = User(username=username, email=email, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    try:
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        return None
def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        return user
    return None
def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("User Type", ["Regular", "Administrator"])
    if st.button("Login"):
        if not username or not password or not role:
            st.error("Please enter both username, password and user type")
        else:
            db = SessionLocal()
            user = authenticate_user(db, username, password)
            if user:
                st.session_state['user'] = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin
                }
                st.success("Login successful")
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")
def register():
    st.subheader("Register")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    role = st.selectbox("User Type", ["Regular", "Administrator"])
    is_admin = True if role == "Administrator" else False
    if st.button("Register"):
        if not username or not email or not password or not role:
            st.error("All fields are required")
        else:
            db = SessionLocal()
            user = create_user(db, username, email, password, is_admin)
            if user:
                st.success("Registration successful")
                st.experimental_rerun()
            else:
                st.error("Username or email already exists")
def dashboard():
    st.subheader("Dashboard")
    if 'user' not in st.session_state:
        st.error("You need to log in first")
        return
    user = st.session_state['user']
    st.write(f"Welcome {user['username']}")

    if user['is_admin']:
        st.write("Admin Dashboard")
        st.subheader("User Management")
        manage_users()
        st.subheader("Update Accreditation Status")
        update_accreditation_status()
    else:
        st.write("User Dashboard")
        st.subheader("Accreditation Status Tracking")
        accreditation_status_tracking()
        st.subheader("Document Management")
        document_management()

    st.subheader("Notifications")
    notifications()
def manage_users():
    db = SessionLocal()
    users = db.query(User).all()
    st.write("List of users:")
    for user in users:
        st.write(f"Username: {user.username}, Email: {user.email}, Admin: {user.is_admin}")
def update_accreditation_status():
    providers = ["Insurance A", "Insurance B", "Insurance C", "Insurance D"]
    status_options = ["Pending", "In Progress", "Approved", "Rejected"]
    provider = st.selectbox("Select Provider", providers)
    new_status = st.selectbox("Select New Status", status_options)
    if st.button("Update Status"):
        st.success(f"Status of {provider} updated to {new_status}")
def accreditation_status_tracking():
    accreditation_data = [
        {"Provider": "Insurance A", "Status": "Pending"},
        {"Provider": "Insurance B", "Status": "In Progress"},
        {"Provider": "Insurance C", "Status": "Approved"},
        {"Provider": "Insurance D", "Status": "Rejected"}
    ]
    filter_status = st.selectbox("Filter by Status", ["All", "Pending", "In Progress", "Approved", "Rejected"])
    if filter_status != "All":
        filtered_data = [acc for acc in accreditation_data if acc["Status"] == filter_status]
    else:
        filtered_data = accreditation_data
    st.write(filtered_data)
def document_management():
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        st.write("File uploaded successfully")
def notifications():
    notifications_list = [
        {"Message": "Status of Insurance B updated to In Progress", "Time": "2024-07-24 10:00"},
        {"Message": "Document upload deadline for Insurance A approaching", "Time": "2024-07-23 15:30"}
    ]
    for notification in notifications_list:
        st.write(f"{notification['Time']}: {notification['Message']}")
# ---------------------------------
# Main application
# ---------------------------------
st.markdown("<h1 style='text-align: center; font-size: 24px;'>Hospital Accreditation Management System</h1>", unsafe_allow_html=True)
page = st.sidebar.radio("", ["Home", "Dashboard"])
if page == "Home":
    form_option = st.selectbox("Select", ["Login", "Register"])
    if form_option == "Login":
        login()
    elif form_option == "Register":
        register()
elif page == "Dashboard":
    dashboard()

