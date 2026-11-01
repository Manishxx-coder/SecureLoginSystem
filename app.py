import streamlit as st
import sqlite3
import hashlib
import hmac
import secrets
import time
from pathlib import Path

DB = Path(__file__).with_name("users.db")
MAX_ATTEMPTS = 5
LOCK_SECONDS = 60


def connect():
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            event_time TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    return con


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        300000
    ).hex()


def log_event(username, action):
    with connect() as con:
        con.execute(
            "INSERT INTO security_logs (username, action) VALUES (?, ?)",
            (username, action)
        )


st.set_page_config(
    page_title="Secure Login System",
    page_icon="🔐",
    layout="centered"
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #101827, #182b49);
    color: white;
}
h1, h2, h3, p, label, [data-testid="stMarkdownContainer"] {
    color: white;
}
.stButton > button, [data-testid="stFormSubmitButton"] > button {
    width: 100%;
    border-radius: 8px;
    font-weight: bold;
}
[data-testid="stForm"] {
    border: 1px solid #40516b;
    border-radius: 14px;
    padding: 22px;
    background: rgba(255,255,255,0.03);
}
[data-testid="stTabs"] button {
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Secure Login System")
st.caption("Information System Security Project")
st.write("Register an account, sign in, and review your security activity.")
st.divider()

if "user" not in st.session_state:
    st.session_state.user = None
if "attempts" not in st.session_state:
    st.session_state.attempts = {}
if "locked_until" not in st.session_state:
    st.session_state.locked_until = {}

if st.session_state.user:
    username = st.session_state.user
    st.success(f"Welcome, {username}!")
    st.subheader("Security Dashboard")
    st.write("You are logged in successfully.")
    st.info("Your session is active.")

    left, right = st.columns(2)
    with left:
        if st.button("View security logs"):
            with connect() as con:
                rows = con.execute("""
                    SELECT action, event_time
                    FROM security_logs
                    WHERE username = ?
                    ORDER BY id DESC LIMIT 20
                """, (username,)).fetchall()
            if rows:
                st.dataframe(
                    rows,
                    use_container_width=True,
                    column_config={
                        "action": "Activity",
                        "event_time": "Time"
                    }
                )
            else:
                st.info("No activity recorded yet.")
    with right:
        if st.button("Logout"):
            log_event(username, "Logout")
            st.session_state.user = None
            st.rerun()
else:
    login_tab, register_tab = st.tabs(["Login", "Create Account"])

    with register_tab:
        st.subheader("Create a new account")
        with st.form("register_form", clear_on_submit=True):
            new_user = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input(
                "Confirm password", type="password"
            )
            register = st.form_submit_button("Register")

        if register:
            new_user = new_user.strip()
            if not new_user or len(new_user) > 50:
                st.error("Username must be 1–50 characters.")
            elif not all(c.isalnum() or c in "_-" for c in new_user):
                st.error("Use only letters, numbers, underscores, or hyphens.")
            elif len(new_password) < 10:
                st.error("Use a password of at least 10 characters.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                salt = secrets.token_bytes(16).hex()
                password_hash = hash_password(new_password, salt)
                try:
                    with connect() as con:
                        con.execute(
                            "INSERT INTO users (username, salt, password_hash) "
                            "VALUES (?, ?, ?)",
                            (new_user, salt, password_hash)
                        )
                    log_event(new_user, "Registration")
                    st.success("Account created. Open the Login tab to sign in.")
                except sqlite3.IntegrityError:
                    st.error("That username already exists.")

    with login_tab:
        st.subheader("Sign in to your account")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_user")
            password = st.text_input(
                "Password", type="password", key="login_pass"
            )
            login = st.form_submit_button("Login")

        if login:
            username = username.strip()
            now = time.time()
            locked_until = st.session_state.locked_until.get(username, 0)

            if now < locked_until:
                remaining = int(locked_until - now) + 1
                st.error(f"Too many attempts. Try again in {remaining} seconds.")
            else:
                with connect() as con:
                    record = con.execute(
                        "SELECT salt, password_hash FROM users WHERE username = ?",
                        (username,)
                    ).fetchone()

                valid = False
                if record:
                    salt, stored_hash = record
                    candidate = hash_password(password, salt)
                    valid = hmac.compare_digest(candidate, stored_hash)

                if valid:
                    st.session_state.attempts[username] = 0
                    st.session_state.locked_until[username] = 0
                    log_event(username, "Successful login")
                    st.session_state.user = username
                    st.rerun()
                else:
                    log_event(username or "unknown", "Failed login")
                    attempts = st.session_state.attempts.get(username, 0) + 1
                    st.session_state.attempts[username] = attempts
                    if attempts >= MAX_ATTEMPTS:
                        st.session_state.locked_until[username] = time.time() + LOCK_SECONDS
                        st.session_state.attempts[username] = 0
                        st.error("Too many failed attempts. Login is locked for 60 seconds.")
                    else:
                        st.error(
                            "Invalid username or password. "
                            f"Attempt {attempts} of {MAX_ATTEMPTS}."
                        )

st.divider()
st.caption("Educational project • Secure authentication demonstration")
