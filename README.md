# Secure Login System

A beginner-friendly Information System Security college project built with Python, Streamlit, and SQLite.

## Features
- User registration and login
- Passwords stored as PBKDF2-HMAC-SHA256 hashes with random salts
- Password minimum length validation
- Basic login attempt limit (5 failed attempts, 60-second lockout)
- Security activity logs
- Logout and dashboard
- Custom CSS styling

## Requirements
- Python 3.10 or newer recommended
- Internet connection for the first dependency installation

## Run on Windows (VS Code)

1. Extract `SecureLoginSystem.zip`.
2. Open the extracted `SecureLoginSystem` folder in VS Code.
3. Open **Terminal → New Terminal**.
4. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

5. Start the app:

   ```bash
   python -m streamlit run app.py
   ```

6. Open the local address printed in the terminal, usually `http://localhost:8501`.
7. Use **Create Account** to register, then use the **Login** tab.

## Files
- `app.py` — Streamlit application
- `requirements.txt` — Python dependency
- `README.md` — setup and project notes
- `SECURITY_NOTES.md` — limitations and security notes

`users.db` is created automatically when the app runs.

## Important limitations
This is an educational prototype, not production-ready authentication. The attempt counter and temporary lockout live in Streamlit session state and can be reset with a new session or app restart. For production use, implement durable server-side rate limiting, secure session controls, HTTPS, account recovery, and appropriate deployment secrets. Do not reuse real passwords in a college demo.
