# Security notes

- Passwords are never stored as plain text. A random salt and PBKDF2-HMAC-SHA256 are used.
- SQL statements use parameters instead of concatenating user input.
- Failed and successful login attempts are written to the SQLite security log.
- The current login lockout is session-based. It is intended to demonstrate the concept, not to withstand deliberate abuse.
- Streamlit's built-in session handling is used for this local educational demo.
- Before public deployment, add durable rate limiting, review session/authentication design, use HTTPS, protect the database file, and test the application.
- This project does not provide email verification, password reset, multi-factor authentication, or admin roles.
