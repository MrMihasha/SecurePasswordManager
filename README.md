# Secure Password Manager

A web-based password manager built with Flask, implementing security best practices including AES-256 encryption, CSRF protection, SQL injection prevention, and XSS mitigation. + Easter Eggs :D

## Features

### Security Features ✅

1. **Secure Credential Storage**
   - AES-256 encryption using Fernet (symmetric encryption)
   - Server-side encryption of all stored passwords
   - Encryption keys stored securely in environment variables

2. **Master Password & Authentication**
   - Argon2 password hashing (resistant to GPU attacks)
   - Automatic password rehashing on algorithm upgrades
   - Secure session management with HttpOnly cookies
   - Session timeout after 30 minutes of inactivity
   - **Optional Two-Factor Authentication (2FA/MFA)**
   - TOTP-based authentication with authenticator apps

3. **SQL Injection Protection**
   - SQLAlchemy ORM with parameterized queries
   - No raw SQL queries used
   - Input validation at form level

4. **XSS Prevention**
   - Jinja2 automatic escaping enabled
   - Content Security Policy (CSP) headers
   - Input sanitization via WTForms validators

5. **CSRF Protection**
   - Flask-WTF CSRF tokens on all forms
   - Token validation on every POST request
   - SameSite cookie attribute set to 'Lax'

6. **Access Control**
   - Per-user ownership enforced on all operations
   - Login required decorator on protected routes
   - User can only access their own passwords

7. **Security Headers**
   - Content-Security-Policy
   - X-Frame-Options: SAMEORIGIN
   - X-Content-Type-Options: nosniff
   - X-XSS-Protection
   - Referrer-Policy

8. **Error Handling**
   - Generic error messages (no stack traces leaked)
   - Custom error pages (404, 403, 500)
   - Database rollback on errors

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. **Extract the project:**
   ```bash
   cd secure_password_manager
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

4. **Configure environment variables:**
   
   The `.env` file is already configured with secure keys. For production use, generate new keys:
   
   ```python
   # Generate SECRET_KEY
   python3 -c "import secrets; print(secrets.token_hex(32))"
   
   # Generate ENCRYPTION_KEY
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   
   Then update `.env` with your keys:
   ```
   SECRET_KEY=your-generated-secret-key
   ENCRYPTION_KEY=your-generated-encryption-key
   SQLALCHEMY_DATABASE_URI=sqlite:///passwords.db
   ```

5. **Initialize the database:**
   ```bash
   python3 run.py
   ```

## Usage

1. **Start the application:**
   ```bash
   python3 run.py
   ```

2. **Access the application:**
   Open your browser and navigate to `http://localhost:8080`

3. **Register an account:**
   - Click "Register" in the navigation
   - Create a strong master password (12+ characters, mixed case, numbers, special characters)
   - **Important:** Your master password cannot be recovered if lost!

4. **Add passwords:**
   - Click "Add Password" in the dashboard
   - Fill in service name, username, password, URL (optional), and notes (optional)
   - Use the password generator for strong passwords
   - All passwords are encrypted before storage

5. **Manage passwords:**
   - View: See password details and copy credentials
   - Edit: Update password information
   - Delete: Remove passwords with confirmation
   - Search: Find passwords by service name, username, or URL

## Security Architecture

### Encryption Flow
```
User Password → Argon2 Hash → Stored in Database
Service Password → AES-256 Encryption → Stored in Database
```

### Authentication Flow
```
1. User enters credentials
2. Email lookup (parameterized query)
3. Argon2 password verification
4. Session created with secure cookie
5. CSRF token generated for forms
```

### Access Control
```
1. User must be authenticated (@login_required)
2. Query filters by user_id
3. Ownership verified before operations
4. Generic error if unauthorized
```

## Technology Stack

- **Backend:** Flask 3.0
- **Database:** SQLAlchemy with SQLite
- **Authentication:** Flask-Login with Argon2
- **Forms:** Flask-WTF with CSRF protection
- **Encryption:** Cryptography (Fernet/AES-256)
- **Frontend:** Bootstrap 5, Bootstrap Icons
- **Security:** CSP headers, secure sessions, input validation

## Project Structure

```
secure_password_manager/
├── app/
│   ├── __init__.py          # Application factory with security config
│   ├── models.py            # User and Password models
│   ├── forms.py             # WTForms with validation
│   ├── auth.py              # Authentication blueprint
│   ├── routes.py            # Main application routes
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css    # Custom styles
│   │   └── js/
│   │       ├── main.js      # General JavaScript
│   │       └── password.js  # Password-specific JS
│   └── templates/
│       ├── base.html        # Base template
│       ├── index.html       # Dashboard
│       ├── auth/            # Authentication templates
│       ├── errors/          # Error pages
│       └── ...              # Other templates
├── .env                     # Environment variables (DO NOT COMMIT)
├── requirements.txt         # Python dependencies
├── run.py                   # Application entry point
└── README.md                # This file
```

### Recommended Testing
```bash
# SQL Injection test
# Try entering: ' OR '1'='1 in login form
# Result: Login fails (parameterized queries)

# XSS test  
# Try entering: <script>alert('XSS')</script> in form
# Result: Displayed as text (Jinja2 escaping)

# CSRF test
# Try submitting form without CSRF token
# Result: 400 Bad Request
```

## Production Deployment

For production deployment:

1. **Use HTTPS:**
   - Obtain SSL certificate (Let's Encrypt)
   - Configure reverse proxy (Nginx/Apache)
   - Set `SESSION_COOKIE_SECURE = True`

2. **Use Production Database:**
   - PostgreSQL or MySQL instead of SQLite
   - Update SQLALCHEMY_DATABASE_URI

3. **Security Hardening:**
   - Set `DEBUG = False`
   - Use strong, unique SECRET_KEY and ENCRYPTION_KEY
   - Implement rate limiting
   - Enable security monitoring
   - Regular security audits

4. **WSGI Server:**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8080 run:app
   ```

## License

This project is for educational purposes as part of the ICS0027 course.

## Security Compliance

This project meets the following security requirements:

- ✅ Secure credential storage with AES-256 encryption
- ✅ Master password authentication with Argon2
- ✅ SQL injection protection via parameterized queries
- ✅ XSS prevention with escaping and CSP
- ✅ CSRF protection on all forms
- ✅ Secure session management
- ✅ Per-user access control
- ✅ Generic error messages
- ✅ Security headers (CSP, X-Frame-Options, etc.)

## Support

For issues or questions:
- Check the README.md
- Review the code comments
- Test in a safe environment first

---

**Warning:** This is a educational project. For production use, consider using established password managers like Bitwarden, 1Password, or KeePass.
