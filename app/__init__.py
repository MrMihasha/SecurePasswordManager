from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://"
)
cipher_suite = None

def create_app():
    """Application factory pattern for better security and testing"""
    load_dotenv()
    
    app = Flask(__name__)
    
    # Security configurations
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///passwords.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Session security settings
    # Set to False for development (HTTP), True for production (HTTPS)
    app.config['SESSION_COOKIE_SECURE'] = False  # Change to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
    
    # CSRF configuration
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire (managed by session)
    app.config['WTF_CSRF_SSL_STRICT'] = False  # Allow CSRF over HTTP in development
    
    # Initialize encryption
    global cipher_suite
    encryption_key = os.getenv('ENCRYPTION_KEY')
    
    if encryption_key:
        try:
            # Try to create cipher suite with the provided key
            cipher_suite = Fernet(encryption_key.encode())
            print("✓ Encryption initialized with key from .env file")
        except Exception as e:
            print(f"ERROR: Invalid encryption key in .env file: {e}")
            print("Generating a new key...")
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            print(f"WARNING: Generated new encryption key: {key.decode()}")
            print("Please add this to your .env file as ENCRYPTION_KEY")
    else:
        # Generate a new key if none exists (for development only)
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        print(f"WARNING: No ENCRYPTION_KEY found in .env file")
        print(f"Generated new encryption key: {key.decode()}")
        print("Please add this to your .env file as ENCRYPTION_KEY")
    
    # Verify cipher_suite is initialized
    if cipher_suite is None:
        raise RuntimeError("Failed to initialize encryption. Cannot start application.")
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    from app.routes import main_bp
    from app.auth import auth_bp
    from app.mfa_routes import mfa_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp, url_prefix='/mfa')
    
    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        """Add security headers to every response"""
        # CSP = XSS prevention
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
        )
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # XSS Protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
    
    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        db.session.rollback()
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template
        return render_template('errors/403.html'), 403
    
    return app
