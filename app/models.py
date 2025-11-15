from app import db, login_manager
import app  # Import module to access cipher_suite
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime

# Initialize Argon2 password hasher (secure against GPU attacks)
ph = PasswordHasher()

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # MFA fields
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)  # TOTP secret
    
    # Relationship to passwords
    passwords = db.relationship('Password', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash password using Argon2"""
        self.password_hash = ph.hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        try:
            ph.verify(self.password_hash, password)
            # Rehash if parameters have changed (security upgrade)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
                db.session.commit()
            return True
        except VerifyMismatchError:
            return False
    
    def generate_mfa_secret(self):
        """Generate a new MFA secret for TOTP"""
        import pyotp
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code generation"""
        import pyotp
        if self.mfa_secret:
            return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
                name=self.email,
                issuer_name='SecurePass Password Manager'
            )
        return None
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        import pyotp
        if self.mfa_secret:
            totp = pyotp.TOTP(self.mfa_secret)
            return totp.verify(token, valid_window=1)  # Allow 1 time step tolerance
        return False
    
    def __repr__(self):
        return f'<User {self.username}>'

class Password(db.Model):
    """Password entry model with encryption"""
    __tablename__ = 'passwords'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, plain_password):
        """Encrypt password before storage"""
        if app.cipher_suite:
            self.encrypted_password = app.cipher_suite.encrypt(plain_password.encode()).decode()
        else:
            raise ValueError("Encryption not configured - cipher_suite is None")
    
    def get_password(self):
        """Decrypt password for display"""
        if app.cipher_suite and self.encrypted_password:
            try:
                return app.cipher_suite.decrypt(self.encrypted_password.encode()).decode()
            except Exception:
                return None
        return None
    
    def __repr__(self):
        return f'<Password {self.name}>'
