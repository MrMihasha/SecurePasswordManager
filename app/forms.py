from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, URL, Regexp
from app.models import User
import re

class LoginForm(FlaskForm):
    """Secure login form with CSRF protection"""
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Master Password', validators=[
        DataRequired(message='Password is required')
    ])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """User registration with strong password requirements"""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Master Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=12, message='Password must be at least 12 characters long')
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        """Check if username already exists"""
        # Parameterized query prevents SQL injection
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
    def validate_email(self, email):
        """Check if email already exists"""
        # Parameterized query prevents SQL injection
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')
    
    def validate_password(self, password):
        """Enforce strong password policy"""
        pwd = password.data
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'[0-9]', pwd):
            raise ValidationError('Password must contain at least one number.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character.')

class PasswordForm(FlaskForm):
    """Form for adding/editing password entries"""
    name = StringField('Service Name', validators=[
        DataRequired(message='Service name is required'),
        Length(min=1, max=255, message='Name must be between 1 and 255 characters')
    ])
    username = StringField('Username/Email', validators=[
        DataRequired(message='Username is required'),
        Length(min=1, max=255, message='Username must be between 1 and 255 characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=1, max=500, message='Password is too long')
    ])
    url = StringField('Website URL', validators=[
        Optional(),
        URL(message='Invalid URL format'),
        Length(max=500, message='URL is too long')
    ])
    notes = TextAreaField('Notes', validators=[
        Optional(),
        Length(max=1000, message='Notes must be less than 1000 characters')
    ])
    submit = SubmitField('Save')

class DeleteConfirmForm(FlaskForm):
    """Simple form for delete confirmation with CSRF protection"""
    submit = SubmitField('Confirm Delete')

class MFAVerifyForm(FlaskForm):
    """Form for verifying MFA token during login"""
    token = StringField('6-Digit Code', validators=[
        DataRequired(message='Verification code is required'),
        Length(min=6, max=6, message='Code must be 6 digits'),
        Regexp(r'^\d{6}$', message='Code must contain only digits')
    ])
    submit = SubmitField('Verify')

class MFASetupForm(FlaskForm):
    """Form for setting up MFA"""
    token = StringField('6-Digit Code', validators=[
        DataRequired(message='Verification code is required'),
        Length(min=6, max=6, message='Code must be 6 digits'),
        Regexp(r'^\d{6}$', message='Code must contain only digits')
    ])
    submit = SubmitField('Enable MFA')

class MFADisableForm(FlaskForm):
    """Form for disabling MFA with password confirmation"""
    password = PasswordField('Master Password', validators=[
        DataRequired(message='Password is required for disabling MFA')
    ])
    token = StringField('6-Digit Code', validators=[
        DataRequired(message='Verification code is required'),
        Length(min=6, max=6, message='Code must be 6 digits'),
        Regexp(r'^\d{6}$', message='Code must contain only digits')
    ])
    submit = SubmitField('Disable MFA')
