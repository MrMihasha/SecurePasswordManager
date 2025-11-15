from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from app import db, limiter
from app.models import User
from app.forms import LoginForm, RegistrationForm
from urllib.parse import urlparse

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Prevent spam registrations
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Create new user with hashed password
            user = User(
                username=form.username.data,
                email=form.email.data
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            # in case of errors
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('auth/register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Prevent brute force
def login():
    """Secure login with master password and optional MFA"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Parameterized query prevents SQL injection
        user = User.query.filter_by(email=form.email.data).first()
        
        # Generic error message - don't reveal if user exists
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Check if MFA is enabled
        if user.mfa_enabled:
            # Store user ID in session temporarily for MFA verification
            from flask import session
            session['mfa_user_id'] = user.id
            session['mfa_next'] = request.args.get('next')
            return redirect(url_for('auth.mfa_verify'))
        
        # Successful login without MFA
        login_user(user)
        
        # Safe redirect - validate next parameter to prevent open redirect
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.index')
        
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/mfa-verify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Prevent MFA brute force
def mfa_verify():
    """Verify MFA token during login"""
    from flask import session
    from app.forms import MFAVerifyForm
    
    # Check if user is in MFA verification state
    if 'mfa_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['mfa_user_id'])
    if not user or not user.mfa_enabled:
        session.pop('mfa_user_id', None)
        session.pop('mfa_next', None)
        return redirect(url_for('auth.login'))
    
    form = MFAVerifyForm()
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            # MFA verification successful
            login_user(user)
            
            # Clean up session
            next_page = session.pop('mfa_next', url_for('main.index'))
            session.pop('mfa_user_id', None)
            
            # Validate redirect
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.index')
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('auth/mfa_verify.html', form=form)

@auth_bp.route('/logout')
def logout():
    """Secure logout"""
    from flask import session
    # Clear any MFA session data
    session.pop('mfa_user_id', None)
    session.pop('mfa_next', None)
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
