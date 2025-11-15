from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user
from app import db
from app.forms import MFASetupForm, MFADisableForm
from sqlalchemy.exc import SQLAlchemyError
import pyotp
import qrcode
import io
import base64

mfa_bp = Blueprint('mfa', __name__)

@mfa_bp.route('/setup', methods=['GET', 'POST'])
@login_required
def setup():
    """Setup MFA for the current user"""
    if current_user.mfa_enabled:
        flash('MFA is already enabled for your account.', 'info')
        return redirect(url_for('mfa.settings'))
    
    form = MFASetupForm()
    
    # Generate secret if not in session
    if 'mfa_setup_secret' not in session:
        secret = pyotp.random_base32()
        session['mfa_setup_secret'] = secret
    else:
        secret = session['mfa_setup_secret']
    
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name='SecurePass Password Manager'
    )
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for display
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    if form.validate_on_submit():
        # Verify the token before enabling
        totp = pyotp.TOTP(secret)
        if totp.verify(form.token.data, valid_window=1):
            try:
                # Enable MFA
                current_user.mfa_secret = secret
                current_user.mfa_enabled = True
                db.session.commit()
                
                # Clear session
                session.pop('mfa_setup_secret', None)
                
                flash('MFA has been successfully enabled for your account!', 'success')
                return redirect(url_for('mfa.settings'))
            except SQLAlchemyError:
                db.session.rollback()
                flash('An error occurred while enabling MFA. Please try again.', 'danger')
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('mfa/setup.html', form=form, secret=secret, qr_code=qr_code_base64)

@mfa_bp.route('/settings')
@login_required
def settings():
    """MFA settings page"""
    return render_template('mfa/settings.html')

@mfa_bp.route('/disable', methods=['GET', 'POST'])
@login_required
def disable():
    """Disable MFA for the current user"""
    if not current_user.mfa_enabled:
        flash('MFA is not enabled for your account.', 'info')
        return redirect(url_for('mfa.settings'))
    
    form = MFADisableForm()
    
    if form.validate_on_submit():
        # Verify password
        if not current_user.check_password(form.password.data):
            flash('Invalid password. MFA not disabled.', 'danger')
            return render_template('mfa/disable.html', form=form)
        
        # Verify MFA token
        if not current_user.verify_totp(form.token.data):
            flash('Invalid verification code. MFA not disabled.', 'danger')
            return render_template('mfa/disable.html', form=form)
        
        try:
            # Disable MFA
            current_user.mfa_enabled = False
            current_user.mfa_secret = None
            db.session.commit()
            
            flash('MFA has been disabled for your account.', 'warning')
            return redirect(url_for('mfa.settings'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('An error occurred while disabling MFA. Please try again.', 'danger')
    
    return render_template('mfa/disable.html', form=form)