from flask import Blueprint, render_template, redirect, url_for, flash, abort, request
from flask_login import login_required, current_user
from app import db
from app.models import Password
from app.forms import PasswordForm, DeleteConfirmForm
from sqlalchemy.exc import SQLAlchemyError

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    """Dashboard showing user's passwords"""
    # Per-user access control - only show current user's passwords
    passwords = Password.query.filter_by(user_id=current_user.id).order_by(Password.name).all()
    return render_template('index.html', passwords=passwords)

@main_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_password():
    """Add new password entry with CSRF protection and hacker detection!"""
    from app.security_pranks import detect_attack, increment_hacker_score, get_hacker_rank, get_funny_fact
    from datetime import datetime
    
    form = PasswordForm()
    
    if form.validate_on_submit():
        # Check for funny hacking attempts in form fields :D
        fields_to_check = [
            (form.name.data, 'service name'),
            (form.username.data, 'username'),
            (form.notes.data, 'notes') if form.notes.data else (None, None)
        ]
        
        for field_value, field_name in fields_to_check:
            if field_value:
                attack_detection = detect_attack(field_value)
                if attack_detection:
                    attack_type, response = attack_detection
                    attempts = increment_hacker_score()
                    
                    # Add context about which field
                    response = response.copy()
                    response['message'] = f"{response['message']}\n(You tried this in the {field_name} field 😄)"
                    
                    return render_template('hacker_detected.html',
                                         attack_type=attack_type,
                                         response=response,
                                         payload=field_value,
                                         hacker_attempts=attempts,
                                         hacker_rank=get_hacker_rank(attempts),
                                         funny_fact=get_funny_fact(),
                                         timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        try:
            # Create new password entry for current user only
            password_entry = Password(
                user_id=current_user.id,
                name=form.name.data,
                username=form.username.data,
                url=form.url.data,
                notes=form.notes.data
            )
            password_entry.set_password(form.password.data)
            
            db.session.add(password_entry)
            db.session.commit()
            
            flash(f'Password for {form.name.data} added successfully!', 'success')
            return redirect(url_for('main.index'))
        except SQLAlchemyError:
            db.session.rollback()
            # Generic error - no internal details leaked
            flash('An error occurred while saving the password. Please try again.', 'danger')
    
    return render_template('add_password.html', form=form)

@main_bp.route('/view/<int:id>')
@login_required
def view_password(id):
    """View password details with decryption"""
    # Access control: ensure user owns this password
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    
    if not password:
        flash('Password not found or access denied.', 'danger')
        return redirect(url_for('main.index'))
    
    # Decrypt password for display
    decrypted_password = password.get_password()
    
    if decrypted_password is None:
        flash('Error decrypting password.', 'danger')
        return redirect(url_for('main.index'))
    
    return render_template('view_password.html', password=password, decrypted_password=decrypted_password)

@main_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_password(id):
    """Edit password entry with access control"""
    # Access control: ensure user owns this password
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    
    if not password:
        flash('Password not found or access denied.', 'danger')
        return redirect(url_for('main.index'))
    
    form = PasswordForm()
    
    if form.validate_on_submit():
        try:
            # Update password entry
            password.name = form.name.data
            password.username = form.username.data
            password.url = form.url.data
            password.notes = form.notes.data
            password.set_password(form.password.data)
            
            db.session.commit()
            
            flash(f'Password for {form.name.data} updated successfully!', 'success')
            return redirect(url_for('main.index'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('An error occurred while updating the password. Please try again.', 'danger')
    elif request.method == 'GET':
        # Pre-fill form with existing data
        form.name.data = password.name
        form.username.data = password.username
        form.url.data = password.url
        form.notes.data = password.notes
        # Don't pre-fill password for security
    
    return render_template('edit_password.html', form=form, password=password)

@main_bp.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_password(id):
    """Delete password with confirmation and access control"""
    # Access control: ensure user owns this password
    password = Password.query.filter_by(id=id, user_id=current_user.id).first()
    
    if not password:
        flash('Password not found or access denied.', 'danger')
        return redirect(url_for('main.index'))
    
    form = DeleteConfirmForm()
    
    if form.validate_on_submit():
        try:
            service_name = password.name
            db.session.delete(password)
            db.session.commit()
            
            flash(f'Password for {service_name} deleted successfully!', 'success')
            return redirect(url_for('main.index'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('An error occurred while deleting the password. Please try again.', 'danger')
    
    return render_template('delete_password.html', form=form, password=password)

@main_bp.route('/search')
@login_required
def search():
    """Search user's passwords with fun hacker detection!"""
    from flask import request, render_template as render, session
    from app.security_pranks import detect_attack, increment_hacker_score, get_hacker_rank, get_funny_fact
    from datetime import datetime
    
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('main.index'))
    
    # 🎉 EASTER EGG: Detect hacking attempts :P
    attack_detection = detect_attack(query)
    if attack_detection:
        attack_type, response = attack_detection
        attempts = increment_hacker_score()
        
        return render('hacker_detected.html', 
                     attack_type=attack_type,
                     response=response,
                     payload=query,
                     hacker_attempts=attempts,
                     hacker_rank=get_hacker_rank(attempts),
                     funny_fact=get_funny_fact(),
                     timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    # Normal search (parameterized queries prevent actual SQL injection)
    passwords = Password.query.filter_by(user_id=current_user.id).filter(
        db.or_(
            Password.name.ilike(f'%{query}%'),
            Password.username.ilike(f'%{query}%'),
            Password.url.ilike(f'%{query}%')
        )
    ).order_by(Password.name).all()
    
    return render('search_results.html', passwords=passwords, query=query)
