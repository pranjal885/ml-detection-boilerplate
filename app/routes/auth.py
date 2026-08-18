from functools import wraps
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, g
from app.models import db, User, ActivityLog

auth_bp = Blueprint('auth', __name__)

# Authentication Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("Authentication required. Please log in to proceed.", "warning")
            return redirect(url_for('auth.login'))
        if g.user.is_blocked:
            session.clear()
            flash("Your account has been deactivated by an administrator.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("Authentication required.", "danger")
            return redirect(url_for('auth.login'))
        if g.user.role != 'admin':
            flash("Access Denied: Administrative privileges required.", "danger")
            return redirect(url_for('main.dashboard'))
        if g.user.is_blocked:
            session.clear()
            flash("Your account has been deactivated.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return render_template('auth/register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "warning")
            return render_template('auth/register.html')
            
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account with that email already exists.", "warning")
            return render_template('auth/register.html')
            
        # Create User
        new_user = User(username=username, email=email, role='user')
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Simple metadata context
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip and ',' in ip:
                ip = ip.split(',')[0].strip()
            ua = request.headers.get('User-Agent', '')

            # Log registration
            log = ActivityLog(
                user_id=new_user.id,
                username=new_user.username,
                action='register',
                ip_address=ip or 'Unknown',
                user_agent=ua[:255] if ua else None,
                details=f"Secure user account registration."
            )
            db.session.add(log)
            db.session.commit()
                               
            flash("Account registered successfully! Please log in.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash("Registration failed. Please try again later.", "danger")
            
    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        ua = request.headers.get('User-Agent', '')
        
        if user and user.check_password(password):
            if user.is_blocked:
                flash("Your account has been deactivated. Contact an administrator.", "danger")
                return render_template('auth/login.html')
                
            session.clear()
            session['user_id'] = user.id
            session['role'] = user.role
            
            # Log success
            log = ActivityLog(
                user_id=user.id,
                username=user.username,
                action='login_success',
                ip_address=ip or 'Unknown',
                user_agent=ua[:255] if ua else None,
                details="Successful login."
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f"Welcome back, {user.username}!", "success")
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('main.dashboard'))
        else:
            # Login credentials verification failed
            user_id = user.id if user else None
            username = user.username if user else (email.split('@')[0].strip() if email else None)
            log = ActivityLog(
                user_id=user_id,
                username=username,
                action='login_failed',
                ip_address=ip or 'Unknown',
                user_agent=ua[:255] if ua else None,
                details=f"Invalid password login attempt for email: {email}"
            )
            db.session.add(log)
            db.session.commit()
            flash("Invalid email or password.", "danger")
            
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        if not username:
            flash("Username cannot be empty.", "warning")
            return render_template('profile.html')
            
        if not g.user.check_password(current_password):
            flash("Incorrect current password.", "danger")
            return render_template('profile.html')
            
        # Update User
        g.user.username = username
        if new_password:
            g.user.set_password(new_password)
            
        try:
            db.session.commit()
            
            # Log updates in security timeline
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip and ',' in ip:
                ip = ip.split(',')[0].strip()
            db.session.add(ActivityLog(
                user_id=g.user.id,
                username=g.user.username,
                action='profile_update',
                ip_address=ip or 'Unknown',
                details="User profile information modified."
            ))
            db.session.commit()
            
            flash("Profile updated successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Failed to update profile.", "danger")
            
    return render_template('profile.html')
