from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, g
from app.models import db, User, ActivityLog
from app.services.events import event_bus
from app.services.security import get_client_ip
from app.services.telemetry import parse_user_agent_details, record_login_telemetry
from app.services.ml_detector import (
    fetch_ip_geolocation, 
    VPNIntelligenceModule, 
    AnomalyDetectionEngine, 
    MLPredictionEngine
)

auth_bp = Blueprint('auth', __name__)

# Security Decorators for Custom Session Management
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
        if session.get('pending_verification'):
            flash("Identity verification pending. Please complete the verification challenge.", "warning")
            return redirect(url_for('auth.verify_identity'))
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
        if session.get('pending_verification'):
            flash("Verification pending. Please verify your identity.", "warning")
            return redirect(url_for('auth.verify_identity'))
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
            
            # Geolocation and UserAgent context
            ip = get_client_ip()
            ua = request.headers.get('User-Agent', '')
            geo = fetch_ip_geolocation(ip)
            browser, operating_system, device = parse_user_agent_details(ua)

            # Log registration
            log = ActivityLog(
                user_id=new_user.id,
                action='register',
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                risk_score=0.0,
                city=geo['city'],
                country=geo['country'],
                latitude=geo['latitude'],
                longitude=geo['longitude'],
                browser=browser,
                operating_system=operating_system,
                device=device,
                prediction='Legitimate User',
                confidence=100.0,
                details=f"Secure user account registration. Location: {geo['city']}, {geo['country']}"
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
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', '')
        username = user.username if user else (email.split('@')[0].strip() if email else None)
        
        # Resolve network intelligence metrics
        geo = fetch_ip_geolocation(ip)
        vpn_detected, vpn_details = VPNIntelligenceModule.evaluate_vpn_risk(ip)
        browser, operating_system, device = parse_user_agent_details(ua)
        platform = operating_system
        
        if user and user.check_password(password):
            if user.is_blocked:
                flash("Your account has been deactivated. Contact an administrator.", "danger")
                return render_template('auth/login.html')
                
            # Perform User Profile Anomaly Analysis
            anomalies = AnomalyDetectionEngine.analyze_profile_anomalies(
                user, geo['city'], geo['country'], browser, platform
            )
            
            # Engineered features to feed the ML Prediction Engine.
            # Keep compatibility with the legacy feature names while supplying the model's
            # exact numeric inputs expected by the trained estimator.
            time_window = datetime.utcnow() - timedelta(hours=24)
            failed_login_count = ActivityLog.query.filter(
                ActivityLog.action == 'login_failed',
                ActivityLog.ip_address == ip,
                ActivityLog.timestamp >= time_window
            ).count()
            location_anomaly = anomalies['new_location']
            device_anomaly = anomalies['new_browser'] or anomalies['new_platform']

            features = {
                'time_of_day': datetime.now().hour,
                'failed_login_count': failed_login_count,
                'vpn_active': vpn_detected,
                'location_anomaly': location_anomaly,
                'device_anomaly': device_anomaly,
                'protocol': 'HTTPS',
                'port': 443,
                'packets': 50 + (failed_login_count * 20) + (30 if vpn_detected else 0),
                'bytes': 5000 + (failed_login_count * 1500) + (2000 if vpn_detected else 0),
                'request_count': 1 + failed_login_count + (2 if location_anomaly else 0),
                'login_attempts': 1 + failed_login_count,
                'cpu_usage': 30 + (8 if vpn_detected else 0) + (12 if device_anomaly else 0),
                'memory_usage': 35 + (15 if vpn_detected else 0) + (10 if location_anomaly else 0),
                'response_time': 120 + (failed_login_count * 35) + (30 if vpn_detected else 0),
            }

            # Evaluate threat profile using the trained model artifact
            risk_pct, threat_level, prediction, confidence = MLPredictionEngine.predict_login_anomaly(features)

            # Log security event details
            log = ActivityLog(
                user_id=user.id,
                action='login_anomaly' if threat_level == 'HIGH' else 'login_success',
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                risk_score=risk_pct / 100.0,
                city=geo['city'],
                country=geo['country'],
                latitude=geo['latitude'],
                longitude=geo['longitude'],
                browser=browser,
                operating_system=operating_system,
                device=device,
                prediction=prediction,
                confidence=confidence,
                vpn_detected=vpn_detected,
                details=(
                    f"ML Prediction: {prediction} | Threat Level: {threat_level} | "
                    f"Risk Score: {risk_pct} | Confidence: {confidence} | "
                    f"VPN={vpn_detected}, LocAnomaly={location_anomaly}, DeviceAnomaly={device_anomaly}"
                )
            )
            record_login_telemetry(
                user=user,
                username=username,
                success=True,
                request=request,
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                endpoint=request.endpoint,
                request_method=request.method,
                log=log,
            )
            
            # Direct logging to telemetry services
            event_bus.dispatch('auth.login_attempt', email=email, ip_address=ip, user_agent=ua, success=True, user_id=user.id)
            
            # If Anomaly Detection triggers HIGH risk, redirect to Identity Verification Check
            if threat_level == 'HIGH':
                session.clear()
                session['pending_verification'] = True
                session['verification_user_id'] = user.id
                session['verification_log_id'] = log.id
                flash("Security Alert: High risk login patterns detected. Multi-factor verification is required.", "danger")
                return redirect(url_for('auth.verify_identity'))
            
            # Complete login normally
            session.clear()
            session['user_id'] = user.id
            session['role'] = user.role
            
            flash(f"Welcome back, {user.username}!", "success")
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('main.dashboard'))
        else:
            # Login credentials verification failed
            user_id = user.id if user else None
            
            # Treat incorrect passwords as suspicious attacker activity automatically.
            # Keep the same route logic and session behavior while using the real ML signal.
            time_window = datetime.utcnow() - timedelta(hours=24)
            failed_login_count = ActivityLog.query.filter(
                ActivityLog.action == 'login_failed',
                ActivityLog.ip_address == ip,
                ActivityLog.timestamp >= time_window
            ).count()
            model_features = {
                'time_of_day': datetime.now().hour,
                'failed_login_count': failed_login_count + 1,
                'vpn_active': vpn_detected,
                'location_anomaly': False,
                'device_anomaly': False,
                'protocol': 'HTTPS',
                'port': 443,
                'packets': 60 + (failed_login_count * 25) + (30 if vpn_detected else 0),
                'bytes': 6000 + (failed_login_count * 1800) + (2000 if vpn_detected else 0),
                'request_count': 1 + failed_login_count + 1,
                'login_attempts': 1 + failed_login_count + 1,
                'cpu_usage': 32 + (8 if vpn_detected else 0),
                'memory_usage': 38 + (15 if vpn_detected else 0),
                'response_time': 140 + (failed_login_count * 40) + (30 if vpn_detected else 0),
            }
            risk_pct, threat_level, prediction, confidence = MLPredictionEngine.predict_login_anomaly(model_features)

            log = ActivityLog(
                user_id=user_id,
                action='login_failed',
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                risk_score=risk_pct / 100.0,
                city=geo['city'],
                country=geo['country'],
                latitude=geo['latitude'],
                longitude=geo['longitude'],
                browser=browser,
                operating_system=operating_system,
                device=device,
                prediction=prediction,
                confidence=confidence,
                vpn_detected=vpn_detected,
                details=(
                    f"Invalid password attempt recorded on target credentials. "
                    f"ML Prediction: {prediction} | Threat Level: {threat_level} | "
                    f"Risk Score: {risk_pct} | Confidence: {confidence}"
                )
            )
            record_login_telemetry(
                user=user,
                username=username,
                success=False,
                request=request,
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                endpoint=request.endpoint,
                request_method=request.method,
                log=log,
            )
            
            event_bus.dispatch('auth.login_attempt', email=email, ip_address=ip, user_agent=ua, success=False, user_id=user_id)
            flash("Invalid email or password.", "danger")
            
    return render_template('auth/login.html')

@auth_bp.route('/verify-identity', methods=['GET', 'POST'])
def verify_identity():
    # Enforce session state verification constraints
    if not session.get('pending_verification') or not session.get('verification_user_id'):
        return redirect(url_for('auth.login'))
        
    user = User.query.get(session['verification_user_id'])
    if not user:
        return redirect(url_for('auth.login'))
        
    log_id = session.get('verification_log_id')
    log = ActivityLog.query.get(log_id) if log_id else None
    
    if request.method == 'POST':
        code = request.form.get('verification_code', '').strip()
        # Accept standard security code 123456 for demo walkthrough
        if code in ['123456', '123-456']:
            # De-escalate security threat flag
            session.clear()
            session['user_id'] = user.id
            session['role'] = user.role
            session.pop('pending_verification', None)
            
            # Upgrade initial alert status in database logs
            if log:
                log.action = 'login_success'
                log.details += " | Anomaly verified: identity challenge code cleared."
                db.session.commit()
                
            # Log verification clearing
            ip = get_client_ip()
            ua = request.headers.get('User-Agent', '')
            db.session.add(ActivityLog(
                user_id=user.id,
                action='verification_passed',
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                risk_score=0.0,
                prediction='Legitimate User',
                confidence=99.0,
                details="Verification challenge completed successfully.",
                city=log.city if log else None,
                country=log.country if log else None,
                latitude=log.latitude if log else None,
                longitude=log.longitude if log else None,
                browser=log.browser if log else None,
                operating_system=log.operating_system if log else None,
                device=log.device if log else None
            ))
            db.session.commit()
            
            flash("MFA verification successful. Access granted to CloudShield AI resources.", "success")
            return redirect(url_for('main.dashboard'))
        else:
            # Register failed verification attempt
            flash("Invalid authorization code. Verification challenge failed.", "danger")
            
    threat_ctx = {
        'risk_score': round(log.risk_score * 100, 1) if log else 92.0,
        'prediction': log.prediction if log else 'Possible Attacker',
        'confidence': log.confidence if log else 95.0,
        'city': log.city if log else 'Unknown',
        'country': log.country if log else 'Unknown',
        'browser': log.browser if log else 'Unknown',
        'operating_system': log.operating_system if log else 'Unknown',
        'ip_address': log.ip_address if log else 'Unknown'
    }
    
    return render_template('auth/verify_identity.html', threat=threat_ctx, user=user)

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
            ip = get_client_ip()
            db.session.add(ActivityLog(
                user_id=g.user.id,
                action='profile_update',
                ip_address=ip,
                risk_score=0.0,
                prediction='Legitimate User',
                confidence=100.0,
                details="User profile information modified."
            ))
            db.session.commit()
            
            flash("Profile updated successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Failed to update profile.", "danger")
            
    return render_template('profile.html')
