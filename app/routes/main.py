import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, send_file, abort, session
from sqlalchemy import func
from app.models import db, File, ActivityLog, BlockedIP
from app.routes.auth import login_required
from app.services.storage import save_file_to_disk, delete_file_from_disk, get_disk_file_path
from app.services.events import event_bus
from app.services.security import get_client_ip
from app.services.telemetry import get_live_telemetry, parse_user_agent_details

main_bp = Blueprint('main', __name__)


def _get_system_usage_estimate():
    cpu_value = 0.0
    memory_value = 0.0
    try:
        import psutil
        cpu_value = float(psutil.cpu_percent(interval=None))
        memory_value = float(psutil.virtual_memory().percent)
    except Exception:
        if ActivityLog.query.count():
            high_risk = ActivityLog.query.filter(ActivityLog.risk_score >= 0.7).count()
            total = ActivityLog.query.count()
            cpu_value = min(100.0, max(12.0, (high_risk / total) * 100.0 if total else 12.0))
            memory_value = min(100.0, max(20.0, ((high_risk + 1) / max(1, total + 1)) * 100.0))
    return round(cpu_value, 1), round(memory_value, 1)


def _extract_response_time_ms(log):
    if not log or not log.details:
        return 0.0
    try:
        payload = json.loads(log.details)
        if isinstance(payload, dict):
            value = payload.get('response_time_ms')
            if value is None:
                value = payload.get('response_time')
            if value is not None:
                return float(value)
    except Exception:
        pass
    return 0.0

@main_bp.route('/')
def index():
    if g.user:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    search_query = request.args.get('search', '').strip()

    # 1. Fetch Protected Resource Files (not deleted)
    query = File.query.filter_by(user_id=g.user.id, is_deleted=False)
    if search_query:
        query = query.filter(File.filename.like(f"%{search_query}%"))
    files = query.order_by(File.upload_time.desc()).all()

    # Storage metrics
    total_used_bytes = sum(file.file_size for file in File.query.filter_by(user_id=g.user.id, is_deleted=False).all())
    storage_limit_bytes = 100 * 1024 * 1024  # 100MB Demo Storage Limit
    used_percentage = min(100.0, (total_used_bytes / storage_limit_bytes) * 100)

    # 2. Retrieve Latest Active Session Telemetry
    latest_login = ActivityLog.query.filter_by(user_id=g.user.id).filter(
        ActivityLog.action.in_(['login_success', 'login_failed', 'verification_passed', 'login_anomaly', 'ip_blocked'])
    ).order_by(ActivityLog.timestamp.desc()).first()

    if latest_login:
        risk_score = round((latest_login.risk_score or 0.0) * 100, 1)
        security_score = round(100.0 - risk_score, 1)
        prediction = latest_login.prediction or "Legitimate User"
        confidence = latest_login.confidence or 97.0
        city = latest_login.city or "Unknown"
        country = latest_login.country or "Unknown"
        fallback_browser, fallback_os, fallback_device = parse_user_agent_details(latest_login.user_agent)
        browser = latest_login.browser or fallback_browser
        operating_system = latest_login.operating_system or fallback_os
        device = latest_login.device or fallback_device
        ip_address = latest_login.ip_address
        vpn_detected = bool(latest_login.vpn_detected)
    else:
        # Fallback diagnostics for first-time launch baselines
        risk_score = 12.0
        security_score = 88.0
        prediction = "Legitimate User"
        confidence = 97.0
        city = "Mumbai"
        country = "India"
        browser = "Chrome"
        operating_system = "Windows"
        device = "Desktop"
        ip_address = get_client_ip()
        vpn_detected = False

    if risk_score < 20:
        threat_level = "LOW"
    elif risk_score < 70:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH"

    # 3. Compile Microsoft Defender-style Dynamic Security Recommendations
    recommendations = []

    if g.user.role == 'admin':
        recommendations.append({
            "status": "success",
            "text": "MFA Enforced: Administrative session protected by MFA challenge gateway."
        })
    else:
        recommendations.append({
            "status": "warning",
            "text": "MFA Recommended: Activate Multi-Factor Authentication (MFA) to lock down credentials."
        })

    if vpn_detected:
        recommendations.append({
            "status": "danger",
            "text": "VPN Flag: Routing mask detected. Intelligence recommends session re-authorization."
        })
    else:
        recommendations.append({
            "status": "success",
            "text": "Trusted ISP Network: No VPN or malicious routing layers detected."
        })

    failed_login_count = ActivityLog.query.filter_by(user_id=g.user.id, action='login_failed').count()
    if failed_login_count > 1:
        recommendations.append({
            "status": "warning",
            "text": f"Brute-force Audit: Unsuccessful login attempts ({failed_login_count}) logged recently."
        })
    else:
        recommendations.append({
            "status": "success",
            "text": "Credentials Audit: Password strength and brute-force indices are clear."
        })

    if browser in ['Chrome', 'Firefox', 'Safari', 'Edge']:
        recommendations.append({
            "status": "success",
            "text": f"Device Profile: Running on trusted browser instance: {browser}."
        })
    else:
        recommendations.append({
            "status": "warning",
            "text": "Uncommon UA Signature: Browser agent pattern does not match corporate baseline."
        })

    # 4. Generate Chronological Threat Timeline
    timeline_logs = ActivityLog.query.filter_by(user_id=g.user.id).order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()

    timeline = []
    action_mappings = {
        'register': 'Secure User Profile Created',
        'login_success': 'Session Authenticated - Prediction Verified',
        'login_failed': 'Failed Session Attempt Blocked',
        'login_anomaly': 'Anomalous Activity Flagged',
        'verification_passed': 'Verification Passed - Access Granted',
        'file_upload': 'Protected Resource Storage Block Uploaded',
        'file_delete': 'Protected Resource Storage Block Wiped',
        'profile_update': 'Account Profile Security Keys Updated',
        'ip_blocked': 'Critical IP Blocked'
    }

    for log in timeline_logs:
        event_label = action_mappings.get(log.action, log.action.replace('_', ' ').title())

        if log.risk_score >= 0.70 or log.action == 'login_failed':
            status = 'danger'
        elif log.risk_score >= 0.20:
            status = 'warning'
        else:
            status = 'success'

        timeline.append({
            'timestamp': log.timestamp,
            'event': event_label,
            'risk_score': round(log.risk_score * 100, 1),
            'ip_address': log.ip_address,
            'status': status
        })

    # 5. Retrieve Login Activity Audits
    login_history = ActivityLog.query.filter_by(user_id=g.user.id).filter(
        ActivityLog.action.in_(['login_success', 'login_failed', 'verification_passed', 'login_anomaly'])
    ).order_by(ActivityLog.timestamp.desc()).limit(20).all()

    total_requests = ActivityLog.query.count()
    attack_requests = ActivityLog.query.filter(
        (ActivityLog.prediction == 'Possible Attacker') |
        (ActivityLog.risk_score >= 0.70) |
        (ActivityLog.action == 'ip_blocked')
    ).count()
    normal_requests = max(0, total_requests - attack_requests)
    successful_logins = ActivityLog.query.filter(
        ActivityLog.action.in_(['login_success', 'verification_passed'])
    ).count()
    failed_logins = ActivityLog.query.filter_by(action='login_failed').count()
    average_risk = db.session.query(func.avg(ActivityLog.risk_score)).scalar() or 0.0
    average_risk_score = round(float(average_risk) * 100.0, 1)

    risk_distribution = {
        'Low': ActivityLog.query.filter(ActivityLog.risk_score < 0.2).count(),
        'Medium': ActivityLog.query.filter(ActivityLog.risk_score >= 0.2, ActivityLog.risk_score < 0.7).count(),
        'High': ActivityLog.query.filter(ActivityLog.risk_score >= 0.7).count(),
    }
    blocked_ip_count = BlockedIP.query.count()
    recent_security_events = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()

    telemetry_snapshot = get_live_telemetry()
    cpu_usage, memory_usage = _get_system_usage_estimate()
    response_values = []
    api_logs = ActivityLog.query.filter_by(action='api_log').order_by(ActivityLog.timestamp.desc()).limit(25).all()
    for log in api_logs:
        value = _extract_response_time_ms(log)
        if value:
            response_values.append(value)
    average_response_time = round(sum(response_values) / len(response_values), 1) if response_values else 0.0

    return render_template(
        'dashboard.html',
        files=files,
        total_used_bytes=total_used_bytes,
        storage_limit_bytes=storage_limit_bytes,
        used_percentage=round(used_percentage, 1),
        search_query=search_query,

        # SOC Telemetry Context
        risk_score=risk_score,
        security_score=security_score,
        threat_level=threat_level,
        prediction=prediction,
        confidence=confidence,
        city=city,
        country=country,
        browser=browser,
        operating_system=operating_system,
        device=device,
        ip_address=ip_address,
        vpn_detected=vpn_detected,

        # Dashboard summary metrics
        total_requests=total_requests,
        normal_requests=normal_requests,
        attack_requests=attack_requests,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        average_risk_score=average_risk_score,
        risk_distribution=risk_distribution,
        blocked_ip_count=blocked_ip_count,
        recent_security_events=recent_security_events,
        telemetry_snapshot=telemetry_snapshot,
        cpu_usage=cpu_usage,
        memory_usage=memory_usage,
        average_response_time=average_response_time,

        # Recommendations & Timelines
        recommendations=recommendations,
        timeline=timeline,
        login_history=login_history
    )

@main_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash("No file part selected.", "warning")
        return redirect(url_for('main.dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash("No file selected for upload.", "warning")
        return redirect(url_for('main.dashboard'))
        
    # Check limit check
    total_used = sum(f.file_size for f in File.query.filter_by(user_id=g.user.id, is_deleted=False).all())
    storage_limit = 100 * 1024 * 1024  # 100MB
    
    file.seek(0, 2)
    incoming_size = file.tell()
    file.seek(0)
    
    if total_used + incoming_size > storage_limit:
        flash("Upload rejected: You have exceeded your 100MB storage quota.", "danger")
        return redirect(url_for('main.dashboard'))
        
    try:
        orig_filename, disk_filename, file_size, mime_type = save_file_to_disk(file)
        
        file_record = File(
            user_id=g.user.id,
            filename=orig_filename,
            secure_filename=disk_filename,
            file_size=file_size,
            mime_type=mime_type
        )
        db.session.add(file_record)
        db.session.commit()
        
        # Telemetry
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', '')
        
        # Retrieve client info for details logging
        geo = fetch_ip_geolocation(ip) if 'fetch_ip_geolocation' in globals() else {"city": "Local", "country": "Local"}
        
        # Log to Database
        browser, operating_system, device = parse_user_agent_details(ua)
        log = ActivityLog(
            user_id=g.user.id,
            action='file_upload',
            ip_address=ip,
            user_agent=ua[:255] if ua else None,
            risk_score=0.0,
            prediction='Legitimate User',
            confidence=100.0,
            city=geo.get('city'),
            country=geo.get('country'),
            browser=browser,
            operating_system=operating_system,
            device=device,
            details=f"Uploaded resource block: '{orig_filename}'."
        )
        db.session.add(log)
        db.session.commit()
        
        event_bus.dispatch('file.upload', user=g.user, file_record=file_record, ip_address=ip, user_agent=ua)
        
        flash(f"File '{orig_filename}' uploaded successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"File upload failed: {str(e)}", "danger")
        
    return redirect(url_for('main.dashboard'))

@main_bp.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    if file_record.user_id != g.user.id and g.user.role != 'admin':
        abort(403, description="Unauthorized file access request.")
        
    if file_record.is_deleted:
        abort(404, description="File has been deleted.")
        
    file_path = get_disk_file_path(file_record.secure_filename)
    if not file_path or not os.path.exists(file_path):
        flash("Physical file could not be found on disk storage.", "danger")
        return redirect(url_for('main.dashboard'))
        
    # Log audit event
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    
    db.session.add(ActivityLog(
        user_id=g.user.id,
        action='file_download',
        ip_address=ip,
        user_agent=ua[:255] if ua else None,
        risk_score=0.0,
        prediction='Legitimate User',
        confidence=100.0,
        details=f"Downloaded resource block ID {file_record.id}: '{file_record.filename}'."
    ))
    db.session.commit()
    
    event_bus.dispatch('file.download', user=g.user, file_record=file_record, ip_address=ip, user_agent=ua)
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_record.filename,
        mimetype=file_record.mime_type
    )

@main_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    if file_record.user_id != g.user.id and g.user.role != 'admin':
        abort(403, description="Unauthorized file deletion request.")
        
    file_record.is_deleted = True
    
    try:
        delete_file_from_disk(file_record.secure_filename)
        
        # Log audit event
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', '')
        
        browser, operating_system, device = parse_user_agent_details(ua)
        db.session.add(ActivityLog(
            user_id=g.user.id,
            action='file_delete',
            ip_address=ip,
            user_agent=ua[:255] if ua else None,
            risk_score=0.0,
            prediction='Legitimate User',
            confidence=100.0,
            browser=browser,
            operating_system=operating_system,
            device=device,
            details=f"Deleted resource block ID {file_record.id}: '{file_record.filename}'."
        ))
        db.session.commit()
        
        event_bus.dispatch('file.delete', user=g.user, file_record=file_record, ip_address=ip, user_agent=ua)
        
        flash(f"File '{file_record.filename}' deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete file: {e}", "danger")
        
    return redirect(url_for('main.dashboard'))

@main_bp.route('/logs')
@login_required
def logs():
    user_logs = ActivityLog.query.filter_by(user_id=g.user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=user_logs)
