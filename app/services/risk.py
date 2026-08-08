import logging
from app.models import db, ActivityLog, BlockedIP, User
from app.services.events import event_bus
from app.services.telemetry import parse_user_agent_details

logger = logging.getLogger(__name__)


def normalize_risk_to_db(risk_value):
    """Convert a percentage 0-100 or normalized 0-1 risk to the database scale used by ActivityLog."""
    if risk_value is None:
        return 0.0
    risk_value = float(risk_value)
    if 0.0 <= risk_value <= 1.0:
        return round(max(0.0, min(1.0, risk_value)), 4)
    return round(max(0.0, min(1.0, risk_value / 100.0)), 4)


def normalize_risk_to_percent(risk_value):
    """Convert a database 0-1 value or a percentage 0-100 value into a percentage."""
    if risk_value is None:
        return 0.0
    risk_value = float(risk_value)
    if 0.0 <= risk_value <= 1.0:
        return round(risk_value * 100.0, 1)
    return round(max(0.0, min(100.0, risk_value)), 1)


def categorize_risk(risk_percentage):
    if risk_percentage <= 20:
        return 'Safe'
    if risk_percentage <= 50:
        return 'Low Risk'
    if risk_percentage <= 80:
        return 'Medium Risk'
    return 'Critical'


def get_latest_ml_login_record(ip_address=None, user_id=None):
    """Fetch the most recent ML-backed login log for the given IP or user."""
    query = ActivityLog.query
    if user_id is not None:
        query = query.filter(ActivityLog.user_id == user_id)
    if ip_address:
        query = query.filter(ActivityLog.ip_address == ip_address)
    query = query.filter(ActivityLog.action.in_(['login_success', 'login_failed', 'login_anomaly', 'verification_passed']))
    return query.order_by(ActivityLog.timestamp.desc()).first()


def analyze_login_risk(email, ip_address, user_agent, success, user_id=None):
    """Return the risk score in database scale while using the ML-generated login risk when available."""
    ml_log = get_latest_ml_login_record(ip_address=ip_address, user_id=user_id)

    if ml_log is not None and ml_log.risk_score is not None:
        risk_pct = normalize_risk_to_percent(ml_log.risk_score)
        risk_label = categorize_risk(risk_pct)
        details = (
            f"Context: IP={ip_address}, UA={user_agent[:50] if user_agent else 'Unknown'}... "
            f"| ML Risk={risk_pct}% | Category={risk_label}"
        )
        if ml_log.prediction:
            details += f" | Prediction={ml_log.prediction}"
        if ml_log.confidence is not None:
            details += f" | Confidence={ml_log.confidence}"
        return normalize_risk_to_db(risk_pct), details

    failed_count = ActivityLog.query.filter(
        ActivityLog.action == 'login_failed',
        ActivityLog.ip_address == ip_address
    ).count()

    if success:
        risk_pct = 0.0
        details = f"Context: IP={ip_address}, UA={user_agent[:50] if user_agent else 'Unknown'}... | Standard successful login verified."
    else:
        risk_pct = min(100.0, 15.0 * (failed_count + 1))
        details = f"Context: IP={ip_address}, UA={user_agent[:50] if user_agent else 'Unknown'}... | Repeated login failures: {failed_count + 1}"

    return normalize_risk_to_db(risk_pct), details


def analyze_file_risk(user, filename, file_size, ip_address):
    """
    Simulates ML anomaly detection on uploaded files (e.g. ransomware payload or malware injection).
    """
    risk_score = 0.0
    details = f"File={filename}, Size={file_size} bytes"

    suspicious_exts = ['.exe', '.sh', '.bat', '.py', '.js', '.scr', '.vbs', '.php']
    lower_name = filename.lower()

    if any(lower_name.endswith(ext) for ext in suspicious_exts):
        risk_score += 0.50
        details += " | Executable script file extension detected"

    parts = lower_name.split('.')
    if len(parts) > 2 and parts[-1] in ['exe', 'zip', 'rar', 'js', 'sh', 'html']:
        risk_score += 0.30
        details += " | Double extension injection detected"

    if file_size > 15 * 1024 * 1024:
        risk_score += 0.15
        details += " | High-volume file size anomaly"

    return min(1.0, risk_score), details


# Event handler callbacks
def handle_login_attempt(email, ip_address, user_agent, success, user_id=None):
    ml_log = get_latest_ml_login_record(ip_address=ip_address, user_id=user_id)

    if ml_log is not None and ml_log.risk_score is not None:
        risk_percentage = normalize_risk_to_percent(ml_log.risk_score)
        prediction = ml_log.prediction or ('Legitimate User' if success else 'Possible Attacker')
        confidence = ml_log.confidence if ml_log.confidence is not None else 0.0
        details = (
            f"ML-derived login risk: {risk_percentage}% | Category={categorize_risk(risk_percentage)} | "
            f"Prediction={prediction} | Confidence={confidence}"
        )
    else:
        risk_score, details = analyze_login_risk(email, ip_address, user_agent, success, user_id=user_id)
        risk_percentage = normalize_risk_to_percent(risk_score)
        prediction = 'Legitimate User' if success else 'Possible Attacker'
        confidence = 95.0 if success else 85.0
        details = details + f" | Prediction={prediction} | Confidence={confidence}"

    risk_db = normalize_risk_to_db(risk_percentage)
    action_type = 'login_success' if success else 'login_failed'

    browser, operating_system, device = parse_user_agent_details(user_agent)
    log = ActivityLog(
        user_id=user_id,
        action=action_type,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        risk_score=risk_db,
        prediction=prediction,
        confidence=confidence,
        details=details,
        username=(ml_log.username if ml_log is not None and ml_log.username else None),
        browser=browser,
        operating_system=operating_system,
        device=device,
    )
    db.session.add(log)

    if risk_percentage >= 81 and not success:
        event_bus.dispatch(
            'security.block_ip',
            ip_address=ip_address,
            reason=f"Critical login risk ({risk_percentage}% / {categorize_risk(risk_percentage)})"
        )

        browser, operating_system, device = parse_user_agent_details(user_agent)
        alert = ActivityLog(
            user_id=user_id,
            action='ip_blocked',
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None,
            risk_score=risk_db,
            prediction=prediction,
            confidence=confidence,
            details=(
                f"Critical risk detected on login. "
                f"Category={categorize_risk(risk_percentage)} | Prediction={prediction} | Confidence={confidence} | "
                f"Risk={risk_percentage}%"
            ),
            username=(ml_log.username if ml_log is not None and ml_log.username else None),
            browser=browser,
            operating_system=operating_system,
            device=device,
        )
        db.session.add(alert)

    db.session.commit()
    logger.info(f"Risk analysis complete for {action_type}. Score: {risk_percentage}% | Category={categorize_risk(risk_percentage)}")


def handle_file_upload(user, file_record, ip_address, user_agent):
    risk_score, details = analyze_file_risk(user, file_record.filename, file_record.file_size, ip_address)

    browser, operating_system, device = parse_user_agent_details(user_agent)
    log = ActivityLog(
        user_id=user.id,
        action='file_upload',
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        risk_score=risk_score,
        details=details,
        browser=browser,
        operating_system=operating_system,
        device=device,
    )
    db.session.add(log)
    db.session.commit()
    logger.info(f"Risk analysis complete for file upload. Score: {risk_score}")


def handle_file_download(user, file_record, ip_address, user_agent):
    browser, operating_system, device = parse_user_agent_details(user_agent)
    log = ActivityLog(
        user_id=user.id,
        action='file_download',
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        risk_score=0.0,
        details=f"Downloaded file ID {file_record.id}: {file_record.filename}",
        browser=browser,
        operating_system=operating_system,
        device=device,
    )
    db.session.add(log)
    db.session.commit()


def handle_file_delete(user, file_record, ip_address, user_agent):
    browser, operating_system, device = parse_user_agent_details(user_agent)
    log = ActivityLog(
        user_id=user.id,
        action='file_delete',
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        risk_score=0.0,
        details=f"Soft deleted file ID {file_record.id}: {file_record.filename}",
        browser=browser,
        operating_system=operating_system,
        device=device,
    )
    db.session.add(log)
    db.session.commit()


event_bus.subscribe('auth.login_attempt', handle_login_attempt)
event_bus.subscribe('file.upload', handle_file_upload)
event_bus.subscribe('file.download', handle_file_download)
event_bus.subscribe('file.delete', handle_file_delete)
