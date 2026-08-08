import logging
import smtplib
from email.mime.text import MIMEText

from flask import abort, current_app, request

from app.models import ActivityLog, BlockedIP, db
from app.services.events import event_bus
from app.services.telemetry import parse_user_agent_details

logger = logging.getLogger(__name__)


def _is_localhost_ip(ip_address):
    if ip_address is None:
        return False
    normalized = str(ip_address).strip().lower()
    return normalized in {'127.0.0.1', '::1', 'localhost'} or normalized.startswith('127.')


def _send_security_alert_email(ip_address, reason="", prediction=None, confidence=None, risk_score=None):
    """Send a security alert email only if SMTP configuration is available."""
    try:
        app = current_app._get_current_object()
        smtp_host = app.config.get('MAIL_SERVER') or app.config.get('SMTP_SERVER')
        if not smtp_host:
            logger.info("SMTP is not configured; skipping security alert email.")
            return

        smtp_port = int(app.config.get('MAIL_PORT') or app.config.get('SMTP_PORT') or 587)
        username = app.config.get('MAIL_USERNAME') or app.config.get('SMTP_USERNAME')
        password = app.config.get('MAIL_PASSWORD') or app.config.get('SMTP_PASSWORD')
        sender = (
            app.config.get('MAIL_DEFAULT_SENDER')
            or app.config.get('MAIL_USERNAME')
            or app.config.get('SMTP_SENDER')
            or 'noreply@cloudvault.local'
        )

        recipients_config = (
            app.config.get('SECURITY_ALERT_EMAILS')
            or app.config.get('ADMINS')
            or app.config.get('MAIL_RECIPIENTS')
            or []
        )
        if isinstance(recipients_config, str):
            recipients = [recipients_config]
        else:
            recipients = list(recipients_config)

        if not recipients:
            logger.info("No security alert recipients configured; skipping email alert.")
            return

        payload = {
            'ip_address': ip_address,
            'reason': reason or 'Critical security event',
            'prediction': prediction or 'Possible Attacker',
            'confidence': confidence if confidence is not None else 'N/A',
            'risk_score': risk_score if risk_score is not None else 'N/A',
        }
        body = (
            "CloudVault Security Alert\n\n"
            f"IP: {payload['ip_address']}\n"
            f"Reason: {payload['reason']}\n"
            f"Prediction: {payload['prediction']}\n"
            f"Confidence: {payload['confidence']}\n"
            f"Risk Score: {payload['risk_score']}"
        )

        message = MIMEText(body, 'plain', 'utf-8')
        message['Subject'] = 'CloudVault Security Alert: Blocked IP'
        message['From'] = sender
        message['To'] = ', '.join(recipients)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if app.config.get('MAIL_USE_TLS', True) or app.config.get('SMTP_USE_TLS', True):
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(sender, recipients, message.as_string())

        logger.info("Security alert email sent successfully for IP: %s", ip_address)
    except Exception as exc:
        logger.warning("Security alert email could not be sent: %s", exc)


def get_client_ip():
    """
    Retrieves the actual client IP, handling proxies using the X-Forwarded-For header.
    """
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def check_ip_block():
    """
    Middleware check to execute before processing any route.
    If the requesting IP matches an entry in blocked_ips, access is forbidden.
    """
    ip_addr = get_client_ip()
    if _is_localhost_ip(ip_addr):
        return

    blocked_record = BlockedIP.query.filter_by(ip_address=ip_addr).first()
    if blocked_record:
        logger.warning(f"Blocked request attempt from IP: {ip_addr}. Reason: {blocked_record.reason}")
        abort(403, description=f"Access Denied: Your IP address ({ip_addr}) has been blacklisted. Reason: {blocked_record.reason}")


def handle_block_ip_event(ip_address, reason="", prediction=None, confidence=None, risk_score=None, **kwargs):
    """
    Event listener to commit an IP block directly to the database.
    """
    if ip_address is None:
        return

    normalized_ip = str(ip_address).strip()
    if not normalized_ip or _is_localhost_ip(normalized_ip):
        logger.warning("Attempted to auto-block localhost - operation bypassed for safety.")
        return

    existing = BlockedIP.query.filter_by(ip_address=normalized_ip).first()
    if existing:
        logger.warning(f"IP {normalized_ip} is already blocked. Duplicate block prevented.")
        if reason and existing.reason != reason:
            existing.reason = reason
            db.session.commit()
        return

    blocked = BlockedIP(ip_address=normalized_ip, reason=reason or "Security policy violation")
    db.session.add(blocked)

    browser, operating_system, device = parse_user_agent_details(kwargs.get('user_agent'))
    log = ActivityLog(
        user_id=kwargs.get('user_id'),
        username=kwargs.get('username'),
        action='ip_blocked',
        ip_address=normalized_ip,
        user_agent=kwargs.get('user_agent')[:255] if kwargs.get('user_agent') else None,
        request_method=kwargs.get('request_method'),
        endpoint=kwargs.get('endpoint'),
        prediction=prediction,
        confidence=confidence,
        risk_score=float(risk_score) if risk_score is not None else 0.0,
        details=reason or 'Critical attack detected and IP blocked automatically.',
        browser=browser,
        operating_system=operating_system,
        device=device,
    )
    db.session.add(log)
    db.session.commit()
    logger.warning(f"IP {normalized_ip} has been successfully added to the blocklist.")

    _send_security_alert_email(
        normalized_ip,
        reason=reason or 'Critical attack detected and IP blocked automatically.',
        prediction=prediction,
        confidence=confidence,
        risk_score=risk_score,
    )


# Connect the IP block trigger to the event bus
event_bus.subscribe('security.block_ip', handle_block_ip_event)
