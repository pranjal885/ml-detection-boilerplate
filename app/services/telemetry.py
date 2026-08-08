import json
import logging
import platform
from datetime import datetime

from flask import request

from app.models import ActivityLog, db
from app.services.events import event_bus

logger = logging.getLogger(__name__)

# Simulated in-memory telemetry database/cache
# In production, this data would be forwarded to Prometheus, Grafana, or a Datadog agent.
telemetry_metrics = {
    'total_api_calls': 0,
    'login_success_count': 0,
    'login_failed_count': 0,
    'files_uploaded': 0,
    'files_downloaded': 0,
    'files_deleted': 0,
    'bytes_processed': 0,
    'network_logs': 0,
    'api_logs': 0,
    'application_logs': 0,
    'system_logs': 0,
}


def parse_user_agent_details(user_agent):
    """Return browser, operating system, and device details from a raw User-Agent string."""
    raw = (user_agent or '').strip()
    lower = raw.lower()

    browser = 'Unknown'
    operating_system = 'Unknown'
    device = 'Desktop'

    if 'edg/' in lower or 'edga/' in lower or 'edgios/' in lower:
        browser = 'Edge'
    elif 'opr/' in lower or 'opera' in lower:
        browser = 'Opera'
    elif 'firefox/' in lower:
        browser = 'Firefox'
    elif 'chrome/' in lower and 'safari/' in lower:
        browser = 'Chrome'
    elif 'safari/' in lower and 'chrome/' not in lower:
        browser = 'Safari'
    elif 'msie' in lower or 'trident/' in lower:
        browser = 'Internet Explorer'

    if 'windows' in lower:
        operating_system = 'Windows'
    elif 'macintosh' in lower or 'mac os' in lower:
        operating_system = 'macOS'
    elif 'android' in lower:
        operating_system = 'Android'
    elif 'iphone' in lower or 'ipad' in lower or 'ios' in lower:
        operating_system = 'iOS'
    elif 'linux' in lower:
        operating_system = 'Linux'

    if 'android' in lower and 'mobile' in lower:
        device = 'Mobile'
    elif 'ipad' in lower or 'tablet' in lower:
        device = 'Tablet'
    elif 'iphone' in lower or 'android' in lower:
        device = 'Mobile'

    return browser, operating_system, device


def _normalize_value(value, max_len=255):
    if value is None:
        return None
    if isinstance(value, str):
        return value[:max_len]
    return value


def _build_activity_log_entry(action, user_id=None, username=None, ip_address='Unknown', user_agent=None,
                             request_method=None, endpoint=None, risk_score=0.0, details=None,
                             login_success=None, **extra_fields):
    payload = {
        'timestamp': datetime.utcnow().isoformat(),
        'user_id': user_id,
        'username': username,
        'source_ip': ip_address,
        'user_agent': user_agent,
        'request_method': request_method,
        'endpoint': endpoint,
        'login_success': login_success,
        'action': action,
        'risk_score': risk_score,
        'details': details,
    }
    payload.update(extra_fields)

    browser, operating_system, device = parse_user_agent_details(user_agent)
    if extra_fields.get('browser'):
        browser = extra_fields.get('browser')
    if extra_fields.get('operating_system'):
        operating_system = extra_fields.get('operating_system')
    if extra_fields.get('device'):
        device = extra_fields.get('device')

    log = ActivityLog(
        user_id=user_id,
        username=username,
        action=action,
        ip_address=_normalize_value(ip_address, 45) or 'Unknown',
        user_agent=_normalize_value(user_agent, 255),
        request_method=_normalize_value(request_method, 20),
        endpoint=_normalize_value(endpoint, 255),
        login_success=login_success,
        risk_score=float(risk_score or 0.0),
        details=json.dumps(payload, default=str) if details is None else details,
        browser=browser,
        operating_system=operating_system,
        device=device,
        prediction=extra_fields.get('prediction'),
        confidence=extra_fields.get('confidence'),
        vpn_detected=extra_fields.get('vpn_detected', False),
        city=extra_fields.get('city'),
        country=extra_fields.get('country'),
        latitude=extra_fields.get('latitude'),
        longitude=extra_fields.get('longitude'),
    )
    return log


def build_login_telemetry_record(user=None, username=None, success=None, ip_address=None, user_agent=None,
                                request_method=None, endpoint=None, timestamp=None):
    """Return a normalized telemetry payload for a login event.

    This is intentionally structured for future ML consumption, while also fitting the
    current activity_logs table design.
    """
    timestamp = timestamp or datetime.utcnow()
    resolved_username = username or (user.username if user is not None else None)
    record = {
        'timestamp': timestamp,
        'user_id': getattr(user, 'id', None),
        'username': resolved_username,
        'source_ip': ip_address,
        'user_agent': user_agent,
        'request_method': request_method,
        'endpoint': endpoint,
        'login_success': bool(success) if success is not None else None,
    }
    return record


def enrich_activity_log(log, user=None, username=None, success=None, ip_address=None, user_agent=None,
                        request_method=None, endpoint=None, timestamp=None):
    """Normalize a login-related ActivityLog instance with telemetry fields.

    This keeps the app logic consistent with the existing database schema while exposing
    the structured values required by Task 6 ML workflows.
    """
    if log is None:
        raise ValueError('An ActivityLog instance is required.')

    payload = build_login_telemetry_record(
        user=user,
        username=username,
        success=success,
        ip_address=ip_address or log.ip_address,
        user_agent=user_agent or log.user_agent,
        request_method=request_method,
        endpoint=endpoint,
        timestamp=timestamp or getattr(log, 'timestamp', None) or datetime.utcnow(),
    )

    log.user_id = payload['user_id'] if payload['user_id'] is not None else log.user_id
    log.username = payload['username'] or log.username
    log.ip_address = payload['source_ip'] or log.ip_address
    log.user_agent = payload['user_agent'] or log.user_agent
    log.request_method = payload['request_method'] or log.request_method
    log.endpoint = payload['endpoint'] or log.endpoint
    log.login_success = payload['login_success'] if payload['login_success'] is not None else log.login_success
    log.timestamp = payload['timestamp'] if payload['timestamp'] else log.timestamp
    log.action = 'login_success' if payload['login_success'] is True else ('login_failed' if payload['login_success'] is False else log.action)

    if not log.details:
        log.details = json.dumps(payload, default=str)
    else:
        details_payload = {
            **payload,
            'details': log.details,
        }
        log.details = json.dumps(details_payload, default=str)

    return log


def record_login_telemetry(user=None, username=None, success=None, request=None, ip_address=None, user_agent=None,
                          endpoint=None, request_method=None, log=None):
    """Persist a normalized login telemetry record into the activity_logs table."""
    if log is None:
        log = ActivityLog(
            user_id=getattr(user, 'id', None),
            username=username or (user.username if user is not None else None),
            action='login_success' if success is True else 'login_failed' if success is False else 'login_attempt',
            ip_address=ip_address or 'Unknown',
            user_agent=user_agent,
            request_method=request_method,
            endpoint=endpoint,
            login_success=bool(success) if success is not None else None,
            details='login telemetry'
        )

    if request is not None:
        request_method = request.method if request_method is None else request_method
        endpoint = request.endpoint if endpoint is None else endpoint

    enrich_activity_log(
        log=log,
        user=user,
        username=username,
        success=success,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
    )

    if log.id is None:
        db.session.add(log)
    db.session.commit()
    return log


def get_login_telemetry(limit=100):
    """Return a list of login payloads suitable for future ML feature extraction."""
    records = ActivityLog.query.filter(ActivityLog.login_success.isnot(None)).order_by(ActivityLog.timestamp.desc()).limit(limit).all()
    return [
        {
            'timestamp': record.timestamp.isoformat() if record.timestamp else None,
            'user_id': record.user_id,
            'username': record.username,
            'source_ip': record.ip_address,
            'user_agent': record.user_agent,
            'request_method': record.request_method,
            'endpoint': record.endpoint,
            'login_success': record.login_success,
            'risk_score': record.risk_score,
            'action': record.action,
        }
        for record in records
    ]


def collect_network_log(ip_address='Unknown', user_agent=None, request_method='GET', endpoint='/',
                        status_code=200, protocol='HTTP', bytes_sent=0, bytes_received=0,
                        user_id=None, username=None, risk_score=0.0, details=None):
    """Store network-layer telemetry inside ActivityLog."""
    telemetry_metrics['network_logs'] += 1
    payload = {
        'event_type': 'network',
        'protocol': protocol,
        'status_code': status_code,
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_received,
    }
    if details:
        payload['details'] = details
    log = _build_activity_log_entry(
        action='network_log',
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        risk_score=risk_score,
        details=json.dumps(payload, default=str),
    )
    db.session.add(log)
    db.session.commit()
    return log


def collect_api_log(ip_address='Unknown', user_agent=None, request_method='GET', endpoint='/',
                    status_code=200, response_time_ms=None, user_id=None, username=None,
                    risk_score=0.0, details=None):
    """Store API request telemetry inside ActivityLog."""
    telemetry_metrics['api_logs'] += 1
    telemetry_metrics['total_api_calls'] += 1
    payload = {
        'event_type': 'api',
        'status_code': status_code,
        'response_time_ms': response_time_ms,
    }
    if details:
        payload['details'] = details
    log = _build_activity_log_entry(
        action='api_log',
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        risk_score=risk_score,
        details=json.dumps(payload, default=str),
    )
    db.session.add(log)
    db.session.commit()
    return log


def collect_application_log(level='INFO', message='Application event', user_id=None, username=None,
                           ip_address='Unknown', user_agent=None, request_method=None, endpoint=None,
                           risk_score=0.0, details=None):
    """Store application event telemetry inside ActivityLog."""
    telemetry_metrics['application_logs'] += 1
    payload = {
        'event_type': 'application',
        'level': level,
        'message': message,
    }
    if details:
        payload['details'] = details
    log = _build_activity_log_entry(
        action='application_log',
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        risk_score=risk_score,
        details=json.dumps(payload, default=str),
    )
    db.session.add(log)
    db.session.commit()
    return log


def collect_system_log(cpu_usage=None, memory_usage=None, response_time_ms=None, ip_address='Unknown',
                      user_agent=None, endpoint=None, user_id=None, username=None, risk_score=0.0, details=None):
    """Store system resource telemetry inside ActivityLog."""
    telemetry_metrics['system_logs'] += 1
    payload = {
        'event_type': 'system',
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'response_time_ms': response_time_ms,
        'platform': platform.system(),
    }
    if details:
        payload['details'] = details
    log = _build_activity_log_entry(
        action='system_log',
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method='SYSTEM',
        endpoint=endpoint,
        risk_score=risk_score,
        details=json.dumps(payload, default=str),
    )
    db.session.add(log)
    db.session.commit()
    return log


def track_request_metric(event_name):
    telemetry_metrics['total_api_calls'] += 1


def handle_login_metric(email, ip_address, user_agent, success, user_id=None):
    track_request_metric('login')
    if success:
        telemetry_metrics['login_success_count'] += 1
    else:
        telemetry_metrics['login_failed_count'] += 1


def handle_upload_metric(user, file_record, ip_address, user_agent):
    track_request_metric('upload')
    telemetry_metrics['files_uploaded'] += 1
    telemetry_metrics['bytes_processed'] += file_record.file_size


def handle_download_metric(user, file_record, ip_address, user_agent):
    track_request_metric('download')
    telemetry_metrics['files_downloaded'] += 1


def handle_delete_metric(user, file_record, ip_address, user_agent):
    track_request_metric('delete')
    telemetry_metrics['files_deleted'] += 1


def handle_network_log_event(ip_address='Unknown', user_agent=None, request_method='GET', endpoint='/',
                            status_code=200, protocol='HTTP', bytes_sent=0, bytes_received=0,
                            user_id=None, username=None, risk_score=0.0, details=None):
    return collect_network_log(
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        status_code=status_code,
        protocol=protocol,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        user_id=user_id,
        username=username,
        risk_score=risk_score,
        details=details,
    )


def handle_api_log_event(ip_address='Unknown', user_agent=None, request_method='GET', endpoint='/',
                        status_code=200, response_time_ms=None, user_id=None, username=None,
                        risk_score=0.0, details=None):
    return collect_api_log(
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        status_code=status_code,
        response_time_ms=response_time_ms,
        user_id=user_id,
        username=username,
        risk_score=risk_score,
        details=details,
    )


def handle_application_log_event(level='INFO', message='Application event', user_id=None, username=None,
                                ip_address='Unknown', user_agent=None, request_method=None, endpoint=None,
                                risk_score=0.0, details=None):
    return collect_application_log(
        level=level,
        message=message,
        user_id=user_id,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        request_method=request_method,
        endpoint=endpoint,
        risk_score=risk_score,
        details=details,
    )


def handle_system_log_event(cpu_usage=None, memory_usage=None, response_time_ms=None, ip_address='Unknown',
                          user_agent=None, endpoint=None, user_id=None, username=None, risk_score=0.0, details=None):
    return collect_system_log(
        cpu_usage=cpu_usage,
        memory_usage=memory_usage,
        response_time_ms=response_time_ms,
        ip_address=ip_address,
        user_agent=user_agent,
        endpoint=endpoint,
        user_id=user_id,
        username=username,
        risk_score=risk_score,
        details=details,
    )


# Register metric tracking with the Event Bus
event_bus.subscribe('auth.login_attempt', handle_login_metric)
event_bus.subscribe('file.upload', handle_upload_metric)
event_bus.subscribe('file.download', handle_download_metric)
event_bus.subscribe('file.delete', handle_delete_metric)
event_bus.subscribe('telemetry.network', handle_network_log_event)
event_bus.subscribe('telemetry.api', handle_api_log_event)
event_bus.subscribe('telemetry.application', handle_application_log_event)
event_bus.subscribe('telemetry.system', handle_system_log_event)


def get_live_telemetry():
    """Return current telemetry values directly from ActivityLog for up-to-date dashboard metrics."""
    return {
        'total_api_calls': ActivityLog.query.filter(ActivityLog.action.in_(['api_log', 'network_log', 'application_log', 'system_log'])).count(),
        'login_success_count': ActivityLog.query.filter(ActivityLog.action.in_(['login_success', 'verification_passed'])).count(),
        'login_failed_count': ActivityLog.query.filter_by(action='login_failed').count(),
        'files_uploaded': ActivityLog.query.filter_by(action='file_upload').count(),
        'files_downloaded': ActivityLog.query.filter_by(action='file_download').count(),
        'files_deleted': ActivityLog.query.filter_by(action='file_delete').count(),
        'bytes_processed': db.session.query(db.func.sum(ActivityLog.risk_score)).scalar() or 0,
        'network_logs': ActivityLog.query.filter_by(action='network_log').count(),
        'api_logs': ActivityLog.query.filter_by(action='api_log').count(),
        'application_logs': ActivityLog.query.filter_by(action='application_log').count(),
        'system_logs': ActivityLog.query.filter_by(action='system_log').count(),
    }
