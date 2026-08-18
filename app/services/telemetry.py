import logging
from app.models import ActivityLog, File, Prediction, db

logger = logging.getLogger(__name__)

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


def get_live_telemetry():
    """Return current telemetry values directly from the database for the dashboard metrics."""
    try:
        return {
            'total_api_calls': ActivityLog.query.count(),
            'login_success_count': ActivityLog.query.filter_by(action='login_success').count(),
            'login_failed_count': ActivityLog.query.filter_by(action='login_failed').count(),
            'files_uploaded': ActivityLog.query.filter_by(action='file_upload').count(),
            'files_downloaded': ActivityLog.query.filter_by(action='file_download').count(),
            'files_deleted': ActivityLog.query.filter_by(action='file_delete').count(),
            'total_predictions': Prediction.query.count(),
        }
    except Exception as e:
        logger.error(f"Error querying live telemetry metrics: {e}")
        return {
            'total_api_calls': 0,
            'login_success_count': 0,
            'login_failed_count': 0,
            'files_uploaded': 0,
            'files_downloaded': 0,
            'files_deleted': 0,
            'total_predictions': 0,
        }
