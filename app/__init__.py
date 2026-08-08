import os
from sqlalchemy import text
from flask import Flask, session, g
from app.config import Config
from app.models import db, User
from app.services.security import check_ip_block


def ensure_activity_log_telemetry_columns():
    """Add required telemetry columns to existing databases without breaking older installs."""
    inspector = db.inspect(db.engine)
    columns = {column['name'] for column in inspector.get_columns('activity_logs')}
    required_columns = {
        'username': 'VARCHAR(150)',
        'request_method': 'VARCHAR(20)',
        'endpoint': 'VARCHAR(255)',
        'login_success': 'BOOLEAN',
    }

    for column_name, column_type in required_columns.items():
        if column_name not in columns:
            db.session.execute(text(f'ALTER TABLE activity_logs ADD COLUMN {column_name} {column_type}'))
    db.session.commit()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize Database Extension
    db.init_app(app)
    
    # Register Security Middleware
    @app.before_request
    def run_security_checks():
        # Exclude static assets from firewall checking for performance
        if not request_is_static():
            check_ip_block()
            
    # Load user context globally if logged in
    @app.before_request
    def load_logged_in_user():
        user_id = session.get('user_id')
        if user_id is None:
            g.user = None
        else:
            g.user = User.query.get(user_id)
            
    # Register Template Context Processors & Filters
    @app.template_filter('format_size')
    def format_size_filter(size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    
    # Initialize db schema automatic creation for development / SQLite fallback
    with app.app_context():
        # Ensures import of event listeners so risk / telemetry is wired up immediately
        from app.services import risk, telemetry

        # Create database tables if they do not exist
        db.create_all()
        ensure_activity_log_telemetry_columns()

        # Seed an admin user automatically if no user exists for test convenience
        seed_admin_user()
        clear_env_blocked_ip()

    return app

def request_is_static():
    from flask import request
    return request.path.startswith('/static/') or request.path == '/favicon.ico'

def seed_admin_user():
    """
    Seeds a default admin user on first launch if the user base is empty.
    """
    admin_exists = User.query.filter_by(role='admin').first()
    if not admin_exists:
        try:
            admin = User(
                username='admin',
                email='admin@cloudvault.com',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Successfully seeded database with admin user: admin@cloudvault.com / admin123")
        except Exception as e:
            db.session.rollback()
            print(f"Error seeding admin user: {e}")


def clear_env_blocked_ip():
    """
    Clears stale database blocks and failed activity logs for the IP specified
    in the CLEAR_BLOCKED_IP environment variable.
    """
    import os
    target_ip = os.environ.get('CLEAR_BLOCKED_IP')
    if not target_ip:
        return

    # Basic sanitization / validation
    target_ip = target_ip.strip()
    if not target_ip:
        return

    from app.models import db, BlockedIP, ActivityLog
    try:
        # Delete only matching BlockedIP
        deleted_blocks = db.session.query(BlockedIP).filter_by(ip_address=target_ip).delete()
        
        # Delete only matching login_failed logs
        deleted_logs = db.session.query(ActivityLog).filter_by(ip_address=target_ip, action='login_failed').delete()
        
        if deleted_blocks > 0 or deleted_logs > 0:
            db.session.commit()
            print(f"[STARTUP] Successfully cleared {deleted_blocks} block(s) and {deleted_logs} log(s) for IP: {target_ip}")
        else:
            print(f"[STARTUP] No records found to clear for IP: {target_ip}")
    except Exception as e:
        db.session.rollback()
        print(f"[STARTUP] Error clearing IP records for {target_ip}: {e}")
