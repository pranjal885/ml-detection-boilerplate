import os
from flask import Flask, session, g
from app.config import Config
from app.models import db, User

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize Database Extension
    db.init_app(app)
    
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

    @app.template_filter('json_loads')
    def json_loads_filter(json_str):
        import json
        try:
            return json.loads(json_str)
        except Exception:
            return {}


    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp
    from app.routes.prediction import prediction_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(prediction_bp)
    
    # Initialize db schema automatic creation for development / SQLite fallback
    with app.app_context():
        # Create database tables if they do not exist
        db.create_all()

        # Seed an admin user automatically if no user exists for test convenience
        seed_admin_user()

    return app

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
