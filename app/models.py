from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user') # 'user' or 'admin'
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")
    logs = db.relationship('ActivityLog', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    secure_filename = db.Column(db.String(255), nullable=False) # UUID-based name on disk
    file_size = db.Column(db.Integer, nullable=False) # In bytes
    mime_type = db.Column(db.String(100), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(100), nullable=False) # 'login_success', 'file_upload', etc.
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    request_method = db.Column(db.String(20), nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    login_success = db.Column(db.Boolean, nullable=True)
    risk_score = db.Column(db.Float, default=0.0) # Scaled 0.0 to 1.0 (or higher)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Advanced Security Telemetry Fields
    city = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    browser = db.Column(db.String(100), nullable=True)
    operating_system = db.Column(db.String(100), nullable=True)
    device = db.Column(db.String(100), nullable=True)
    prediction = db.Column(db.String(100), nullable=True) # 'Legitimate User' or 'Possible Attacker'
    confidence = db.Column(db.Float, nullable=True) # 0.0 to 100.0
    vpn_detected = db.Column(db.Boolean, default=False)

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
