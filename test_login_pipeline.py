import os
import unittest
from flask import session
from app import create_app
from app.models import db, User, BlockedIP, ActivityLog
from app.services.security import get_client_ip

class TestLoginPipeline(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        self.app = create_app()
        self.app.config['TESTING'] = True
        # Use an in-memory SQLite database for test isolation if needed,
        # but since we want to run against the production-like local DB:
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Ensure database tables exist
        db.create_all()

        # Seed test user
        self.username = "testuser"
        self.email = "testuser@example.com"
        self.password = "securepass123"
        
        user = User.query.filter_by(email=self.email).first()
        if not user:
            user = User(username=self.username, email=self.email, role='user')
            user.set_password(self.password)
            db.session.add(user)
            db.session.commit()
            
        # Clean up any blocks for our test IPs
        self.legit_ip = "103.132.148.4"
        self.malicious_ip = "198.51.100.1" # triggers VPN detection in VPNIntelligenceModule
        
        BlockedIP.query.filter(BlockedIP.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        ActivityLog.query.filter(ActivityLog.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        db.session.commit()

    def tearDown(self):
        # Clean up test user's test logs and blocks
        BlockedIP.query.filter(BlockedIP.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        ActivityLog.query.filter(ActivityLog.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        db.session.commit()
        self.app_context.pop()

    def test_legitimate_login(self):
        """Verify that a legitimate login does not trigger a 403 or IP blocking."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'X-Forwarded-For': self.legit_ip
        }
        
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, headers=headers, follow_redirects=True)
        
        # Assert response is successful and not forbidden
        self.assertNotEqual(response.status_code, 403)
        
        # Verify the IP is NOT blacklisted
        blocked = BlockedIP.query.filter_by(ip_address=self.legit_ip).first()
        self.assertIsNone(blocked, f"Legitimate IP {self.legit_ip} was blocked!")
        
        # Verify the activity log entry for the login
        # Since it's a first login/baseline, anomalies are False, VPN is False, failed attempts are 0.
        # Scaled prediction should be Legitimate User (0% risk)
        last_log = ActivityLog.query.filter_by(ip_address=self.legit_ip).order_by(ActivityLog.timestamp.desc()).first()
        self.assertIsNotNone(last_log)
        print(f"\n[TEST_LEGIT] Action: {last_log.action}, Risk: {last_log.risk_score * 100}%, Prediction: {last_log.prediction}")
        self.assertEqual(last_log.action, 'login_success')
        self.assertEqual(last_log.risk_score, 0.0)

    def test_high_risk_login_blocking(self):
        """Verify that a login containing high-risk features triggers block list registry."""
        # 1. Simulate prior failed login attempts from this IP to build up failed login count
        # In risk.py: risk = min(100.0, 15.0 * (failed_count + 1))
        # But wait! If we fail the login multiple times using wrong password:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'X-Forwarded-For': self.malicious_ip # This IP starts with '198.51.', triggering VPN intelligence module!
        }
        
        # Make a few failed attempts first to raise risk profile
        for _ in range(2):
            self.client.post('/login', data={
                'email': self.email,
                'password': 'wrongpassword'
            }, headers=headers, follow_redirects=True)
            
        # Try login with correct credentials from high-risk VPN IP after failed attempts
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, headers=headers, follow_redirects=True)
        
        # Check if the malicious IP got blocked
        blocked = BlockedIP.query.filter_by(ip_address=self.malicious_ip).first()
        self.assertIsNotNone(blocked, "High risk malicious login IP was not blocked!")
        print(f"[TEST_MALICIOUS] Blocked successfully. Reason: {blocked.reason}")
        
        # Try any route and it should yield 403 Forbidden now
        response2 = self.client.get('/', headers=headers)
        self.assertEqual(response2.status_code, 403)
        self.assertIn("Access Denied", response2.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
