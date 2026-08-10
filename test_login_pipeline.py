import os
import unittest
from datetime import datetime, timedelta
from flask import session
from app import create_app
from app.models import db, User, BlockedIP, ActivityLog
from app.services.security import get_client_ip

class TestLoginPipeline(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        self.app = create_app()
        self.app.config['TESTING'] = True
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
            
        self.legit_ip = "103.132.148.4"
        self.malicious_ip = "198.51.100.1" # triggers VPN detection in VPNIntelligenceModule
        
        # Clean up database tables for these test IPs
        BlockedIP.query.filter(BlockedIP.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        ActivityLog.query.filter(ActivityLog.ip_address.in_([self.legit_ip, self.malicious_ip])).delete()
        db.session.commit()

    def tearDown(self):
        # Clean up database tables for these test IPs
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
        last_log = ActivityLog.query.filter_by(ip_address=self.legit_ip).order_by(ActivityLog.timestamp.desc()).first()
        self.assertIsNotNone(last_log)
        print(f"\n[TEST_LEGIT] Action: {last_log.action}, Risk: {last_log.risk_score * 100}%, Prediction: {last_log.prediction}")
        self.assertEqual(last_log.action, 'login_success')
        self.assertEqual(last_log.risk_score, 0.0)

    def test_successful_credential_high_risk_reaches_mfa(self):
        """Verify that a login attempt with CORRECT credentials but high risk triggers MFA redirect and does NOT block the IP."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'X-Forwarded-For': self.malicious_ip
        }
        
        # 1. Add 4 failed logins to DB to simulate history
        for _ in range(4):
            log = ActivityLog(
                user_id=None,
                action='login_failed',
                ip_address=self.malicious_ip,
                risk_score=0.71,
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
        db.session.commit()
        
        # 2. Attempt successful login (correct credentials)
        response = self.client.post('/login', data={
            'email': self.email,
            'password': self.password
        }, headers=headers)
        
        # Risk score will be 89% (from failed_login_count=4).
        # It should redirect to identity verification
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/verify-identity'))
        
        # IP should NOT be blocked in the BlockedIP table
        blocked = BlockedIP.query.filter_by(ip_address=self.malicious_ip).first()
        self.assertIsNone(blocked, "IP was incorrectly blocked on successful credentials verification!")
        print("[TEST_SUCCESSFUL_HIGH_RISK] Reached MFA redirect without IP blocking.")

    def test_failed_credential_high_risk_triggers_block(self):
        """Verify that a login attempt with WRONG credentials and high risk triggers IP blocking."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'X-Forwarded-For': self.malicious_ip
        }
        
        # 1. Add 4 failed logins to DB to simulate history
        for _ in range(4):
            log = ActivityLog(
                user_id=None,
                action='login_failed',
                ip_address=self.malicious_ip,
                risk_score=0.71,
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
        db.session.commit()
        
        # 2. Attempt failed login (incorrect credentials)
        response = self.client.post('/login', data={
            'email': self.email,
            'password': 'wrongpassword'
        }, headers=headers, follow_redirects=True)
        
        # IP should be blocked in BlockedIP table
        blocked = BlockedIP.query.filter_by(ip_address=self.malicious_ip).first()
        self.assertIsNotNone(blocked, "IP was not blocked on failed credentials verification with high risk!")
        print(f"[TEST_FAILED_HIGH_RISK] Successfully blocked IP. Reason: {blocked.reason}")

    def test_failed_login_time_window(self):
        """Verify that failed logins older than 24 hours are excluded from the risk counter."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'X-Forwarded-For': self.malicious_ip
        }
        
        # 1. Add 4 stale failed logins to DB (older than 24 hours)
        stale_time = datetime.utcnow() - timedelta(hours=25)
        for _ in range(4):
            log = ActivityLog(
                user_id=None,
                action='login_failed',
                ip_address=self.malicious_ip,
                risk_score=0.71,
                timestamp=stale_time
            )
            db.session.add(log)
        db.session.commit()
        
        # 2. Attempt failed login (incorrect credentials)
        # This attempt should only count 0 previous failed attempts because the stale attempts are > 24 hours old.
        # Thus, failed_login_count parameter = 1. Risk will be 71% (Medium), which is < 81%, so it should NOT block the IP.
        response = self.client.post('/login', data={
            'email': self.email,
            'password': 'wrongpassword'
        }, headers=headers, follow_redirects=True)
        
        blocked = BlockedIP.query.filter_by(ip_address=self.malicious_ip).first()
        self.assertIsNone(blocked, "IP was incorrectly blocked due to stale (>24h) failed attempts!")
        print("[TEST_TIME_WINDOW] Stale failed attempts successfully excluded from risk calculation.")

    def test_env_var_clears_blocked_ip_when_set(self):
        """Verify that clear_env_blocked_ip deletes the specified IP block and logs, while leaving others untouched."""
        from app import clear_env_blocked_ip
        
        target_ip = "198.51.200.1"
        other_ip = "198.51.200.2"
        
        # Clean up database tables for these test IPs
        BlockedIP.query.filter(BlockedIP.ip_address.in_([target_ip, other_ip])).delete()
        ActivityLog.query.filter(ActivityLog.ip_address.in_([target_ip, other_ip])).delete()
        db.session.commit()
        
        # Insert blocks
        db.session.add(BlockedIP(ip_address=target_ip, reason="Test block target"))
        db.session.add(BlockedIP(ip_address=other_ip, reason="Test block other"))
        
        # Insert activity logs
        db.session.add(ActivityLog(ip_address=target_ip, action='login_failed', risk_score=0.71))
        db.session.add(ActivityLog(ip_address=other_ip, action='login_failed', risk_score=0.71))
        db.session.commit()
        
        # Set env var
        os.environ['CLEAR_BLOCKED_IP'] = target_ip
        
        try:
            # Run cleanup
            clear_env_blocked_ip()
            
            # Assertions
            # Target IP must be deleted
            self.assertIsNone(BlockedIP.query.filter_by(ip_address=target_ip).first())
            self.assertEqual(ActivityLog.query.filter_by(ip_address=target_ip, action='login_failed').count(), 0)
            
            # Other IP must remain untouched
            self.assertIsNotNone(BlockedIP.query.filter_by(ip_address=other_ip).first())
            self.assertEqual(ActivityLog.query.filter_by(ip_address=other_ip, action='login_failed').count(), 1)
            
        finally:
            # Cleanup
            os.environ.pop('CLEAR_BLOCKED_IP', None)
            BlockedIP.query.filter(BlockedIP.ip_address.in_([target_ip, other_ip])).delete()
            ActivityLog.query.filter(ActivityLog.ip_address.in_([target_ip, other_ip])).delete()
            db.session.commit()

    def test_env_var_does_nothing_when_absent(self):
        """Verify that clear_env_blocked_ip does nothing when the environment variable is absent."""
        from app import clear_env_blocked_ip
        
        target_ip = "198.51.200.1"
        
        # Clean up database tables for these test IPs
        BlockedIP.query.filter_by(ip_address=target_ip).delete()
        ActivityLog.query.filter_by(ip_address=target_ip).delete()
        db.session.commit()
        
        # Insert block
        db.session.add(BlockedIP(ip_address=target_ip, reason="Test block target"))
        db.session.add(ActivityLog(ip_address=target_ip, action='login_failed', risk_score=0.71))
        db.session.commit()
        
        # Ensure env var is absent
        os.environ.pop('CLEAR_BLOCKED_IP', None)
        
        try:
            # Run cleanup
            clear_env_blocked_ip()
            
            # Target IP must NOT be deleted
            self.assertIsNotNone(BlockedIP.query.filter_by(ip_address=target_ip).first())
            self.assertEqual(ActivityLog.query.filter_by(ip_address=target_ip, action='login_failed').count(), 1)
            
        finally:
            BlockedIP.query.filter_by(ip_address=target_ip).delete()
            ActivityLog.query.filter_by(ip_address=target_ip).delete()
            db.session.commit()

    def test_failed_attempts_accumulate_before_success(self):
        """TEST 1 — Failed attempts accumulate before success"""
        from app.routes.auth import get_failed_login_count
        test_ip = "103.132.148.99"
        
        # Ensure clean state
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Start at 0
        self.assertEqual(get_failed_login_count(test_ip), 0)
        
        # Add failed login logs
        for i in range(3):
            db.session.add(ActivityLog(
                ip_address=test_ip,
                action='login_failed',
                timestamp=datetime.utcnow() - timedelta(minutes=10 - i)
            ))
            db.session.commit()
            self.assertEqual(get_failed_login_count(test_ip), i + 1)

    def test_successful_authentication_resets_counter(self):
        """TEST 2 — Successful authentication resets the effective counter"""
        from app.routes.auth import get_failed_login_count
        test_ip = "103.132.148.99"
        
        # Ensure clean state
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Create 3 failed logs
        for i in range(3):
            db.session.add(ActivityLog(
                ip_address=test_ip,
                action='login_failed',
                timestamp=datetime.utcnow() - timedelta(minutes=15 - i)
            ))
        db.session.commit()
        
        # Create a successful authentication event (login_success)
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_success',
            timestamp=datetime.utcnow() - timedelta(minutes=5)
        ))
        db.session.commit()
        
        # Create subsequent failed login
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_failed',
            timestamp=datetime.utcnow()
        ))
        db.session.commit()
        
        # The counter must ignore the 3 failures before successful authentication and only count 1
        self.assertEqual(get_failed_login_count(test_ip), 1)

    def test_mfa_success_resets_counter(self):
        """TEST 3 — MFA success resets the effective counter"""
        from app.routes.auth import get_failed_login_count
        test_ip = "103.132.148.99"
        
        # Ensure clean state
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Create prior failures
        for i in range(2):
            db.session.add(ActivityLog(
                ip_address=test_ip,
                action='login_failed',
                timestamp=datetime.utcnow() - timedelta(minutes=20 - i)
            ))
        db.session.commit()
        
        # Create the successful MFA verification event (verification_passed)
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='verification_passed',
            timestamp=datetime.utcnow() - timedelta(minutes=10)
        ))
        db.session.commit()
        
        # Create a subsequent failure
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_failed',
            timestamp=datetime.utcnow()
        ))
        db.session.commit()
        
        # Only the failure after the verification should be counted
        self.assertEqual(get_failed_login_count(test_ip), 1)

    def test_historical_audit_logs_remain_intact(self):
        """TEST 4 — Historical audit logs remain intact"""
        test_ip = "103.132.148.99"
        
        # Ensure clean state
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Create failures
        db.session.add(ActivityLog(ip_address=test_ip, action='login_failed'))
        db.session.commit()
        
        # Create verification success
        db.session.add(ActivityLog(ip_address=test_ip, action='verification_passed'))
        db.session.commit()
        
        # Verify the original login_failed still exists in database (count remains 1)
        all_failed_count = ActivityLog.query.filter_by(ip_address=test_ip, action='login_failed').count()
        self.assertEqual(all_failed_count, 1)

    def test_twenty_four_hour_boundary_enforced(self):
        """TEST 5 — 24-hour boundary remains enforced"""
        from app.routes.auth import get_failed_login_count
        test_ip = "103.132.148.99"
        
        # Ensure clean state
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Create failed login older than 24 hours (e.g. 25h)
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_failed',
            timestamp=datetime.utcnow() - timedelta(hours=25)
        ))
        
        # Create successful login
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_success',
            timestamp=datetime.utcnow() - timedelta(hours=2)
        ))
        
        # Create failed login within 24 hours and after the successful login
        db.session.add(ActivityLog(
            ip_address=test_ip,
            action='login_failed',
            timestamp=datetime.utcnow() - timedelta(hours=1)
        ))
        db.session.commit()
        
        # Only the current failure (1h ago) should be counted; the 25h failure is out of window
        self.assertEqual(get_failed_login_count(test_ip), 1)

    def test_brute_force_protection_still_works(self):
        """TEST 6 — Existing brute-force protection still works"""
        from app.routes.auth import get_failed_login_count
        test_ip = "103.132.148.99"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'X-Forwarded-For': test_ip
        }
        
        # Clean up database tables for this test IP
        BlockedIP.query.filter_by(ip_address=test_ip).delete()
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()
        
        # Perform repeated failed logins (incorrect credentials)
        # Attempt 1: DB count = 0 -> model gets 1 -> risk = 71%. No block. Logs committed = 2.
        # Attempt 2: DB count = 2 -> model gets 3 -> risk = 76%. No block. Logs committed = 4.
        # Attempt 3: DB count = 4 -> model gets 5 -> risk = 92%. Blocks!
        for i in range(3):
            response = self.client.post('/login', data={
                'email': self.email,
                'password': 'wrongpassword'
            }, headers=headers, follow_redirects=True)
            
            blocked = BlockedIP.query.filter_by(ip_address=test_ip).first()
            if i < 2:
                self.assertIsNone(blocked, f"IP blocked prematurely at attempt {i + 1}")
            else:
                self.assertIsNotNone(blocked, "IP was not blocked after 3 consecutive failures")
                
        # Clean up
        BlockedIP.query.filter_by(ip_address=test_ip).delete()
        ActivityLog.query.filter_by(ip_address=test_ip).delete()
        db.session.commit()

if __name__ == '__main__':
    unittest.main()
