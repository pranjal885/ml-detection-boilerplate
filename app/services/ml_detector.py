import os
import urllib.request
import json
import logging
from datetime import datetime

import joblib
import pandas as pd

from app.models import db, ActivityLog

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
MODEL_PATH = os.path.join(PROJECT_ROOT, 'training', 'models', 'best_model.pkl')
SCALER_PATH = os.path.join(PROJECT_ROOT, 'preprocessing', 'models', 'scaler.pkl')


def get_best_model():
    """Load the trained production model from the training artifacts folder."""
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Best model not found at {MODEL_PATH}")
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception as exc:
        logger.exception(f"Failed to load training model from {MODEL_PATH}: {exc}")
        return None


def get_scaler():
    """Load the trained feature scaler from the preprocessing models folder."""
    if not os.path.exists(SCALER_PATH):
        logger.error(f"Scaler not found at {SCALER_PATH}")
        return None
    try:
        return joblib.load(SCALER_PATH)
    except Exception as exc:
        logger.exception(f"Failed to load scaler from {SCALER_PATH}: {exc}")
        return None

def get_outward_ip():
    """
    Fetches the machine's external public IP address.
    Used for local development testing to resolve real geolocations.
    """
    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "CloudShield-AI/1.2.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('ip')
    except Exception as e:
        logger.warning(f"Unable to fetch outward public IP: {e}")
        return None

def fetch_ip_geolocation(ip_address):
    """
    Queries real-time IP Geolocation database using a free API (ipwho.is).
    Automatically maps loopbacks to external public IPs for demo dynamic updates.
    """
    # For local loopbacks, attempt to fetch the outward facing public IP
    if ip_address in ['127.0.0.1', '::1', 'localhost']:
        public_ip = get_outward_ip()
        if public_ip:
            ip_address = public_ip
        else:
            # Fallback coordinate reference
            return {
                "city": "Mumbai",
                "country": "India",
                "latitude": 19.0760,
                "longitude": 72.8777
            }
            
    try:
        url = f"http://ipwho.is/{ip_address}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CloudShield-AI/1.2.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('success', False):
                return {
                    "city": data.get('city', 'Unknown'),
                    "country": data.get('country', 'Unknown'),
                    "latitude": float(data.get('latitude', 0.0)),
                    "longitude": float(data.get('longitude', 0.0))
                }
    except Exception as e:
        logger.error(f"Error querying ipwho.is geolocation API: {e}")
        
    return {
        "city": "Unknown",
        "country": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0
    }

class VPNIntelligenceModule:
    """
    Enterprise Threat Intelligence module for proxy and VPN masking detection.
    Provides standard abstraction wrappers for future MaxMind/IPinfo data subscription hooks.
    """
    @staticmethod
    def evaluate_vpn_risk(ip_address):
        """
        Validates if the source IP belongs to known hosting, proxy, or VPN subnets.
        """
        # Placeholders: identify test addresses mapped to threat simulations
        # E.g., IP addresses starting with '198.51.' represent blacklisted assets
        if ip_address.startswith('198.51.') or ip_address.startswith('203.0.113.'):
            return True, "IP categorized under public proxy threat registry."
        return False, "IP is cleared from known VPN/hosting lists."

class AnomalyDetectionEngine:
    """
    Compares real-time user metrics (Browser, Location, Device) against their historical
    profile of successful interactions to identify behavior drift anomalies.
    """
    @staticmethod
    def analyze_profile_anomalies(user, city, country, browser, platform):
        if not user:
            return {
                "new_location": True,
                "new_browser": True,
                "new_platform": True
            }
            
        # Retrieve user history (prior login_success entries)
        past_success_logs = ActivityLog.query.filter_by(
            user_id=user.id,
            action='login_success'
        ).all()
        
        if not past_success_logs:
            # Baseline is empty, mark as standard new account
            return {
                "new_location": False,
                "new_browser": False,
                "new_platform": False
            }
            
        known_cities = {log.city for log in past_success_logs if log.city}
        known_browsers = {log.browser for log in past_success_logs if log.browser}
        known_platforms = {log.operating_system for log in past_success_logs if log.operating_system}
        
        return {
            "new_location": city not in known_cities if city != 'Unknown' else False,
            "new_browser": browser not in known_browsers if browser else False,
            "new_platform": platform not in known_platforms if platform else False
        }

class MLPredictionEngine:
    """Real model-backed predictor using the trained CloudShield model artifact."""

    @staticmethod
    def _risk_bucket(risk_pct):
        if risk_pct <= 20:
            return 'Safe'
        if risk_pct <= 50:
            return 'Low'
        if risk_pct <= 80:
            return 'Medium'
        return 'Critical'

    @staticmethod
    def _build_feature_vector(features):
        """Map the current login feature dict into the saved model's exact feature schema."""
        model = get_best_model()
        if model is None:
            return None, None

        feature_names = list(getattr(model, 'feature_names_in_', [
            'Protocol', 'Port', 'Packets', 'Bytes', 'Request Count',
            'Login Attempts', 'CPU Usage', 'Memory Usage', 'Response Time'
        ]))

        protocol = str(features.get('protocol', 'HTTPS')).upper()
        if protocol == 'HTTP':
            protocol_value = 0
        else:
            protocol_value = 1

        failed_login_count = int(features.get('failed_login_count', 0) or 0)
        vpn_active = bool(features.get('vpn_active', False))
        location_anomaly = bool(features.get('location_anomaly', False))
        device_anomaly = bool(features.get('device_anomaly', False))

        payload = {
            'Protocol': protocol_value,
            'Port': int(features.get('port', 443)),
            'Packets': int(features.get('packets', 50 + failed_login_count * 20 + (30 if vpn_active else 0))),
            'Bytes': int(features.get('bytes', 5000 + failed_login_count * 1500 + (2000 if vpn_active else 0))),
            'Request Count': int(features.get('request_count', 1 + failed_login_count + (2 if location_anomaly else 0))),
            'Login Attempts': int(features.get('login_attempts', 1 + failed_login_count)),
            'CPU Usage': float(features.get('cpu_usage', 30 + (8 if vpn_active else 0) + (12 if device_anomaly else 0))),
            'Memory Usage': float(features.get('memory_usage', 35 + (15 if vpn_active else 0) + (10 if location_anomaly else 0))),
            'Response Time': float(features.get('response_time', 120 + failed_login_count * 35 + (30 if vpn_active else 0)))
        }

        ordered_values = [payload.get(name, 0) for name in feature_names]
        df = pd.DataFrame([ordered_values], columns=feature_names)

        # Scale numerical features if scaler is available
        scaler = get_scaler()
        if scaler is not None:
            numerical_columns = [
                "Port", "Packets", "Bytes", "Request Count", "Login Attempts",
                "CPU Usage", "Memory Usage", "Response Time"
            ]
            cols_to_scale = [col for col in numerical_columns if col in df.columns]
            if cols_to_scale:
                df[cols_to_scale] = scaler.transform(df[cols_to_scale])
        else:
            logger.warning("Scaler not available. Features remain unscaled, which may trigger false positive anomalies.")

        return df, model

    @staticmethod
    def predict_login_anomaly(features):
        """
        Accepts the legacy login feature dictionary and returns the risk signal using the trained model.

        Returns:
          tuple: (risk_score, threat_level, prediction_str, confidence_float)
        """
        feature_frame, model = MLPredictionEngine._build_feature_vector(features or {})
        if model is None or feature_frame is None:
            logger.warning("Model unavailable. Falling back to safe default risk profile.")
            return 0.0, 'LOW', 'Legitimate User', 100.0

        try:
            probabilities = model.predict_proba(feature_frame)
            prediction = model.predict(feature_frame)[0]
            classes = list(model.classes_)
            attack_index = classes.index(1) if 1 in classes else 0
            attack_probability = float(probabilities[0][attack_index])
            confidence = float(max(probabilities[0]) * 100.0)
        except Exception as exc:
            logger.exception(f"Prediction failed with model {MODEL_PATH}: {exc}")
            return 0.0, 'LOW', 'Legitimate User', 100.0

        risk_pct = round(attack_probability * 100.0, 1)
        risk_bucket = MLPredictionEngine._risk_bucket(risk_pct)

        if prediction == 1 or risk_pct >= 81:
            threat_level = 'HIGH'
            prediction_label = 'Possible Attacker'
        elif risk_pct >= 51:
            threat_level = 'MEDIUM'
            prediction_label = 'Suspicious User'
        else:
            threat_level = 'LOW'
            prediction_label = 'Legitimate User'

        return risk_pct, threat_level, prediction_label, round(confidence, 1)
