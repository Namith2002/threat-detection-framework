"""
Application configuration settings
"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    
    # Flask Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('FLASK_ENV') == 'development'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'sqlite:///threat_detection.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SocketIO Configuration
    SOCKETIO_MESSAGE_QUEUE = os.getenv(
        'SOCKETIO_MESSAGE_QUEUE',
        'redis://localhost:6379'
    )
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_SECURE = not DEBUG
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS Settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # Gemini AI Configuration
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-pro')
    
    # Threat Detection Configuration
    THREAT_DETECTION = {
        'enabled': True,
        'check_interval': 5,  # seconds
        'batch_size': 100,
        'confidence_threshold': 0.6
    }
    
    # ML Model Configuration
    ML_MODELS = {
        'threat_classifier': {
            'model_path': 'models/threat_classifier.pkl',
            'threshold': 0.7
        },
        'anomaly_detector': {
            'model_path': 'models/anomaly_detector.pkl',
            'sensitivity': 0.85
        }
    }
    
    # Alert Configuration
    ALERT_CONFIG = {
        'critical_threshold': 8,
        'high_threshold': 6,
        'email_alerts': os.getenv('EMAIL_ALERTS', 'false').lower() == 'true',
        'slack_alerts': os.getenv('SLACK_ALERTS', 'false').lower() == 'true'
    }
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/threat_detection.log'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
