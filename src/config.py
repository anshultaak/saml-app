import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration class"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = False
    TESTING = False
    
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/sso')
    
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    OIDC_ISSUER = os.getenv('OIDC_ISSUER', 'http://localhost:5002')
    
    SAML_ENTITY_ID = os.getenv('SAML_ENTITY_ID', 'https://localhost:5002')
    SAML_CERT_PATH = os.getenv('SAML_CERT_PATH', 'certs/sp.crt')
    SAML_KEY_PATH = os.getenv('SAML_KEY_PATH', 'certs/sp.key')

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    MONGODB_URI = 'mongodb://localhost:27017/sso_test'
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

class ProductionConfig(Config):
    """Production configuration"""
    pass

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
