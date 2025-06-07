#!/usr/bin/env python3
"""
Main Flask application for SSO login service.
"""
import os
import logging
from flask import Flask
from flask_login import LoginManager
from mongoengine import connect
from src.models import User
from src.views.auth import auth_bp
from src.views.main import main_bp
from src.auth.saml_manager import SAMLManager

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder='src/templates', static_folder='src/static')
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MONGODB_URI'] = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/sso')
    app.config['SAML_ENTITY_ID'] = os.environ.get('SAML_ENTITY_ID', 'https://localhost:5002')
    app.config['SAML_BASE_URL'] = os.environ.get('SAML_BASE_URL', 'https://localhost:5002')
    app.config['OIDC_ISSUER'] = os.environ.get('OIDC_ISSUER', 'https://localhost:5002')
    app.config['SAML_CERT_PATH'] = os.environ.get('SAML_CERT_PATH', 'certs/sp.crt')
    app.config['SAML_KEY_PATH'] = os.environ.get('SAML_KEY_PATH', 'certs/sp.key')
    
    logging.basicConfig(level=logging.INFO)
    
    connect(host=app.config['MONGODB_URI'])
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.objects(id=user_id).first()
        except:
            return None
    
    saml_manager = SAMLManager()
    saml_manager.init_app(app)
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
