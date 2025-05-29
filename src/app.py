from flask import Flask
from flask_login import LoginManager
from .auth.saml_manager import SAMLManager
from .auth.oidc import OIDCManager
from .config import config
from .models import User
from .db import init_db
import os
import logging

login_manager = LoginManager()
saml_manager = SAMLManager()
oidc_manager = OIDCManager()

def create_app(config_name='default'):
    """Application factory function"""
    app = Flask(__name__)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    try:
        # Initialize database first
        init_db(app)
        
        # Then initialize other extensions
        login_manager.init_app(app)
        saml_manager.init_app(app)
        oidc_manager.init_app(app)
        
        @login_manager.user_loader
        def load_user(user_id):
            return User.objects(id=user_id).first()
        
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        
        # Register blueprints
        from .views.main import main_bp
        from .views.auth import auth_bp
        from .views.admin import admin_bp
        
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp, url_prefix='/auth')
        app.register_blueprint(admin_bp, url_prefix='/admin')
        
        # Create required directories
        os.makedirs('certs', exist_ok=True)
        
        @app.route('/create_user')
        def create_user():
            from .models import User
            username = "anshultaak_t"
            email = "anshultaak_2@gmail.com"
            password = "test123"
            user = User.objects(username=username, email=email).first()
            if user:
                user.set_password(password)
                user.save()
                return f"User already existed, password updated: {user.username} ({user.email}) with password: {password}"
            user = User(username=username, email=email, active=True)
            user.set_password(password)
            user.save()
            return f"User created: {user.username} ({user.email}) with password: {password}"
        
        app.logger.info("Application initialized successfully")
        return app
        
    except Exception as e:
        app.logger.error(f"Failed to initialize application: {str(e)}")
        raise
