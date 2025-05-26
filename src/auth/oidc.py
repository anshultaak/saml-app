from flask import current_app, request, session, url_for, redirect
from authlib.integrations.flask_client import OAuth
import json
from typing import Dict, Any, Optional, Tuple

from ..models import User, UserIdentity, ServiceProvider

class OIDCManager:
    """OpenID Connect authentication manager"""
    
    def __init__(self, app=None):
        self.app = app
        self.oauth = OAuth()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the OIDC manager with a Flask application"""
        self.app = app
        self.oauth.init_app(app)
        
        with app.app_context():
            self._register_providers()
    
    def _register_providers(self):
        """Register all active OIDC providers from database"""
        providers = ServiceProvider.objects(
            protocol='oidc',
            active=True
        ).all()
        
        for provider in providers:
            self._register_provider(provider)
    
    def _register_provider(self, provider: ServiceProvider) -> bool:
        """Register a single OIDC provider with OAuth"""
        try:
            self.oauth.register(
                name=f'oidc_{provider.id}',
                client_id=provider.client_id,
                client_secret=provider.client_secret,
                server_metadata_url=provider.metadata_url,
                client_kwargs={
                    'scope': 'openid email profile',
                    'code_challenge_method': 'S256'  # Enable PKCE
                }
            )
            return True
        except Exception as e:
            current_app.logger.error(f"Failed to register OIDC provider {provider.id}: {str(e)}")
            return False
    
    def login(self, sp_id: str, return_to: Optional[str] = None) -> redirect:
        """Initiate OIDC authentication"""
        sp = ServiceProvider.objects(id=sp_id, protocol='oidc').first()
        if not sp:
            raise ValueError(f"Service provider {sp_id} not found or not OIDC")
        
        oauth_client = self.oauth.create_client(f'oidc_{sp_id}')
        if not oauth_client:
            self._register_provider(sp)
            oauth_client = self.oauth.create_client(f'oidc_{sp_id}')
        
        redirect_uri = url_for('auth.oidc_callback', sp_id=sp_id, _external=True)
        
        if return_to:
            session['oidc_return_to'] = return_to
            
        return oauth_client.authorize_redirect(redirect_uri)
    
    def process_callback(self, sp_id: str) -> Tuple[bool, Any]:
        """Process OIDC callback and authenticate user"""
        sp = ServiceProvider.objects(id=sp_id, protocol='oidc').first()
        if not sp:
            return False, "Invalid service provider"
            
        oauth_client = self.oauth.create_client(f'oidc_{sp_id}')
        if not oauth_client:
            return False, "OIDC client not configured"
            
        try:
            token = oauth_client.authorize_access_token()
            user_info = oauth_client.parse_id_token(token)
            
            sub = user_info.get('sub')
            email = user_info.get('email')
            name = user_info.get('name')
            
            if not sub:
                return False, "Missing subject identifier"
                
            identity = UserIdentity.objects(
                provider='oidc',
                provider_user_id=sub
            ).first()
            
            if identity:
                user = identity.user
            else:
                if email:
                    user = User.objects(email=email).first()
                else:
                    user = None
                    
                if not user:
                    username = email.split('@')[0] if email else f"user_{sub}"
                    user = User(
                        username=username,
                        email=email or f"{username}@example.com",
                        active=True
                    )
                    user.save()
                
                identity = UserIdentity(
                    provider='oidc',
                    provider_user_id=sub,
                    user=user,
                    metadata=user_info
                )
                identity.save()
                
            return True, user
            
        except Exception as e:
            current_app.logger.error(f"OIDC callback error: {str(e)}")
            return False, f"Authentication error: {str(e)}"
    
    def logout(self, sp_id: str, return_to: Optional[str] = None) -> redirect:
        """Logout from OIDC provider"""
        sp = ServiceProvider.objects(id=sp_id, protocol='oidc').first()
        if not sp:
            raise ValueError(f"Service provider {sp_id} not found or not OIDC")
            
        
        redirect_url = return_to or url_for('main.index', _external=True)
        
        return redirect(redirect_url)

oidc_manager = OIDCManager()

