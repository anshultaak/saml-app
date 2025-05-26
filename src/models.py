from datetime import datetime
from mongoengine import Document, StringField, EmailField, BooleanField, DateTimeField, ReferenceField, ListField, DictField, IntField
from mongoengine.errors import ValidationError

class User(Document):
    """User model for authentication"""
    username = StringField(required=True, unique=True)
    email = EmailField(required=True, unique=True)
    password_hash = StringField()
    active = BooleanField(default=True)
    created_at = DateTimeField(default=datetime.utcnow)
    is_admin = BooleanField(default=False)
    
    meta = {
        'collection': 'users',
        'indexes': [
            'username', 
            'email'
        ]
    }
    
    def get_id(self):
        """Required for Flask-Login"""
        return str(self.id)
    
    def is_authenticated(self):
        """Required for Flask-Login"""
        return True
    
    def is_active(self):
        """Required for Flask-Login"""
        return self.active
    
    def is_anonymous(self):
        """Required for Flask-Login"""
        return False
    
    def get_identities(self):
        """Get all external identities linked to this user"""
        return UserIdentity.objects(user=self).all()
    
    def set_password(self, password):
        """Set the password hash for the user"""
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the password is correct"""
        from werkzeug.security import check_password_hash
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return f'<User {self.username}>'

class UserIdentity(Document):
    """External identity providers linked to a user"""
    provider = StringField(required=True)  # 'saml', 'oidc', etc.
    provider_user_id = StringField(required=True)
    user = ReferenceField(User, required=True)
    metadata = DictField()
    created_at = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'user_identities',
        'indexes': [
            {'fields': ['provider', 'provider_user_id'], 'unique': True},
            'user'
        ]
    }
    
    def __repr__(self):
        return f'<UserIdentity {self.provider}:{self.provider_user_id}>'

class ServiceProvider(Document):
    """Cloud services that integrate with this SSO"""
    name = StringField(required=True)
    description = StringField()
    protocol = StringField(required=True)  # 'saml', 'oidc'
    client_id = StringField()  # For OIDC
    client_secret = StringField()  # For OIDC
    metadata_url = StringField()  # For SAML or OIDC discovery
    entity_id = StringField(required=True)  # For SAML - Required for SAML providers
    acs_url = StringField()  # For SAML
    sso_url = StringField()  # For SAML IdP SSO URL
    slo_url = StringField()  # For SAML IdP SLO URL
    x509cert = StringField()  # For SAML IdP certificate
    aws_role = StringField()  # AWS Role name (without full ARN)
    aws_provider = StringField()  # AWS Provider name (without full ARN)
    aws_account_id = StringField()  # AWS Account ID
    active = BooleanField(default=True)
    created_at = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'service_providers',
        'indexes': [
            'name',
            'protocol'
        ]
    }
    
    def clean(self):
        """Validate model fields"""
        if self.protocol == 'saml':
            if not self.entity_id:
                raise ValidationError('entity_id is required for SAML providers')
            if not self.acs_url:
                raise ValidationError('acs_url is required for SAML providers')
    
    def __repr__(self):
        return f'<ServiceProvider {self.name}>'
