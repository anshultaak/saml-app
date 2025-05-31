"""
Provider registry for managing different SSO provider types.
Enables extensible support for various integrations without affecting each other.
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class ProviderHandler(ABC):
    """Abstract base class for provider-specific handlers."""
    
    @abstractmethod
    def get_provider_type(self) -> str:
        """Return the provider type this handler supports."""
        pass
    
    @abstractmethod
    def detect_provider(self, sp) -> bool:
        """Detect if this handler should be used for the given service provider."""
        pass
    
    @abstractmethod
    def build_saml_response(self, user, sp) -> str:
        """Build a SAML response specific to this provider type."""
        pass
    
    @abstractmethod
    def get_template_name(self) -> str:
        """Return the template name for this provider type."""
        pass
    
    def get_custom_attributes(self, user, sp) -> Dict[str, Any]:
        """Get custom attributes for this provider type."""
        return {}
    
    def process_acs_url(self, acs_url: str, sp) -> str:
        """Process and clean the ACS URL for this provider type."""
        return acs_url.strip() if acs_url else ''


class AWSProviderHandler(ProviderHandler):
    """Handler for AWS SSO integration."""
    
    def get_provider_type(self) -> str:
        return 'aws'
    
    def detect_provider(self, sp) -> bool:
        return (sp.provider_type and sp.provider_type.lower() == 'aws') or \
               (sp.entity_id and 'aws' in sp.entity_id.lower()) or \
               (sp.name and 'aws' in sp.name.lower())
    
    def build_saml_response(self, user, sp) -> str:
        from .saml_response import SAMLResponseBuilder
        return SAMLResponseBuilder.build_aws_response(user, sp)
    
    def get_template_name(self) -> str:
        return 'auth/aws_post.html'
    
    def process_acs_url(self, acs_url: str, sp) -> str:
        clean_acs_url = acs_url.strip() if acs_url else ''
        if 'signin.aws.amazon.com' in clean_acs_url and ',' in clean_acs_url:
            clean_acs_url = clean_acs_url.split(',')[0].strip()
        return clean_acs_url


class JenkinsProviderHandler(ProviderHandler):
    """Handler for Jenkins SSO integration."""
    
    def get_provider_type(self) -> str:
        return 'jenkins'
    
    def detect_provider(self, sp) -> bool:
        return (sp.provider_type and sp.provider_type.lower() == 'jenkins') or \
               (sp.entity_id and 'jenkins' in sp.entity_id.lower()) or \
               (sp.name and 'jenkins' in sp.name.lower())
    
    def build_saml_response(self, user, sp) -> str:
        from .saml_response import SAMLResponseBuilder
        return SAMLResponseBuilder.build_jenkins_response(user, sp)
    
    def get_template_name(self) -> str:
        return 'auth/jenkins_post.html'
    
    def process_acs_url(self, acs_url: str, sp) -> str:
        clean_acs_url = acs_url.strip() if acs_url else ''
        if clean_acs_url and not clean_acs_url.startswith(('http://', 'https://')):
            clean_acs_url = f"https://{clean_acs_url}"
        return clean_acs_url


class GitHubProviderHandler(ProviderHandler):
    """Handler for GitHub SSO integration."""
    
    def get_provider_type(self) -> str:
        return 'github'
    
    def detect_provider(self, sp) -> bool:
        return (sp.provider_type and sp.provider_type.lower() == 'github') or \
               (sp.entity_id and 'github' in sp.entity_id.lower()) or \
               (sp.name and 'github' in sp.name.lower())
    
    def build_saml_response(self, user, sp, in_response_to=None) -> str:
        from .saml_response import SAMLResponseBuilder
        return SAMLResponseBuilder.build_github_response(user, sp, in_response_to=in_response_to)
    
    def get_template_name(self) -> str:
        return 'auth/github_post.html'


class GenericProviderHandler(ProviderHandler):
    """Generic handler for standard SAML providers."""
    
    def get_provider_type(self) -> str:
        return 'generic'
    
    def detect_provider(self, sp) -> bool:
        return True  # Fallback handler
    
    def build_saml_response(self, user, sp) -> str:
        from .saml_response import SAMLResponseBuilder
        return SAMLResponseBuilder.build_generic_response(user, sp)
    
    def get_template_name(self) -> str:
        return 'auth/generic_post.html'


class ProviderRegistry:
    """Registry for managing provider handlers."""
    
    def __init__(self):
        self._handlers = []
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default provider handlers."""
        self.register_handler(AWSProviderHandler())
        self.register_handler(JenkinsProviderHandler())
        self.register_handler(GitHubProviderHandler())
        self.register_handler(GenericProviderHandler())  # Must be last (fallback)
    
    def register_handler(self, handler: ProviderHandler):
        """Register a new provider handler."""
        self._handlers.append(handler)
        logging.info(f"Registered provider handler: {handler.get_provider_type()}")
    
    def get_handler(self, sp) -> ProviderHandler:
        """Get the appropriate handler for a service provider."""
        for handler in self._handlers:
            if handler.detect_provider(sp):
                logging.info(f"Using provider handler: {handler.get_provider_type()} for SP: {sp.name}")
                return handler
        
        raise ValueError(f"No handler found for service provider: {sp.name}")
    
    def get_handler_by_type(self, provider_type: str) -> Optional[ProviderHandler]:
        """Get a handler by provider type."""
        for handler in self._handlers:
            if handler.get_provider_type() == provider_type:
                return handler
        return None


provider_registry = ProviderRegistry()
