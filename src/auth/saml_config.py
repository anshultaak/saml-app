"""
SAML configuration module.
Provides configuration settings for SAML authentication.
"""
import os
from flask import current_app

class SAMLConfig:
    """Class for managing SAML configuration settings."""
    
    @staticmethod
    def get_entity_id():
        """
        Get the SAML entity ID for this IdP.
        
        Returns:
            str: The entity ID.
        """
        return os.environ.get('SAML_ENTITY_ID', 'https://13.203.99.201')
    
    @staticmethod
    def get_cert_path():
        """
        Get the path to the SAML certificate file.
        
        Returns:
            str: Path to the certificate file.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_dir, 'certs', 'sp.crt')
    
    @staticmethod
    def get_key_path():
        """
        Get the path to the SAML private key file.
        
        Returns:
            str: Path to the private key file.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_dir, 'certs', 'sp.key')
    
    @staticmethod
    def get_base_url():
        """
        Get the base URL for SAML endpoints.
        
        Returns:
            str: The base URL.
        """
        return os.environ.get('SAML_BASE_URL', 'https://13.203.99.201')
    
    @staticmethod
    def get_metadata_url():
        """
        Get the metadata URL for this IdP.
        
        Returns:
            str: The metadata URL.
        """
        base_url = SAMLConfig.get_base_url()
        return f"{base_url}/auth/saml/metadata.xml"
