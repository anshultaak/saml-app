"""
SAML configuration module for the SSO application.
Centralizes all SAML-related configuration.
"""
from flask import current_app
import os
import logging

class SAMLConfig:
    """Class to centralize SAML configuration settings."""
    
    DEFAULT_ENTITY_ID = 'https://localhost:5002'
    DEFAULT_CERT_PATH = 'certs/sp.crt'
    DEFAULT_KEY_PATH = 'certs/sp.key'
    
    TEST_ENTITY_ID = 'https://test.example.com'
    TEST_CERT_PATH = 'tests/fixtures/sp.crt'
    TEST_KEY_PATH = 'tests/fixtures/sp.key'
    
    @staticmethod
    def is_test_environment():
        """Check if we're in a test environment."""
        return os.environ.get('TESTING') == 'True' or \
               (hasattr(current_app, '_get_current_object') and 
                getattr(current_app, 'testing', False))
    
    @staticmethod
    def get_entity_id():
        """Get the entity ID for the IdP."""
        try:
            if SAMLConfig.is_test_environment():
                if hasattr(current_app, 'config') and 'SAML_ENTITY_ID' in current_app.config:
                    return current_app.config.get('SAML_ENTITY_ID')
                return SAMLConfig.TEST_ENTITY_ID
            entity_id = os.environ.get('SAML_ENTITY_ID', 
                                     current_app.config.get('SAML_ENTITY_ID', 
                                                          SAMLConfig.DEFAULT_ENTITY_ID))
            return entity_id
        except RuntimeError:
            return os.environ.get('SAML_ENTITY_ID', SAMLConfig.DEFAULT_ENTITY_ID)
    
    @staticmethod
    def get_cert_path():
        """Get the path to the signing certificate."""
        try:
            if SAMLConfig.is_test_environment():
                return SAMLConfig.TEST_CERT_PATH
            cert_path = os.environ.get('SAML_CERT_PATH', 
                                     current_app.config.get('SAML_CERT_PATH', 
                                                          SAMLConfig.DEFAULT_CERT_PATH))
            return cert_path
        except RuntimeError:
            return os.environ.get('SAML_CERT_PATH', SAMLConfig.DEFAULT_CERT_PATH)
    
    @staticmethod
    def get_key_path():
        """Get the path to the signing key."""
        try:
            if SAMLConfig.is_test_environment():
                return SAMLConfig.TEST_KEY_PATH
            key_path = os.environ.get('SAML_KEY_PATH', 
                                    current_app.config.get('SAML_KEY_PATH', 
                                                         SAMLConfig.DEFAULT_KEY_PATH))
            return key_path
        except RuntimeError:
            return os.environ.get('SAML_KEY_PATH', SAMLConfig.DEFAULT_KEY_PATH)
    
    @staticmethod
    def load_cert_and_key():
        """Load the certificate and key content."""
        cert_file = SAMLConfig.get_cert_path()
        key_file = SAMLConfig.get_key_path()
        
        try:
            if SAMLConfig.is_test_environment():
                os.makedirs(os.path.dirname(cert_file), exist_ok=True)
                if not os.path.exists(cert_file) or not os.path.exists(key_file):
                    logging.info(f"Generating test certificates in {cert_file} and {key_file}")
                    os.system(f'openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj "/CN=localhost"')
            
            if not os.path.isabs(cert_file):
                possible_locations = [
                    cert_file,  # Relative to current directory
                    os.path.join(os.getcwd(), cert_file),  # Absolute from current directory
                    os.path.join(os.getcwd(), 'login', cert_file),  # In login subdirectory
                    os.path.join(os.path.dirname(os.getcwd()), cert_file),  # Parent directory
                ]
                
                for location in possible_locations:
                    if os.path.exists(location):
                        cert_file = location
                        break
            
            if not os.path.isabs(key_file):
                possible_locations = [
                    key_file,
                    os.path.join(os.getcwd(), key_file),
                    os.path.join(os.getcwd(), 'login', key_file),
                    os.path.join(os.path.dirname(os.getcwd()), key_file),
                ]
                
                for location in possible_locations:
                    if os.path.exists(location):
                        key_file = location
                        break
            
            logging.info(f"Loading certificate from {cert_file}")
            logging.info(f"Loading key from {key_file}")
            
            with open(cert_file, 'r') as f:
                cert = f.read()
            
            with open(key_file, 'r') as f:
                key = f.read()
                
            return cert, key
        except Exception as e:
            logging.error(f"Failed to load certificate or key: {str(e)}")
            raise
