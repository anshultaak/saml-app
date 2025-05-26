"""
Unit tests for SAML metadata generation.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.auth.saml_metadata import SAMLMetadata
from src.auth.saml_config import SAMLConfig

class TestSAMLMetadata(unittest.TestCase):
    """Test cases for SAML metadata generation."""
    
    @patch.object(SAMLConfig, 'load_cert_and_key')
    @patch.object(SAMLConfig, 'get_entity_id')
    def test_generate_metadata(self, mock_get_entity_id, mock_load_cert_and_key):
        """Test generating SAML metadata."""
        mock_get_entity_id.return_value = 'https://test.example.com'
        mock_load_cert_and_key.return_value = (
            '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA==\n-----END CERTIFICATE-----',
            'dummy_key'
        )
        
        metadata = SAMLMetadata.generate_metadata()
        
        self.assertIn('<?xml version="1.0"?>', metadata)
        self.assertIn('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"', metadata)
        self.assertIn('entityID="https://test.example.com"', metadata)
        self.assertIn('<IDPSSODescriptor', metadata)
        self.assertIn('WantAuthnRequestsSigned="true"', metadata)
        self.assertIn('<X509Certificate>MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA==</X509Certificate>', metadata)
        self.assertIn('<SingleSignOnService', metadata)
        self.assertIn('<SingleLogoutService', metadata)
    
    @patch.object(SAMLConfig, 'load_cert_and_key')
    def test_generate_metadata_error(self, mock_load_cert_and_key):
        """Test error handling in metadata generation."""
        mock_load_cert_and_key.side_effect = Exception("Certificate not found")
        
        with self.assertRaises(Exception):
            SAMLMetadata.generate_metadata()

if __name__ == '__main__':
    unittest.main()
