"""
Unit tests for SAML configuration.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.auth.saml_config import SAMLConfig

class TestSAMLConfig(unittest.TestCase):
    """Test cases for SAML configuration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.original_env = os.environ.copy()
    
    def tearDown(self):
        """Tear down test fixtures."""
        os.environ.clear()
        os.environ.update(self.original_env)
    
    def test_get_entity_id_from_env(self):
        """Test getting entity ID from environment variable."""
        os.environ['SAML_ENTITY_ID'] = 'https://test-env.example.com'
        
        entity_id = SAMLConfig.get_entity_id()
        
        self.assertEqual(entity_id, 'https://test-env.example.com')
    
    
    def test_get_cert_path_from_env(self):
        """Test getting certificate path from environment variable."""
        os.environ['SAML_CERT_PATH'] = '/custom/path/to/cert.crt'
        
        cert_path = SAMLConfig.get_cert_path()
        
        self.assertEqual(cert_path, '/custom/path/to/cert.crt')
    
    def test_get_key_path_from_env(self):
        """Test getting key path from environment variable."""
        os.environ['SAML_KEY_PATH'] = '/custom/path/to/key.key'
        
        key_path = SAMLConfig.get_key_path()
        
        self.assertEqual(key_path, '/custom/path/to/key.key')
    
    @patch('os.path.exists')
    @patch('os.path.isabs')
    @patch('src.auth.saml_config.SAMLConfig.is_test_environment')
    def test_load_cert_and_key_with_relative_paths(self, mock_is_test_env, mock_isabs, mock_exists):
        """Test loading certificate and key with relative paths."""
        mock_is_test_env.return_value = False
        
        mock_isabs.return_value = False
        
        mock_exists.side_effect = lambda path: 'certs/sp.crt' in path or 'certs/sp.key' in path
        
        with patch('builtins.open', unittest.mock.mock_open(read_data='test_cert_content')):
            cert, key = SAMLConfig.load_cert_and_key()
            
            self.assertEqual(cert, 'test_cert_content')
            self.assertEqual(key, 'test_cert_content')

if __name__ == '__main__':
    unittest.main()
