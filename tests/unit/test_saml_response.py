"""
Unit tests for SAML response generation.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import base64
from lxml import etree
from flask import Flask
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.auth.saml_response import SAMLResponseBuilder
from src.auth.saml_config import SAMLConfig

class TestSAMLResponseBuilder(unittest.TestCase):
    """Test cases for SAML response generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['SAML_ENTITY_ID'] = 'https://test.example.com'
        self.app.config['SAML_CERT_PATH'] = 'tests/fixtures/sp.crt'
        self.app.config['SAML_KEY_PATH'] = 'tests/fixtures/sp.key'
        
        os.makedirs('tests/fixtures', exist_ok=True)
        
        if not os.path.exists('tests/fixtures/sp.crt') or not os.path.exists('tests/fixtures/sp.key'):
            os.system('openssl req -x509 -newkey rsa:2048 -keyout tests/fixtures/sp.key -out tests/fixtures/sp.crt -days 365 -nodes -subj "/CN=localhost"')
        
        self.user = MagicMock()
        self.user.email = 'test@example.com'
        self.user.username = 'testuser'
        
        self.aws_sp = MagicMock()
        self.aws_sp.name = 'AWS Test'
        self.aws_sp.entity_id = 'urn:amazon:webservices'
        self.aws_sp.acs_url = 'https://signin.aws.amazon.com/saml'
        self.aws_sp.aws_account_id = '123456789012'
        self.aws_sp.aws_role = 'TestRole'
        self.aws_sp.aws_provider = 'TestProvider'
        
        self.jenkins_sp = MagicMock()
        self.jenkins_sp.name = 'Jenkins Test'
        self.jenkins_sp.entity_id = 'jenkins:test'
        self.jenkins_sp.acs_url = 'https://jenkins.example.com/securityRealm/finishLogin'
        
        os.environ['TESTING'] = 'True'
    
    @patch.object(SAMLConfig, 'load_cert_and_key')
    @patch.object(SAMLConfig, 'get_entity_id')
    def test_build_aws_response(self, mock_get_entity_id, mock_load_cert_and_key):
        """Test building AWS SAML response."""
        mock_get_entity_id.return_value = 'https://test.example.com'
        mock_load_cert_and_key.return_value = (
            '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA==\n-----END CERTIFICATE-----',
            '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCH1iBtI4d0\n-----END PRIVATE KEY-----'
        )
        
        with self.app.app_context():
            response = SAMLResponseBuilder.build_aws_response(self.user, self.aws_sp)
            
            self.assertTrue(isinstance(response, str))
            
            try:
                xml = base64.b64decode(response).decode('utf-8')
                root = etree.fromstring(xml)
                
                namespaces = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                             'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}
                
                role_attr = root.xpath('//saml:Attribute[@Name="https://aws.amazon.com/SAML/Attributes/Role"]',
                                     namespaces=namespaces)
                self.assertEqual(len(role_attr), 1)
                
                session_attr = root.xpath('//saml:Attribute[@Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"]',
                                        namespaces=namespaces)
                self.assertEqual(len(session_attr), 1)
                
                signature = root.xpath('//ds:Signature', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                self.assertGreaterEqual(len(signature), 1)
                
            except Exception as e:
                self.fail(f"Failed to parse SAML response: {str(e)}")
    
    @patch.object(SAMLConfig, 'load_cert_and_key')
    @patch.object(SAMLConfig, 'get_entity_id')
    def test_build_jenkins_response(self, mock_get_entity_id, mock_load_cert_and_key):
        """Test building Jenkins SAML response."""
        mock_get_entity_id.return_value = 'https://test.example.com'
        mock_load_cert_and_key.return_value = (
            '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA==\n-----END CERTIFICATE-----',
            '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCH1iBtI4d0\n-----END PRIVATE KEY-----'
        )
        
        with self.app.app_context():
            response = SAMLResponseBuilder.build_jenkins_response(self.user, self.jenkins_sp)
            
            self.assertTrue(isinstance(response, str))
            
            try:
                xml = base64.b64decode(response).decode('utf-8')
                root = etree.fromstring(xml)
                
                namespaces = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                             'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}
                
                username_attr = root.xpath('//saml:Attribute[@Name="username"]', namespaces=namespaces)
                self.assertEqual(len(username_attr), 1)
                
                email_attr = root.xpath('//saml:Attribute[@Name="email"]', namespaces=namespaces)
                self.assertEqual(len(email_attr), 1)
                
                groups_attr = root.xpath('//saml:Attribute[@Name="groups"]', namespaces=namespaces)
                self.assertEqual(len(groups_attr), 1)
                
                signature = root.xpath('//ds:Signature', namespaces={'ds': 'http://www.w3.org/2000/09/xmldsig#'})
                self.assertGreaterEqual(len(signature), 1)
                
            except Exception as e:
                self.fail(f"Failed to parse SAML response: {str(e)}")

if __name__ == '__main__':
    unittest.main()
