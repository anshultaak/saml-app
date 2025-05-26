"""
Integration tests for SAML authentication.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import base64
from flask import Flask, url_for
from flask_login import LoginManager, login_user
import mongomock
from mongoengine import connect, disconnect
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models import User, ServiceProvider
from src.auth.saml_manager import SAMLManager

class TestSAMLAuth(unittest.TestCase):
    """Integration tests for SAML authentication."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = Flask(__name__, 
                         template_folder=os.path.join(os.path.dirname(__file__), '../fixtures/templates'))
        self.app.config['SECRET_KEY'] = 'test-key'
        self.app.config['TESTING'] = True
        self.app.config['SERVER_NAME'] = 'localhost:5000'
        self.app.config['SAML_ENTITY_ID'] = 'https://localhost:5000'
        self.app.config['SAML_CERT_PATH'] = 'tests/fixtures/sp.crt'
        self.app.config['SAML_KEY_PATH'] = 'tests/fixtures/sp.key'
        
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        
        @self.login_manager.user_loader
        def load_user(user_id):
            return User.objects(id=user_id).first()
        
        disconnect()
        connect('testdb', mongo_client_class=mongomock.MongoClient)
        
        self.user = User(username='testuser', email='test@example.com')
        self.user.set_password('password')
        self.user.save()
        
        self.aws_sp = ServiceProvider(
            name='AWS Test',
            protocol='saml',
            entity_id='urn:amazon:webservices',
            acs_url='https://signin.aws.amazon.com/saml',
            aws_account_id='123456789012',
            aws_role='TestRole',
            aws_provider='TestProvider'
        )
        self.aws_sp.save()
        
        self.jenkins_sp = ServiceProvider(
            name='Jenkins Test',
            protocol='saml',
            entity_id='jenkins:test',
            acs_url='https://jenkins.example.com/securityRealm/finishLogin'
        )
        self.jenkins_sp.save()
        
        from src.views.auth import auth_bp, saml_manager
        self.app.register_blueprint(auth_bp, url_prefix='')
        
        self.saml_manager = saml_manager
        self.saml_manager.init_app(self.app)
        
        os.makedirs('tests/fixtures', exist_ok=True)
        if not os.path.exists('tests/fixtures/sp.crt'):
            os.system('openssl req -x509 -newkey rsa:2048 -keyout tests/fixtures/sp.key -out tests/fixtures/sp.crt -days 365 -nodes -subj "/CN=localhost"')
    
    def tearDown(self):
        """Tear down test fixtures."""
        User.drop_collection()
        ServiceProvider.drop_collection()
    
    def test_get_metadata(self):
        """Test getting SAML metadata."""
        with self.app.app_context():
            metadata = self.saml_manager.get_metadata()
            
            self.assertIn('<?xml version="1.0"?>', metadata)
            self.assertIn('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"', metadata)
            self.assertIn('entityID="https://localhost:5000"', metadata)
            self.assertIn('<IDPSSODescriptor', metadata)
            self.assertIn('WantAuthnRequestsSigned="true"', metadata)
    
    @patch('src.auth.saml_response.SAMLResponseBuilder.build_aws_response')
    def test_handle_aws_login(self, mock_build_aws_response):
        """Test handling AWS login."""
        mock_build_aws_response.return_value = 'dummy_saml_response'
        
        template_dir = os.path.join(os.path.dirname(__file__), '../fixtures/templates')
        os.makedirs(os.path.join(template_dir, 'auth'), exist_ok=True)
        
        test_template = os.path.join(template_dir, 'auth/aws_post.html')
        if not os.path.exists(test_template):
            with open(test_template, 'w') as f:
                f.write('<!DOCTYPE html><html><body>{{ saml_response }}</body></html>')
        
        self.app.template_folder = template_dir
        
        with self.app.test_request_context():
            with self.app.test_client() as client:
                with client.session_transaction() as session:
                    session['_user_id'] = str(self.user.id)
                
                response = self.saml_manager.handle_aws_login(str(self.aws_sp.id))
                self.assertEqual(response.status_code, 200)
                self.assertIn('dummy_saml_response', response.get_data(as_text=True))

    def test_jenkins_saml_auth(self):
        """Test Jenkins SAML authentication."""
        saml_request = base64.b64encode(b'''
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="_123456789"
                           Version="2.0"
                           IssueInstant="2023-01-01T12:00:00Z"
                           Destination="https://localhost:5000/saml/sso"
                           AssertionConsumerServiceURL="https://jenkins.example.com/securityRealm/finishLogin"
                           ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>jenkins:test</saml:Issuer>
            <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                               AllowCreate="true"/>
        </samlp:AuthnRequest>
        ''').decode('utf-8')
        
        relay_state = 'https://jenkins.example.com:8081/securityRealm/finishLogin'
        
        with self.app.test_request_context(f'/saml/sso?SAMLRequest={saml_request}&RelayState={relay_state}'):
            with self.app.test_client() as client:
                with client.session_transaction() as session:
                    session['_user_id'] = str(self.user.id)
                
                response = client.get(f'/saml/sso?SAMLRequest={saml_request}&RelayState={relay_state}')
                self.assertEqual(response.status_code, 200)
                self.assertIn('saml-form', response.get_data(as_text=True))
                self.assertIn('SAMLResponse', response.get_data(as_text=True))
                self.assertIn(relay_state, response.get_data(as_text=True))
    
    def test_jenkins_specific_endpoint(self):
        """Test the Jenkins-specific endpoint."""
        saml_request = base64.b64encode(b'''
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="_123456789"
                           Version="2.0"
                           IssueInstant="2023-01-01T12:00:00Z"
                           Destination="https://localhost:5000/saml/jenkins/auth"
                           AssertionConsumerServiceURL="https://jenkins.example.com/securityRealm/finishLogin"
                           ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>jenkins:test</saml:Issuer>
            <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                               AllowCreate="true"/>
        </samlp:AuthnRequest>
        ''').decode('utf-8')
        
        relay_state = 'https://jenkins.example.com:8081/securityRealm/finishLogin'
        
        with self.app.test_request_context(f'/saml/jenkins/auth?SAMLRequest={saml_request}&RelayState={relay_state}'):
            with self.app.test_client() as client:
                with client.session_transaction() as session:
                    session['_user_id'] = str(self.user.id)
                
                response = client.get(f'/saml/jenkins/auth?SAMLRequest={saml_request}&RelayState={relay_state}')
                self.assertEqual(response.status_code, 200)
                self.assertIn('saml-form', response.get_data(as_text=True))
                self.assertIn('SAMLResponse', response.get_data(as_text=True))
                self.assertIn(relay_state, response.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
