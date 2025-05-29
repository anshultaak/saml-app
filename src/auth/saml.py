from flask import current_app, request, session, url_for, redirect, render_template
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import json
import os
from typing import Dict, Any, Optional, Tuple
import uuid
from flask_login import current_user
import logging
import datetime

from ..models import User, UserIdentity, ServiceProvider

logging.basicConfig(level=logging.DEBUG)

class SAMLManager:
    """SAML 2.0 authentication manager"""
    
    def __init__(self, app=None):
        self.app = app
        # Always use certs/sp.crt and certs/sp.key
        self.cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../certs/sp.crt')
        self.key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../certs/sp.key')
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the SAML manager with a Flask application"""
        self.app = app
        # Always use certs/sp.crt and certs/sp.key
        self.cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../certs/sp.crt')
        self.key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../certs/sp.key')
        cert_dir = os.path.dirname(self.cert_path)
        os.makedirs(cert_dir, exist_ok=True)
    
    def _prepare_flask_request(self, request):
        """Prepare Flask request for pysaml2"""
        url_data = request.url.split('/')
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': url_data[2].split(':')[-1] if len(url_data) > 2 and ':' in url_data[2] else '443' if request.scheme == 'https' else '80',
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy()
        }
    
    def _get_saml_settings(self, sp_id: str) -> Dict[str, Any]:
        """Get SAML settings for a specific service provider"""
        sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
        if not sp:
            raise ValueError(f"Service provider {sp_id} not found or not SAML")
            
        settings = {
            "strict": True,
            "debug": current_app.debug,
            "sp": {
                "entityId": current_app.config['SAML_ENTITY_ID'],
                "assertionConsumerService": {
                    "url": url_for('auth.saml_acs', sp_id=sp_id, _external=True),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": url_for('auth.saml_sls', sp_id=sp_id, _external=True),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": "",
                "privateKey": ""
            },
            "idp": {
                "entityId": sp.entity_id,
                "singleSignOnService": {
                    "url": sp.sso_url or sp.metadata_url,  # Fallback to metadata_url if sso_url not set
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": sp.slo_url or sp.metadata_url,  # Fallback to metadata_url if slo_url not set
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": sp.x509cert or ""  # Use IdP certificate if provided
            }
        }
        
        if os.path.exists(self.cert_path):
            with open(self.cert_path, 'r') as f:
                settings['sp']['x509cert'] = f.read()
                
        if os.path.exists(self.key_path):
            with open(self.key_path, 'r') as f:
                settings['sp']['privateKey'] = f.read()
        
        return settings
    
    def init_auth(self, request, sp_id: str):
        """Initialize SAML auth for a request"""
        req = self._prepare_flask_request(request)
        settings = self._get_saml_settings(sp_id)
        auth = OneLogin_Saml2_Auth(req, settings)
        return auth
    
    def login(self, sp_id: str, return_to: Optional[str] = None):
        """Generate SAML authentication request"""
        auth = self.init_auth(request, sp_id)
        return redirect(auth.login(return_to=return_to))

    def process_sso_request(self, sp_id: str, return_to: Optional[str] = None):
        """Process SAML SSO request from service provider"""
        try:
            # Get the service provider
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                raise ValueError(f"Service provider {sp_id} not found or not SAML")
                
            # Build SAML response
            now = datetime.datetime.utcnow()
            not_on_or_after = now + datetime.timedelta(minutes=5)
            assertion_id = '_' + str(uuid.uuid4())
            response_id = '_' + str(uuid.uuid4())
            
            # Get user attributes
            attributes = {
                'username': current_user.username,
                'email': current_user.email,
                'name': current_user.username  # Add more attributes as needed
            }
            
            # Build the SAML response XML
            from lxml import etree
            
            # Create the root Response element
            nsmap = {
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
            }
            response_root = etree.Element('{urn:oasis:names:tc:SAML:2.0:protocol}Response', nsmap=nsmap)
            response_root.set('ID', response_id)
            response_root.set('Version', '2.0')
            response_root.set('IssueInstant', now.strftime('%Y-%m-%dT%H:%M:%SZ'))
            response_root.set('Destination', sp.acs_url)
            
            # Add Issuer
            issuer = etree.SubElement(response_root, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            issuer.text = current_app.config['SAML_ENTITY_ID']  # Use IdP's entity_id as issuer
            
            # Add Status
            status = etree.SubElement(response_root, '{urn:oasis:names:tc:SAML:2.0:protocol}Status')
            status_code = etree.SubElement(status, '{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
            status_code.set('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success')
            
            # Create Assertion
            assertion = etree.SubElement(response_root, '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            assertion.set('ID', assertion_id)
            assertion.set('Version', '2.0')
            assertion.set('IssueInstant', now.strftime('%Y-%m-%dT%H:%M:%SZ'))
            
            # Add Assertion Issuer
            assertion_issuer = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            assertion_issuer.text = current_app.config['SAML_ENTITY_ID']  # Use IdP's entity_id as issuer
            
            # Add Subject
            subject = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
            name_id = etree.SubElement(subject, '{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
            name_id.set('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
            name_id.text = current_user.email
            
            # Add Subject Confirmation
            subject_conf = etree.SubElement(subject, '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation')
            subject_conf.set('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
            conf_data = etree.SubElement(subject_conf, '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData')
            conf_data.set('NotOnOrAfter', not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'))
            conf_data.set('Recipient', sp.acs_url)
            
            # Add Conditions
            conditions = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
            conditions.set('NotBefore', now.strftime('%Y-%m-%dT%H:%M:%SZ'))
            conditions.set('NotOnOrAfter', not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'))
            audience_restriction = etree.SubElement(conditions, '{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction')
            audience = etree.SubElement(audience_restriction, '{urn:oasis:names:tc:SAML:2.0:assertion}Audience')
            audience.text = sp.acs_url  # Use SP's ACS URL as audience
            
            # Add Authentication Statement
            authn_statement = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement')
            authn_statement.set('AuthnInstant', now.strftime('%Y-%m-%dT%H:%M:%SZ'))
            authn_statement.set('SessionIndex', assertion_id)
            authn_context = etree.SubElement(authn_statement, '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext')
            authn_context_class = etree.SubElement(authn_context, '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef')
            authn_context_class.text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            
            # Add Attribute Statement
            attr_statement = etree.SubElement(assertion, '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
            for key, value in attributes.items():
                attr = etree.SubElement(attr_statement, '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
                attr.set('Name', key)
                attr_value = etree.SubElement(attr, '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')
                attr_value.text = value
            
            # Sign the assertion if certificates are available
            if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
                from signxml import XMLSigner, methods
                with open(self.key_path, 'rb') as key_file:
                    private_key = key_file.read()
                with open(self.cert_path, 'rb') as cert_file:
                    public_key = cert_file.read()
                    
                logging.info("[SAML] Certificate Details:")
                logging.info(f"[SAML] Certificate Path: {self.cert_path}")
                logging.info(f"[SAML] Certificate Content:\n{public_key.decode()}")
                
                # Create a copy of the assertion for signing
                assertion_copy = etree.fromstring(etree.tostring(assertion))
                
                # Log the assertion before signing
                logging.info("[SAML] Assertion before signing:")
                logging.info(etree.tostring(assertion_copy, pretty_print=True).decode())
                
                # Log the digest value from the assertion
                digest_value = assertion_copy.find('.//{http://www.w3.org/2000/09/xmldsig#}DigestValue')
                if digest_value is not None:
                    logging.info(f"[SAML] Assertion Digest Value: {digest_value.text}")
                
                signer = XMLSigner(
                    method=methods.enveloped,
                    c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
                    signature_algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    digest_algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
                )
                
                try:
                    signed_xml = signer.sign(assertion_copy, key=private_key, cert=public_key)
                    
                    # Clean up the certificate in the signed XML
                    cert_elem = signed_xml.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
                    if cert_elem is not None:
                        cert_content = cert_elem.text.strip()
                        cert_content = cert_content.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')
                        cert_elem.text = cert_content
                    
                    # Log the signed assertion
                    logging.info("[SAML] Signed Assertion:")
                    logging.info(etree.tostring(signed_xml, pretty_print=True).decode())
                    
                    # Replace the unsigned assertion with the signed one
                    old_assertion = response_root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
                    response_root.remove(old_assertion)
                    response_root.append(signed_xml)
                    
                    # Log the final response
                    logging.info("[SAML] Final SAML Response:")
                    logging.info(etree.tostring(response_root, pretty_print=True).decode())
                    
                    logging.info("[SAML] Successfully signed SAML assertion")
                except Exception as e:
                    logging.error(f"[SAML] Error signing assertion: {str(e)}")
                    raise
            else:
                logging.error(f"[SAML] Certificate files not found at {self.cert_path} or {self.key_path}")
            
            # Convert to string and encode
            response_str = etree.tostring(response_root, pretty_print=True, encoding='utf-8').decode('utf-8')
            
            # Base64 encode the response
            from base64 import b64encode
            encoded_response = b64encode(response_str.encode('utf-8')).decode('utf-8')
            
            # Return template with auto-submit form
            return render_template('auth/saml_response.html',
                                acs_url=sp.acs_url,
                                saml_response=encoded_response,
                                relay_state=return_to)
                                
        except Exception as e:
            current_app.logger.error(f"Error in process_sso_request: {str(e)}")
            raise
    
    def process_response(self, sp_id: str) -> Tuple[bool, Any]:
        """Process SAML response from IdP"""
        auth = self.init_auth(request, sp_id)
        auth.process_response()
        
        if not auth.is_authenticated():
            return False, "Authentication failed"
        
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        
        identity = UserIdentity.objects(
            provider='saml', 
            provider_user_id=name_id
        ).first()
        
        if identity:
            user = identity.user
        else:
            email = attributes.get('email', [None])[0] or name_id
            user = User.objects(email=email).first()
            
            if not user:
                username = attributes.get('username', [None])[0] or email.split('@')[0]
                user = User(
                    username=username,
                    email=email,
                    active=True
                )
                user.save()
            
            identity = UserIdentity(
                provider='saml',
                provider_user_id=name_id,
                user=user,
                metadata=attributes
            )
            identity.save()
            
        return True, user
    
    def logout(self, sp_id: str, return_to: Optional[str] = None):
        """Generate SAML logout request"""
        auth = self.init_auth(request, sp_id)
        return redirect(auth.logout(return_to=return_to))
    
    def get_metadata(self, sp_id: str) -> Tuple[bool, str]:
        """Get SAML metadata for this service provider"""
        settings = self._get_saml_settings(sp_id)
        saml_settings = OneLogin_Saml2_Settings(settings)
        metadata = saml_settings.get_sp_metadata()
        
        errors = saml_settings.validate_metadata(metadata)
        if errors:
            return False, errors
            
        return True, metadata

    def get_idp_metadata(self, sp_id: str) -> str:
        sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
        if not sp:
            raise ValueError(f"Service provider {sp_id} not found or not SAML")
        cert_content = ""
        if os.path.exists(self.cert_path):
            with open(self.cert_path, 'r') as f:
                cert_content = f.read().strip()
                cert_content = cert_content.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')
        entity_id = current_app.config['SAML_ENTITY_ID']
        sso_url = url_for('auth.saml_sso', sp_id=sp_id, _external=True)
        slo_url = url_for('auth.saml_sls', sp_id=sp_id, _external=True)
        metadata = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:xsi="https://www.w3.org/2001/XMLSchema-instance"
    entityID="{entity_id}">
  <IDPSSODescriptor WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert_content}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo_url}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>
'''
        return metadata

def build_aws_saml_response(user, sp):
    """
    Build a properly signed SAML Response for AWS with required attributes.
    """
    import base64
    import datetime
    import uuid
    from onelogin.saml2.response import OneLogin_Saml2_Response
    from onelogin.saml2.constants import OneLogin_Saml2_Constants
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    from lxml import etree
    from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
    
    now = datetime.datetime.utcnow()
    not_on_or_after = now + datetime.timedelta(minutes=5)
    
    cert_file = current_app.config['SAML_CERT_PATH']
    key_file = current_app.config['SAML_KEY_PATH']
    
    with open(cert_file, 'r') as f:
        cert = f.read()
    
    with open(key_file, 'r') as f:
        key = f.read()
    
    role_arn = f"arn:aws:iam::{sp.aws_account_id}:role/{sp.aws_role}" if sp.aws_account_id and sp.aws_role else ""
    provider_arn = f"arn:aws:iam::{sp.aws_account_id}:saml-provider/{sp.aws_provider}" if sp.aws_account_id and sp.aws_provider else ""
    aws_role = f"{role_arn},{provider_arn}" if role_arn and provider_arn else ""
    role_session_name = user.email or user.username
    
    logging.info(f"[SAML] Building SAML Response for user: {user.email}, aws_role: {aws_role}, role_session_name: {role_session_name}")
    logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {sp.acs_url}")
    
    assertion_id = f"_{uuid.uuid4()}"
    response_id = f"_{uuid.uuid4()}"
    
    # Build SAML response XML
    saml_response_xml = OneLogin_Saml2_Templates.RESPONSE % {
        'id': response_id,
        'issue_instant': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'destination': sp.acs_url,
        'issuer': current_app.config['SAML_ENTITY_ID'],
        'status': OneLogin_Saml2_Constants.STATUS_SUCCESS,
        'assertion': ''
    }
    
    # Create assertion template
    assertion_xml = OneLogin_Saml2_Templates.ASSERTION % {
        'id': assertion_id,
        'issue_instant': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'issuer': current_app.config['SAML_ENTITY_ID'],
        'name_id': user.email,
        'name_id_format': OneLogin_Saml2_Constants.NAMEID_EMAIL_ADDRESS,
        'recipient': sp.acs_url,
        'audience': sp.entity_id,
        'not_on_or_after': not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'not_before': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'authn_context_class': OneLogin_Saml2_Constants.AC_PASSWORD_PROTECTED_TRANSPORT,
        'session_not_on_or_after': not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'attributes': ''
    }
    
    # Add AWS-specific attributes to the assertion
    attributes = f'''
    <saml:AttributeStatement>
        <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
            <saml:AttributeValue>{aws_role}</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
            <saml:AttributeValue>{role_session_name}</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
    '''
    
    # Insert attributes into assertion
    assertion_xml = assertion_xml.replace('<saml:Subject>', attributes + '<saml:Subject>')
    
    assertion_tree = etree.fromstring(assertion_xml)
    response_tree = etree.fromstring(saml_response_xml)
    
    # Sign the assertion
    assertion_signed = OneLogin_Saml2_Utils.add_sign(assertion_tree, key, cert)
    
    # Add signed assertion to the response
    response_tree.append(assertion_signed)
    
    # Sign the entire response
    response_signed = OneLogin_Saml2_Utils.add_sign(response_tree, key, cert)
    
    # Convert to string and encode as base64
    response_xml = etree.tostring(response_signed, pretty_print=False)
    logging.info(f"[SAML] SAML Response XML: {response_xml}")
    
    return base64.b64encode(response_xml).decode()

def build_jenkins_saml_response(user, sp):
    """
    Build a properly signed SAML Response for Jenkins with required attributes.
    """
    import base64
    import datetime
    import uuid
    from onelogin.saml2.response import OneLogin_Saml2_Response
    from onelogin.saml2.constants import OneLogin_Saml2_Constants
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    from lxml import etree
    from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
    
    now = datetime.datetime.utcnow()
    not_on_or_after = now + datetime.timedelta(minutes=5)
    
    cert_file = current_app.config['SAML_CERT_PATH']
    key_file = current_app.config['SAML_KEY_PATH']
    
    with open(cert_file, 'r') as f:
        cert = f.read()
    
    with open(key_file, 'r') as f:
        key = f.read()
    
    logging.info(f"[SAML] Building SAML Response for Jenkins user: {user.email}")
    logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {sp.acs_url}")
    
    assertion_id = f"_{uuid.uuid4()}"
    response_id = f"_{uuid.uuid4()}"
    
    # Build SAML response XML
    saml_response_xml = OneLogin_Saml2_Templates.RESPONSE % {
        'id': response_id,
        'issue_instant': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'destination': sp.acs_url,
        'issuer': current_app.config['SAML_ENTITY_ID'],
        'status': OneLogin_Saml2_Constants.STATUS_SUCCESS,
        'assertion': ''
    }
    
    # Create assertion template
    assertion_xml = OneLogin_Saml2_Templates.ASSERTION % {
        'id': assertion_id,
        'issue_instant': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'issuer': current_app.config['SAML_ENTITY_ID'],
        'name_id': user.email,
        'name_id_format': OneLogin_Saml2_Constants.NAMEID_EMAIL_ADDRESS,
        'recipient': sp.acs_url,
        'audience': sp.entity_id,
        'not_on_or_after': not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'not_before': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'authn_context_class': OneLogin_Saml2_Constants.AC_PASSWORD_PROTECTED_TRANSPORT,
        'session_not_on_or_after': not_on_or_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'attributes': ''
    }
    
    attributes = f'''
    <saml:AttributeStatement>
        <saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{user.username}</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">{user.email}</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">authenticated</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
    '''
    
    # Insert attributes into assertion
    assertion_xml = assertion_xml.replace('<saml:Subject>', attributes + '<saml:Subject>')
    
    logging.info(f"[SAML] Jenkins Assertion XML: {assertion_xml}")
    
    assertion_tree = etree.fromstring(assertion_xml)
    response_tree = etree.fromstring(saml_response_xml)
    
    # Sign the assertion
    assertion_signed = OneLogin_Saml2_Utils.add_sign(assertion_tree, key, cert)
    
    # Add signed assertion to the response
    response_tree.append(assertion_signed)
    
    # Sign the entire response
    response_signed = OneLogin_Saml2_Utils.add_sign(response_tree, key, cert)
    
    # Convert to string and encode as base64
    response_xml = etree.tostring(response_signed, pretty_print=False)
    logging.info(f"[SAML] SAML Response XML for Jenkins: {response_xml}")
    
    return base64.b64encode(response_xml).decode()

def handle_aws_authn_request(sp_id):
    logging.info(f"[SAML] handle_aws_authn_request called for sp_id: {sp_id}")
    # If not logged in, redirect to login
    if not current_user.is_authenticated:
        logging.info("[SAML] User not authenticated, redirecting to login.")
        session['saml_return_to'] = request.url
        return redirect(url_for('auth.login', next=request.url))

    # Get the ServiceProvider
    from ..models import ServiceProvider
    sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
    if not sp:
        logging.error(f"[SAML] ServiceProvider with ID {sp_id} not found")
        return redirect(url_for('main.dashboard'))
        
    if not (sp.aws_role and sp.aws_provider and sp.aws_account_id):
        logging.error(f"[SAML] AWS role, provider, or account ID not configured for {sp.name}")
        session['flash_message'] = f"AWS role not configured for {sp.name}. Please contact administrator."
        return redirect(url_for('main.dashboard'))

    # Build SAML Response and POST to AWS
    from .saml import build_aws_saml_response
    logging.info(f"[SAML] ServiceProvider: {sp}")
    saml_response = build_aws_saml_response(current_user, sp)
    logging.info(f"[SAML] Generated SAMLResponse for AWS, posting to: {sp.acs_url}")
    clean_acs_url = sp.acs_url.rstrip(',').strip() if sp.acs_url else ''
    if 'signin.aws.amazon.com' in clean_acs_url and ',' in clean_acs_url:
        clean_acs_url = clean_acs_url.split(',')[0].strip()
    logging.info(f"[SAML] Cleaned ACS URL: {clean_acs_url}")
    return render_template('auth/aws_post.html', acs_url=clean_acs_url, saml_response=saml_response)

saml_manager = SAMLManager()
