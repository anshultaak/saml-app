"""
SAML authentication manager module.
Handles SAML authentication flows and service provider integration.
"""
import logging
import os
import base64
from flask import current_app, request, url_for, session, redirect, render_template, flash
from flask_login import current_user, login_user, logout_user
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS as NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_PERSISTENT

from .saml_config import SAMLConfig
from .saml_metadata import SAMLMetadata
from .saml_response import SAMLResponseBuilder
from ..models import User, ServiceProvider

class SAMLManager:
    """Class for managing SAML authentication flows."""
    
    def __init__(self):
        """Initialize the SAML manager."""
        self.app = None
    
    def init_app(self, app):
        """Initialize with Flask app."""
        self.app = app
        logging.info("SAML Manager initialized")
    
    def _prepare_flask_request(self):
        """
        Prepare the Flask request for the python-saml library.
        
        Returns:
            dict: Request data in the format expected by python-saml.
        """
        url_data = request.url.split('?')
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'script_name': request.path,
            'server_port': request.environ.get('SERVER_PORT', '80'),
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            'query_string': request.query_string.decode('utf-8')
        }
    
    def _get_saml_settings(self, sp_id):
        """
        Get SAML settings for a specific service provider.
        
        Args:
            sp_id (str): The ID of the service provider.
            
        Returns:
            tuple: (success, settings_or_error) - Success flag and settings or error.
        """
        try:
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                return False, "Service Provider not found"
            
            entity_id = SAMLConfig.get_entity_id()
            cert_path = SAMLConfig.get_cert_path()
            key_path = SAMLConfig.get_key_path()
            
            # Log the certificate used for signing
            with open(cert_path, 'r') as f:
                cert = f.read()
            cert_formatted = cert.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')
            logging.info(f"Certificate used for signing (first 60 chars): {cert_formatted[:60]}")
            
            config = {
                "entityid": entity_id,
                "service": {
                    "sp": {
                        "name": "SSO Service Provider",
                        "endpoints": {
                            "assertion_consumer_service": [
                                (url_for('auth.saml_acs', sp_id=sp_id, _external=True), BINDING_HTTP_POST),
                            ],
                            "single_logout_service": [
                                (url_for('auth.saml_sls', sp_id=sp_id, _external=True), BINDING_HTTP_REDIRECT),
                            ],
                        },
                        "name_id_format": NAMEID_FORMAT_EMAIL,
                        "authn_requests_signed": True,
                        "want_assertions_signed": True,
                        "allow_unsolicited": True,
                    },
                },
                "key_file": key_path,
                "cert_file": cert_path,
                "metadata": {
                    "local": [sp.metadata_path] if hasattr(sp, 'metadata_path') and sp.metadata_path else [],
                },
                "debug": 1,
                "allow_unknown_attributes": True,
            }
            
            if sp.entity_id:
                config["metadata"]["inline"] = [self._generate_idp_metadata(sp)]
            
            saml_config = Saml2Config()
            saml_config.load(config)
            
            return True, saml_config
        except Exception as e:
            logging.error(f"Error getting SAML settings: {str(e)}")
            return False, str(e)
    
    def _generate_idp_metadata(self, sp):
        """
        Generate IdP metadata for a service provider.
        
        Args:
            sp: The service provider object.
            
        Returns:
            str: IdP metadata XML.
        """
        entity_id = sp.entity_id
        sso_url = sp.sso_url or ""
        slo_url = sp.slo_url or ""
        x509cert = sp.x509cert or ""
        
        if x509cert:
            x509cert = x509cert.replace('-----BEGIN CERTIFICATE-----', '')
            x509cert = x509cert.replace('-----END CERTIFICATE-----', '')
            x509cert = x509cert.replace('\n', '')
        
        metadata = f"""
        <EntityDescriptor entityID="{entity_id}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
          <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <KeyDescriptor use="signing">
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                  <X509Certificate>{x509cert}</X509Certificate>
                </X509Data>
              </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="{BINDING_HTTP_REDIRECT}" Location="{sso_url}"/>
            <SingleLogoutService Binding="{BINDING_HTTP_REDIRECT}" Location="{slo_url}"/>
          </IDPSSODescriptor>
        </EntityDescriptor>
        """
        
        return metadata
    
    def _get_saml_auth(self, sp_id):
        """
        Get SAML auth object for a specific service provider.
        
        Args:
            sp_id (str): The ID of the service provider.
            
        Returns:
            tuple: (success, auth_or_error) - Success flag and auth object or error.
        """
        try:
            success, config = self._get_saml_settings(sp_id)
            
            if not success:
                return False, config
            
            # Create Saml2Client
            client = Saml2Client(config)
            return True, client
        except Exception as e:
            logging.error(f"Error getting SAML auth: {str(e)}")
            return False, str(e)
    
    def login(self, sp_id, return_to=None):
        """
        Initiate SAML login for a service provider.
        
        Args:
            sp_id (str): The ID of the service provider.
            return_to (str, optional): URL to return to after login.
            
        Returns:
            Response: Flask response.
        """
        try:
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                logging.error(f"Service Provider with ID {sp_id} not found")
                return redirect(url_for('auth.login'))
            
            is_aws = (sp.entity_id and 'aws' in sp.entity_id.lower()) or \
                    (sp.name and 'aws' in sp.name.lower())
            
            is_jenkins = (sp.entity_id and 'jenkins' in sp.entity_id.lower()) or \
                        (sp.name and 'jenkins' in sp.name.lower())
                        
            if current_user.is_authenticated:
                if is_aws:
                    return self.handle_aws_login(sp_id)
                elif is_jenkins:
                    return self.handle_jenkins_login(sp_id)
            
            if sp.sso_url:
                session['saml_return_to'] = return_to
                return redirect(sp.sso_url)
            
            success, client = self._get_saml_auth(sp_id)
            if not success:
                logging.error(f"Failed to initialize SAML auth: {client}")
                return redirect(url_for('auth.login'))
            
            try:
                reqid, info = client.prepare_for_authenticate()
                
                session['saml_request_id'] = reqid
                session['saml_return_to'] = return_to
                
                headers = dict(info['headers'])
                return redirect(headers['Location'])
            except Exception as e:
                logging.error(f"Error preparing SAML authentication request: {str(e)}")
                return redirect(url_for('auth.login'))
        except Exception as e:
            logging.error(f"Error initiating SAML login: {str(e)}")
            return redirect(url_for('auth.login'))
    
    def process_sso_request(self, sp_id=None, relay_state=None, saml_request=None, sig_alg=None, signature=None):
        """
        Process SAML SSO request.
        
        Args:
            sp_id (str, optional): The ID of the service provider.
            relay_state (str, optional): Relay state from the request.
            saml_request (str, optional): SAMLRequest parameter from the request.
            sig_alg (str, optional): Signature algorithm from the request.
            signature (str, optional): Signature from the request.
            
        Returns:
            Response: Flask response.
        """
        try:
            if saml_request:
                logging.info(f"Processing SP-initiated SAML request for SP: {sp_id}")
                
                if not sp_id:
                    jenkins_sp = ServiceProvider.objects(name__icontains='jenkins', protocol='saml').first()
                    if jenkins_sp:
                        sp_id = str(jenkins_sp.id)
                        logging.info(f"Using Jenkins SP with id: {sp_id}")
            
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                logging.error(f"Service Provider with ID {sp_id} not found")
                return redirect(url_for('auth.login'))
            
            if not current_user.is_authenticated:
                # Store SAML request details in session
                session['saml_request'] = saml_request
                session['saml_relay_state'] = relay_state
                session['saml_sp_id'] = sp_id
                return redirect(url_for('auth.login'))
            
            try:
                # First URL decode the SAML request
                import urllib.parse
                decoded_request = urllib.parse.unquote(saml_request)
                
                # Then base64 decode
                decoded_request = base64.b64decode(decoded_request)
                
                # Decompress the request (it's deflated)
                import zlib
                decoded_request = zlib.decompress(decoded_request, -15)
                
                # Parse the XML
                from lxml import etree
                # Define SAML namespaces
                namespaces = {
                    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
                }
                
                # Create a parser that doesn't validate namespaces
                parser = etree.XMLParser(remove_blank_text=True, recover=True)
                root = etree.fromstring(decoded_request, parser=parser)
                
                # Try multiple approaches to get the request ID
                request_id = None
                
                # First try: direct attribute on root
                if root.get('ID'):
                    request_id = root.get('ID')
                
                # Second try: AuthnRequest element
                if not request_id:
                    authn_request = root.find('.//{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest')
                    if authn_request is not None:
                        request_id = authn_request.get('ID')
                
                # Third try: XPath with namespaces
                if not request_id:
                    try:
                        request_id = root.xpath('//samlp:AuthnRequest/@ID', namespaces=namespaces)[0]
                    except (IndexError, KeyError):
                        pass
                
                if not request_id:
                    raise ValueError("Could not find request ID in SAML request")
                    
                logging.info(f"Extracted request ID: {request_id}")
                
                if current_user.is_authenticated:
                    if 'aws' in sp.name.lower():
                        return self.handle_aws_login(sp_id)
                    elif 'jenkins' in sp.name.lower():
                        return self.handle_jenkins_login(sp_id, relay_state)
                    else:
                        # Use generic response for other SPs
                        saml_response = SAMLResponseBuilder.build_generic_response(current_user, sp, in_response_to=request_id)
                        return render_template('auth/saml_post.html',
                                            acs_url=sp.acs_url,
                                            saml_response=saml_response,
                                            relay_state=relay_state)
                
                session['saml_request_id'] = request_id
                session['saml_relay_state'] = relay_state
                session['saml_sp_id'] = sp_id
                
                return redirect(url_for('auth.login'))
            except Exception as e:
                logging.error(f"Error decoding SAML request: {str(e)}")
                return redirect(url_for('auth.login'))
            
            return redirect(url_for('auth.login'))
        except Exception as e:
            logging.error(f"Error processing SAML SSO request: {str(e)}")
            return redirect(url_for('auth.login'))
    
    def process_acs(self, sp_id):
        """
        Process SAML Assertion Consumer Service request.
        
        Args:
            sp_id (str): The ID of the service provider.
            
        Returns:
            Response: Flask response.
        """
        try:
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                logging.error(f"Service Provider with ID {sp_id} not found")
                return redirect(url_for('auth.login'))
            
            success, client = self._get_saml_auth(sp_id)
            if not success:
                logging.error(f"Failed to initialize SAML auth: {client}")
                return redirect(url_for('auth.login'))
            
            try:
                saml_response = request.form.get('SAMLResponse')
                if not saml_response:
                    logging.error("No SAML response found in request")
                    return redirect(url_for('auth.login'))
                
                decoded_response = base64.b64decode(saml_response).decode('utf-8')
                
                from lxml import etree
                root = etree.fromstring(decoded_response)
                namespaces = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
                name_id_element = root.find('.//saml:NameID', namespaces=namespaces)
                
                if name_id_element is not None:
                    name_id = name_id_element.text
                    
                    user = User.objects(email=name_id).first()
                    if not user:
                        user = User(email=name_id, username=name_id.split('@')[0])
                        user.save()
                    
                    login_user(user)
                    
                    return_to = session.pop('saml_return_to', url_for('main.dashboard'))
                    return redirect(return_to)
                else:
                    logging.error("No NameID found in SAML response")
                    return redirect(url_for('auth.login'))
            except Exception as e:
                logging.error(f"Error processing SAML response: {str(e)}")
                return redirect(url_for('auth.login'))
        except Exception as e:
            logging.error(f"Error processing SAML ACS request: {str(e)}")
            return redirect(url_for('auth.login'))
    
    def process_slo(self, sp_id):
        """
        Process SAML Single Logout request.
        
        Args:
            sp_id (str): The ID of the service provider.
            
        Returns:
            Response: Flask response.
        """
        try:
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                logging.error(f"Service Provider with ID {sp_id} not found")
                return redirect(url_for('auth.login'))
            
            success, client = self._get_saml_auth(sp_id)
            if not success:
                logging.error(f"Failed to initialize SAML auth: {client}")
                return redirect(url_for('auth.login'))
            
            try:
                is_aws = (sp.entity_id and 'aws' in sp.entity_id.lower()) or \
                        (sp.name and 'aws' in sp.name.lower())
                
                is_jenkins = (sp.entity_id and 'jenkins' in sp.entity_id.lower()) or \
                            (sp.name and 'jenkins' in sp.name.lower())
                
                if is_aws or is_jenkins:
                    return redirect(url_for('main.dashboard'))
                
                logout_user()
                
                return redirect(url_for('auth.login'))
            except Exception as e:
                logging.error(f"Error processing SAML SLO request: {str(e)}")
                return redirect(url_for('auth.login'))
        except Exception as e:
            logging.error(f"Error processing SAML SLO request: {str(e)}")
            return redirect(url_for('auth.login'))
    
    def get_metadata(self):
        """
        Get IdP metadata.
        
        Returns:
            str: SAML metadata XML.
        """
        try:
            return SAMLMetadata.generate_metadata()
        except Exception as e:
            logging.error(f"Error generating metadata: {str(e)}")
            return str(e)
    
    def handle_aws_login(self, sp_id):
        """
        Handle AWS SSO login.
        
        Args:
            sp_id (str): The ID of the service provider.
            
        Returns:
            Response: Flask response.
        """
        from flask import Response
        
        sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
        if not sp:
            logging.error(f"AWS Service Provider with ID {sp_id} not found")
            return redirect(url_for('main.dashboard'))
        
        try:
            saml_response = SAMLResponseBuilder.build_aws_response(current_user, sp)
            
            clean_acs_url = sp.acs_url.rstrip(',').strip() if sp.acs_url else ''
            if 'signin.aws.amazon.com' in clean_acs_url and ',' in clean_acs_url:
                clean_acs_url = clean_acs_url.split(',')[0].strip()
            
            logging.info(f"[SAML] Posting AWS SAML response to: {clean_acs_url}")
            logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {clean_acs_url}")
            
            response = render_template('auth/aws_post.html', acs_url=clean_acs_url, saml_response=saml_response)
            if not isinstance(response, Response):
                response = Response(response, mimetype='text/html')
            return response
        except Exception as e:
            logging.error(f"Error building AWS SAML response: {str(e)}")
            return redirect(url_for('main.dashboard'))
    
    def handle_jenkins_login(self, sp_id, relay_state=None):
        """
        Handle Jenkins SSO login.
        
        Args:
            sp_id (str): The ID of the service provider.
            relay_state (str, optional): Relay state to include in the SAML response.
            
        Returns:
            Response: Flask response.
        """
        sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
        if not sp:
            logging.error(f"Jenkins Service Provider with ID {sp_id} not found")
            return redirect(url_for('main.dashboard'))
        
        try:
            saml_response = SAMLResponseBuilder.build_jenkins_response(current_user, sp)
            
            clean_acs_url = sp.acs_url.strip() if sp.acs_url else ''
            
            if clean_acs_url and not clean_acs_url.startswith(('http://', 'https://')):
                clean_acs_url = f"https://{clean_acs_url}"
            
            logging.info(f"[SAML] Posting Jenkins SAML response to: {clean_acs_url}")
            logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {clean_acs_url}")
            logging.info(f"[SAML] Relay state: {relay_state}")
            
            from flask import Response
            response = render_template('auth/jenkins_post.html', 
                                      acs_url=clean_acs_url, 
                                      saml_response=saml_response,
                                      relay_state=relay_state)
            if not isinstance(response, Response):
                response = Response(response, mimetype='text/html')
            return response
        except Exception as e:
            logging.error(f"Error building Jenkins SAML response: {str(e)}")
            return redirect(url_for('main.dashboard'))

