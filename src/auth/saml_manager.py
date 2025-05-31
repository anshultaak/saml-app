"""
SAML authentication manager module.
Handles SAML authentication flows and service provider integration.
"""
import logging
import os
import base64
from flask import current_app, request, url_for, session, redirect, render_template
from flask_login import current_user, login_user, logout_user
import uuid
import datetime
try:
    from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
    from saml2.client import Saml2Client
    from saml2.config import Config as Saml2Config
    from saml2.saml import NAMEID_FORMAT_EMAILADDRESS as NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_PERSISTENT
    SAML_AVAILABLE = True
except ImportError:
    logging.warning("SAML dependencies not available - SAML functionality disabled")
    SAML_AVAILABLE = False
    BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    NAMEID_FORMAT_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    NAMEID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

from .saml_config import SAMLConfig
from .saml_metadata import SAMLMetadata
from .saml_response import SAMLResponseBuilder
from .provider_registry import provider_registry
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
            
            if not SAML_AVAILABLE:
                return False, "SAML dependencies not available"
                
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
            
            if current_user.is_authenticated:
                handler = provider_registry.get_handler(sp)
                return self.handle_provider_login(sp_id, handler)
            
            if sp.sso_url:
                session['saml_return_to'] = return_to
                return redirect(sp.sso_url)
            
            if not SAML_AVAILABLE:
                logging.error("SAML login attempted but SAML dependencies not available")
                return redirect(url_for('auth.login'))
                
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
            logging.info(f"[SAML] process_sso_request called with saml_request: {saml_request[:100] if saml_request else None}")
            if saml_request:
                logging.info(f"Processing SP-initiated SAML request for SP: {sp_id}")
                if not sp_id:
                    jenkins_sp = ServiceProvider.objects(name__icontains='jenkins', protocol='saml').first()
                    if jenkins_sp:
                        sp_id = str(jenkins_sp.id)
                        logging.info(f"Using Jenkins SP with id: {sp_id}")
                    else:
                        any_sp = ServiceProvider.objects(protocol='saml').first()
                        if any_sp:
                            sp_id = str(any_sp.id)
                            logging.info(f"No Jenkins SP found, using first available SAML SP with id: {sp_id}")
                        else:
                            logging.error("No SAML service providers found")
                            return redirect(url_for('auth.login'))
            sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
            if not sp:
                logging.error(f"Service Provider with ID {sp_id} not found")
                return redirect(url_for('auth.login'))
            handler = provider_registry.get_handler(sp)
            in_response_to = None
            # Only extract and pass in_response_to for github
            if handler.get_provider_type() == 'github' and saml_request:
                try:
                    import base64
                    from lxml import etree
                    import zlib
                    import urllib.parse
                    logging.info(f"[SAML] Processing GitHub SAML request: {saml_request[:100]}...")
                    saml_request_decoded = base64.b64decode(saml_request)
                    try:
                        saml_request_xml = zlib.decompress(saml_request_decoded, -15)
                        logging.info("[SAML] Successfully decompressed SAML request (HTTP-Redirect binding)")
                    except Exception:
                        saml_request_xml = saml_request_decoded
                        logging.info("[SAML] Using SAML request as-is (HTTP-POST binding)")
                    logging.info(f"[SAML] Decoded SAML request XML: {saml_request_xml.decode('utf-8')}")
                    root = etree.fromstring(saml_request_xml)
                    in_response_to = root.get('ID')
                    logging.info(f"[SAML] Extracted InResponseTo ID: {in_response_to}")
                except Exception as e:
                    logging.error(f"Failed to extract InResponseTo from SAMLRequest: {str(e)}", exc_info=True)
            if handler.get_provider_type() == 'github':
                logging.info(f"[SAML] Building GitHub SAML response with InResponseTo: {in_response_to}")
                saml_response = handler.build_saml_response(current_user, sp, in_response_to=in_response_to)
            else:
                saml_response = handler.build_saml_response(current_user, sp)
            template = handler.get_template_name()
            clean_acs_url = handler.process_acs_url(sp.acs_url, sp)
            logging.info(f"[SAML] Posting SAML response to: {clean_acs_url}")
            from flask import Response
            response = render_template(template, 
                                      acs_url=clean_acs_url, 
                                      saml_response=saml_response,
                                      relay_state=relay_state)
            if not isinstance(response, Response):
                response = Response(response, mimetype='text/html')
            return response
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
            
            if not SAML_AVAILABLE:
                logging.error("SAML login attempted but SAML dependencies not available")
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
            
            if not SAML_AVAILABLE:
                logging.error("SAML login attempted but SAML dependencies not available")
                return redirect(url_for('auth.login'))
                
            success, client = self._get_saml_auth(sp_id)
            if not success:
                logging.error(f"Failed to initialize SAML auth: {client}")
                return redirect(url_for('auth.login'))
            
            try:
                handler = provider_registry.get_handler(sp)
                if handler.get_provider_type() in ['aws', 'jenkins']:
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
    
    def handle_provider_login(self, sp_id, handler, relay_state=None):
        """
        Handle SSO login for any provider type using the provider registry.
        
        Args:
            sp_id (str): The ID of the service provider.
            handler: The provider handler instance.
            relay_state (str, optional): Relay state to include in the SAML response.
            
        Returns:
            Response: Flask response.
        """
        from flask import Response
        
        sp = ServiceProvider.objects(id=sp_id, protocol='saml').first()
        if not sp:
            logging.error(f"Service Provider with ID {sp_id} not found")
            return redirect(url_for('main.dashboard'))
        
        try:
            saml_response = handler.build_saml_response(current_user, sp)
            clean_acs_url = handler.process_acs_url(sp.acs_url, sp)
            template = handler.get_template_name()
            
            logging.info(f"[SAML] Posting {handler.get_provider_type()} SAML response to: {clean_acs_url}")
            logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {clean_acs_url}")
            if relay_state:
                logging.info(f"[SAML] Relay state: {relay_state}")
            
            response = render_template(template, 
                                      acs_url=clean_acs_url, 
                                      saml_response=saml_response,
                                      relay_state=relay_state)
            if not isinstance(response, Response):
                response = Response(response, mimetype='text/html')
            return response
        except Exception as e:
            logging.error(f"Error building {handler.get_provider_type()} SAML response: {str(e)}")
            return redirect(url_for('main.dashboard'))

    @staticmethod
    def build_github_response(user, sp, in_response_to=None):
        logging.info(f"[SAML] Building SAML Response for GitHub user: {user.email}")
        issuer_value = SAMLConfig.get_entity_id()
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)

        nsmap = {
            'samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
            'saml': "urn:oasis:names:tc:SAML:2.0:assertion",
            'ds': "http://www.w3.org/2000/09/xmldsig#",
            'ec': "http://www.w3.org/2001/10/xml-exc-c14n#"
        }
        for prefix, uri in nsmap.items():
            etree.register_namespace(prefix, uri)

        # Build the Response
        response_attrs = {
            "ID": response_id,
            "Version": "2.0",
            "IssueInstant": now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "Destination": sp.acs_url.strip()
        }
        if in_response_to:
            response_attrs["InResponseTo"] = in_response_to
        root = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}Response", attrib=response_attrs, nsmap=nsmap)

        # Add Issuer
        response_issuer = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        response_issuer.text = issuer_value

        # Add Status
        status = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
        status_code = etree.SubElement(status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

        # Build Assertion
        assertion_attrs = {
            "ID": assertion_id,
            "IssueInstant": now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "Version": "2.0"
        }
        assertion = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion", attrib=assertion_attrs)

        # Assertion Issuer
        assertion_issuer = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        assertion_issuer.text = issuer_value

        # Subject
        subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
        name_id = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
        name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        name_id.text = user.email
        subject_confirmation = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation")
        subject_confirmation.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        confirmation_data = etree.SubElement(subject_confirmation, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")
        confirmation_data.set("NotOnOrAfter", not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        confirmation_data.set("Recipient", sp.acs_url.strip())
        if in_response_to:
            confirmation_data.set("InResponseTo", in_response_to)

        # Conditions
        conditions = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
        conditions.set("NotBefore", now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        conditions.set("NotOnOrAfter", not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        audience_restriction = etree.SubElement(conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
        audience = etree.SubElement(audience_restriction, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
        audience.text = sp.entity_id.strip()

        # AuthnStatement
        authn_statement = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement")
        authn_statement.set("AuthnInstant", now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        authn_context = etree.SubElement(authn_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
        authn_context_class_ref = etree.SubElement(authn_context, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
        authn_context_class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

        # AttributeStatement
        attribute_statement = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")
        login_attr = etree.SubElement(attribute_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        login_attr.set("Name", "login")
        login_attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        login_value = etree.SubElement(login_attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        login_value.text = user.username
        email_attr = etree.SubElement(attribute_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        email_attr.set("Name", "email")
        email_attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        email_value = etree.SubElement(email_attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        email_value.text = user.email
        name_attr = etree.SubElement(attribute_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        name_attr.set("Name", "name")
        name_attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        name_value = etree.SubElement(name_attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        name_value.text = user.username

        # Sign the Assertion
        assertion_xml = etree.tostring(assertion, encoding='unicode')
        key_path = SAMLConfig.get_key_path()
        signed_assertion = SAMLResponseBuilder._sign_xml(assertion_xml, key_path)
        signed_assertion_elem = etree.fromstring(signed_assertion)

        # Replace the original assertion with the signed one
        root.append(signed_assertion_elem)

        # Convert final response to string
        final_xml = etree.tostring(root, encoding='unicode')
        logging.info(f"[SAML] Final SAML Response XML for GitHub: \n{final_xml}")

        return base64.b64encode(final_xml.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _sign_assertion_xml(assertion_xml, key_file):
        try:
            with open(key_file, 'rb') as key_file_obj:
                private_key_data = key_file_obj.read()

            assertion = etree.fromstring(assertion_xml)
            assertion_id = assertion.get('ID')

            # Create signature element
            ns = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            signature = etree.Element("{http://www.w3.org/2000/09/xmldsig#}Signature", nsmap={'ds': ns['ds']})

            signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
            canon_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")
            canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            sig_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
            sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            reference = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference")
            reference.set("URI", f"#{assertion_id}")

            transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
            transform = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            transform2 = etree.SubElement(transforms, "{http://www.w3.org/2001/10/xml-exc-c14n#}Transform")
            transform2.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

            digest_method = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            digest_value = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

            # Canonicalize the assertion without the signature
            assertion_copy = etree.fromstring(etree.tostring(assertion))
            signature_elem = assertion_copy.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            if signature_elem is not None:
                assertion_copy.remove(signature_elem)
            canonicalized_xml = etree.tostring(assertion_copy, method='c14n', exclusive=True)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(canonicalized_xml)
            digest_result = digest.finalize()
            digest_value.text = base64.b64encode(digest_result).decode('utf-8')

            signature_value = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            signed_info_xml = etree.tostring(signed_info, method='c14n', exclusive=True)
            private_key = load_pem_private_key(private_key_data, password=None)
            signature_bytes = private_key.sign(
                signed_info_xml,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_value.text = base64.b64encode(signature_bytes).decode('utf-8')

            key_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
            x509_data = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
            x509_cert = etree.SubElement(x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
            cert_path = SAMLConfig.get_cert_path()
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
            cert_text = cert_data.decode('utf-8')
            cert_text = cert_text.replace('-----BEGIN CERTIFICATE-----', '')
            cert_text = cert_text.replace('-----END CERTIFICATE-----', '')
            cert_text = cert_text.replace('\n', '')
            x509_cert.text = cert_text

            # Insert signature after Issuer
            issuer = assertion.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            if issuer is not None:
                issuer.addnext(signature)
            else:
                assertion.insert(0, signature)

            return etree.tostring(assertion, encoding='unicode')
        except Exception as e:
            logging.error(f"Error signing Assertion XML: {str(e)}")
            return assertion_xml
