"""
SAML response generation module.
Handles building and signing of SAML responses for different service providers.
"""
import base64
import datetime
import logging
import uuid
import os
from flask import current_app
from lxml import etree
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from .saml_config import SAMLConfig

class SAMLResponseBuilder:
    """Class for building SAML responses."""
    
    @staticmethod
    def _sign_xml(xml_string, key_file):
        """
        Sign an XML document using OpenSSL command line.
        
        Args:
            xml_string (str): The XML string to sign.
            key_file (str): Path to the private key file.
            
        Returns:
            str: The signed XML string.
        """
        try:
            with open(key_file, 'rb') as key_file_obj:
                private_key_data = key_file_obj.read()
                
            root = etree.fromstring(xml_string)
            
            ns = {
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'ec': 'http://www.w3.org/2001/10/xml-exc-c14n#'
            }
            
            for prefix, uri in ns.items():
                etree.register_namespace(prefix, uri)
            
            signature = etree.SubElement(root, "{http://www.w3.org/2000/09/xmldsig#}Signature", nsmap={'ds': ns['ds']})
            
            signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
            
            canon_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")
            canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            sig_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
            sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            
            reference = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference")
            reference.set("URI", "")
            
            transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
            
            transform = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            
            digest_method = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            
            digest_value = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
            
            canonicalized_xml = etree.tostring(root, method='c14n', exclusive=True)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(canonicalized_xml)
            digest_result = digest.finalize()
            digest_value.text = base64.b64encode(digest_result).decode('utf-8')
            
            signature_value = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            
            # Sign the SignedInfo
            signed_info_xml = etree.tostring(signed_info, method='c14n', exclusive=True)
            
            private_key = load_pem_private_key(private_key_data, password=None)
            
            # Sign the data
            signature_bytes = private_key.sign(
                signed_info_xml,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            signature_value.text = base64.b64encode(signature_bytes).decode('utf-8')
            
            key_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
            
            x509_data = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
            
            x509_cert = etree.SubElement(x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
            
            # Get the certificate
            cert_path = SAMLConfig.get_cert_path()
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = load_pem_x509_certificate(cert_data)
                
            cert_text = cert_data.decode('utf-8')
            cert_text = cert_text.replace('-----BEGIN CERTIFICATE-----', '')
            cert_text = cert_text.replace('-----END CERTIFICATE-----', '')
            cert_text = cert_text.replace('\n', '')
            x509_cert.text = cert_text
            
            return etree.tostring(root).decode('utf-8')
        except Exception as e:
            logging.error(f"Error signing XML: {str(e)}")
            return xml_string
    
    @staticmethod
    def build_aws_response(user, sp):
        """
        Build a SAML response for AWS.
        
        Args:
            user: The user object.
            sp: The service provider object.
            
        Returns:
            str: Base64-encoded SAML response XML.
        """
        if not (sp.aws_role and sp.aws_provider and sp.aws_account_id):
            logging.error(f"AWS role, provider, or account ID not configured for {sp.name}")
            raise ValueError(f"AWS role not configured for {sp.name}")
            
        role_arn = f"arn:aws:iam::{sp.aws_account_id}:role/{sp.aws_role}"
        provider_arn = f"arn:aws:iam::{sp.aws_account_id}:saml-provider/{sp.aws_provider}"
        aws_role = f"{role_arn},{provider_arn}"
        role_session_name = user.email or user.username
        
        logging.info(f"[SAML] Building SAML Response for user: {user.email}, aws_role: {aws_role}, role_session_name: {role_session_name}")
        logging.info(f"[SAML] SP entity_id: {sp.entity_id}, ACS URL: {sp.acs_url}")
        
        issuer_value = SAMLConfig.get_entity_id()
        
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        
        response_xml = f"""
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{response_id}" Version="2.0" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Destination="{sp.acs_url}">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Version="2.0">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user.email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Recipient="{sp.acs_url}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AudienceRestriction>
              <saml:Audience>urn:amazon:webservices</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
              <saml:AttributeValue>{aws_role}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
              <saml:AttributeValue>{role_session_name}</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
        
        </samlp:Response>
        """
        
        logging.info(f"[SAML] SAML Response XML: \n{response_xml}")
        
        # Sign the SAML response
        key_path = SAMLConfig.get_key_path()
        try:
            signed_response = SAMLResponseBuilder._sign_xml(response_xml, key_path)
            return base64.b64encode(signed_response.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing SAML response: {str(e)}")
            return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def build_jenkins_response(user, sp):
        """
        Build a SAML response for Jenkins.
        
        Args:
            user: The user object.
            sp: The service provider object.
            
        Returns:
            str: Base64-encoded SAML response XML.
        """
        logging.info(f"[SAML] Building SAML Response for Jenkins user: {user.email}")
        
        issuer_value = SAMLConfig.get_entity_id()
        
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        
        response_xml = f"""
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{response_id}" Version="2.0" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Destination="{sp.acs_url}">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Version="2.0">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user.email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Recipient="{sp.acs_url}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AudienceRestriction>
              <saml:Audience>{sp.entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                   xsi:type="xs:string">{user.username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">{user.email}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">authenticated</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
        
        </samlp:Response>
        """
        
        # Sign the SAML response
        key_path = SAMLConfig.get_key_path()
        try:
            signed_response = SAMLResponseBuilder._sign_xml(response_xml, key_path)
            return base64.b64encode(signed_response.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing SAML response: {str(e)}")
            return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def build_github_response(user, sp):
        """
        Build a SAML response for GitHub.
        
        Args:
            user: The user object.
            sp: The service provider object.
            
        Returns:
            str: Base64-encoded SAML response XML.
        """
        logging.info(f"[SAML] Building SAML Response for GitHub user: {user.email}")
        
        issuer_value = SAMLConfig.get_entity_id()
        
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        
        response_xml = f"""
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{response_id}" Version="2.0" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Destination="{sp.acs_url}">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Version="2.0">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user.email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Recipient="{sp.acs_url}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AudienceRestriction>
              <saml:Audience>{sp.entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>
            <saml:Attribute Name="login" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                   xsi:type="xs:string">{user.username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">{user.email}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">{user.username}</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
        
        </samlp:Response>
        """
        
        # Sign the SAML response
        key_path = SAMLConfig.get_key_path()
        try:
            signed_response = SAMLResponseBuilder._sign_xml(response_xml, key_path)
            return base64.b64encode(signed_response.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing SAML response: {str(e)}")
            return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def build_generic_response(user, sp):
        """
        Build a generic SAML response for standard providers.
        
        Args:
            user: The user object.
            sp: The service provider object.
            
        Returns:
            str: Base64-encoded SAML response XML.
        """
        logging.info(f"[SAML] Building generic SAML Response for user: {user.email}")
        
        issuer_value = SAMLConfig.get_entity_id()
        
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        
        custom_attributes = ""
        if hasattr(sp, 'attribute_mapping') and sp.attribute_mapping:
            for attr_name, attr_value in sp.attribute_mapping.items():
                if attr_value == '{user.email}':
                    attr_value = user.email
                elif attr_value == '{user.username}':
                    attr_value = user.username
                
                custom_attributes += f"""
            <saml:Attribute Name="{attr_name}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">{attr_value}</saml:AttributeValue>
            </saml:Attribute>"""
        else:
            custom_attributes = f"""
            <saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" 
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                                   xsi:type="xs:string">{user.username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
              <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                   xsi:type="xs:string">{user.email}</saml:AttributeValue>
            </saml:Attribute>"""
        
        response_xml = f"""
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{response_id}" Version="2.0" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Destination="{sp.acs_url}">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Version="2.0">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user.email}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" Recipient="{sp.acs_url}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}" NotOnOrAfter="{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AudienceRestriction>
              <saml:Audience>{sp.entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant="{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>{custom_attributes}
          </saml:AttributeStatement>
        </saml:Assertion>
        
        </samlp:Response>
        """
        
        # Sign the SAML response
        key_path = SAMLConfig.get_key_path()
        try:
            signed_response = SAMLResponseBuilder._sign_xml(response_xml, key_path)
            return base64.b64encode(signed_response.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing SAML response: {str(e)}")
            return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')
