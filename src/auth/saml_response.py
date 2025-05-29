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
                'ec': 'http://www.w3.org/2001/10/xml-exc-c14n#',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
            }
            
            for prefix, uri in ns.items():
                etree.register_namespace(prefix, uri)
            
            # Create signature element
            signature = etree.Element("{http://www.w3.org/2000/09/xmldsig#}Signature", nsmap={'ds': ns['ds']})
            
            # Find the Issuer element
            issuer = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            if issuer is not None:
                # Insert signature after Issuer
                issuer.addnext(signature)
            else:
                # If no Issuer found, insert at the beginning
                root.insert(0, signature)
            
            signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
            
            canon_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")
            canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            sig_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
            sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            
            # Set the Reference URI to the Assertion ID
            assertion_id = root.get('ID')
            reference = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference")
            if assertion_id:
                reference.set("URI", f"#{assertion_id}")
            
            transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
            
            transform = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            
            # Add exclusive canonicalization transform
            transform2 = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform2.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            logging.info("[SAML] Applied XML transforms:")
            logging.info("1. Enveloped signature transform")
            logging.info("2. Exclusive canonicalization transform")
            
            digest_method = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            
            digest_value = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
            
            # Create a copy of the root element without the signature
            root_copy = etree.fromstring(etree.tostring(root))
            signature_elem = root_copy.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            if signature_elem is not None:
                root_copy.remove(signature_elem)
            
            # Canonicalize the copy without the signature
            canonicalized_xml = etree.tostring(root_copy, method='c14n', exclusive=True)
            logging.info(f"[SAML] Canonicalized XML before digest (without signature): {canonicalized_xml.decode('utf-8')}")
            
            # Log the exact XML structure being signed
            logging.info("[SAML] XML Structure being signed:")
            for elem in root_copy.iter():
                logging.info(f"Element: {elem.tag}, Attributes: {elem.attrib}")
            
            digest = hashes.Hash(hashes.SHA256())
            digest.update(canonicalized_xml)
            digest_result = digest.finalize()
            digest_value.text = base64.b64encode(digest_result).decode('utf-8')
            
            # Log the digest value and the exact bytes being hashed
            logging.info(f"[SAML] Generated Digest Value: {digest_value.text}")
            logging.info(f"[SAML] Bytes being hashed (hex): {canonicalized_xml.hex()}")
            
            # Now add the signature to the original root
            signature_value = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            
            # Sign the SignedInfo
            signed_info_xml = etree.tostring(signed_info, method='c14n', exclusive=True)
            logging.info(f"[SAML] SignedInfo being signed: {signed_info_xml.decode('utf-8')}")
            
            private_key = load_pem_private_key(private_key_data, password=None)
            
            # Sign the data
            signature_bytes = private_key.sign(
                signed_info_xml,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            signature_value.text = base64.b64encode(signature_bytes).decode('utf-8')
            
            # Add KeyInfo with X509Certificate
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
            logging.info(f"SAMLResponseBuilder: Certificate used for signing (first 60 chars): {cert_text[:60]}")
            x509_cert.text = cert_text
            
            # Log the final signed XML
            final_xml = etree.tostring(root).decode('utf-8')
            logging.info(f"[SAML] Final signed XML: {final_xml}")
            
            return final_xml
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
              <saml:Audience>{sp.acs_url}</saml:Audience>
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
    def build_generic_response(user, sp, in_response_to=None):
        """
        Build a generic SAML response for service providers that don't have specific implementations.
        
        Args:
            user: The user object.
            sp: The service provider object.
            in_response_to: The ID of the request being responded to.
            
        Returns:
            str: Base64-encoded SAML response XML.
        """
        logging.info(f"[SAML] Building generic SAML Response for user: {user.email}")
        
        issuer_value = SAMLConfig.get_entity_id()
        
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        
        # Register all required namespaces
        nsmap = {
            'samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
            'saml': "urn:oasis:names:tc:SAML:2.0:assertion",
            'ds': "http://www.w3.org/2000/09/xmldsig#",
            'ec': "http://www.w3.org/2001/10/xml-exc-c14n#"
        }
        
        for prefix, uri in nsmap.items():
            etree.register_namespace(prefix, uri)
        
        # Create the base XML structure
        root = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}Response", 
                           attrib={
                               "ID": response_id,
                               "Version": "2.0",
                               "IssueInstant": now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                               "Destination": sp.acs_url.strip()  # Remove any extra spaces
                           },
                           nsmap=nsmap)
        
        if in_response_to:
            root.set("InResponseTo", in_response_to)
        
        # Add Response-level Issuer as the first child
        response_issuer = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        response_issuer.text = issuer_value
        root.insert(0, response_issuer)
        
        # Add Status next
        status = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
        status_code = etree.SubElement(status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
        
        # Create Assertion
        assertion = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
                                   attrib={
                                       "ID": assertion_id,
                                       "IssueInstant": now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                                       "Version": "2.0"
                                   })
        
        # Add Assertion Issuer
        assertion_issuer = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        assertion_issuer.text = issuer_value
        
        # Add Subject
        subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
        name_id = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
        name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        name_id.text = user.email
        
        subject_confirmation = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation")
        subject_confirmation.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        
        confirmation_data = etree.SubElement(subject_confirmation, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")
        confirmation_data.set("NotOnOrAfter", not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        confirmation_data.set("Recipient", sp.acs_url.strip())  # Remove any extra spaces
        if in_response_to:
            confirmation_data.set("InResponseTo", in_response_to)
        
        # Add Conditions
        conditions = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
        conditions.set("NotBefore", now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        conditions.set("NotOnOrAfter", not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        
        audience_restriction = etree.SubElement(conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
        audience = etree.SubElement(audience_restriction, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
        audience.text = sp.entity_id.strip()  # Remove any extra spaces
        
        # Add AuthnStatement
        authn_statement = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement")
        authn_statement.set("AuthnInstant", now.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
        
        authn_context = etree.SubElement(authn_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
        authn_context_class_ref = etree.SubElement(authn_context, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
        authn_context_class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        
        # Add AttributeStatement
        attribute_statement = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")
        
        # Add email attribute
        email_attr = etree.SubElement(attribute_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        email_attr.set("Name", "email")
        email_attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        email_value = etree.SubElement(email_attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        email_value.text = user.email
        
        # Add username attribute
        username_attr = etree.SubElement(attribute_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        username_attr.set("Name", "username")
        username_attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        username_value = etree.SubElement(username_attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        username_value.text = user.username
        
        # Convert assertion to string for signing
        assertion_xml = etree.tostring(assertion, encoding='unicode')
        logging.info(f"[SAML] Assertion XML before signing: \n{assertion_xml}")
        
        # Sign the Assertion
        key_path = SAMLConfig.get_key_path()
        try:
            signed_assertion = SAMLResponseBuilder._sign_xml(assertion_xml, key_path)
            signed_assertion_elem = etree.fromstring(signed_assertion)
            
            # Replace the original assertion with the signed one
            root.remove(assertion)
            root.append(signed_assertion_elem)
            
            # Convert final response to string
            final_xml = etree.tostring(root, encoding='unicode')
            logging.info(f"[SAML] Final SAML Response XML: \n{final_xml}")
            
            return base64.b64encode(final_xml.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing SAML response: {str(e)}")
            return base64.b64encode(etree.tostring(root, encoding='unicode').encode('utf-8')).decode('utf-8')
