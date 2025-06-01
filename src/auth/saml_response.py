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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
            
            # Create SignedInfo
            signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
            
            # Add canonicalization method
            canon_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")
            canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            # Add signature method
            sig_method = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
            sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            
            # Set the Reference URI to the Assertion ID
            assertion_id = root.get('ID')
            reference = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference")
            if assertion_id:
                reference.set("URI", f"#{assertion_id}")
            
            # Add transforms
            transforms = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
            
            # Add enveloped signature transform
            transform = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
            
            # Add exclusive canonicalization transform
            transform2 = etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform")
            transform2.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            
            # Add digest method
            digest_method = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
            digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
            
            # Add digest value
            digest_value = etree.SubElement(reference, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")
            
            # Create a copy of the root element without the signature
            root_copy = etree.fromstring(etree.tostring(root))
            signature_elem = root_copy.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            if signature_elem is not None:
                root_copy.remove(signature_elem)
            
            # Canonicalize the copy without the signature
            canonicalized_xml = etree.tostring(root_copy, method='c14n', exclusive=True)
            logger.info(f"[SAML] Canonicalized XML before digest (without signature): {canonicalized_xml.decode('utf-8')}")
            
            # Calculate digest
            digest = hashes.Hash(hashes.SHA256())
            digest.update(canonicalized_xml)
            digest_result = digest.finalize()
            digest_value.text = base64.b64encode(digest_result).decode('utf-8')
            
            # Log the digest value
            logger.info(f"[SAML] Generated Digest Value: {digest_value.text}")
            
            # Add signature value
            signature_value = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            
            # Sign the SignedInfo
            signed_info_xml = etree.tostring(signed_info, method='c14n', exclusive=True)
            logger.info(f"[SAML] SignedInfo being signed: {signed_info_xml.decode('utf-8')}")
            
            private_key = load_pem_private_key(private_key_data, password=None)
            
            # Sign the data
            signature_bytes = private_key.sign(
                signed_info_xml,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            signature_value.text = base64.b64encode(signature_bytes).decode('utf-8')
            
            # Add KeyInfo
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
            
            # Insert signature after Issuer if present, else at the start
            issuer = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            if issuer is not None and issuer.getparent() is root:
                root.insert(root.index(issuer) + 1, signature)
            else:
                root.insert(0, signature)
            
            # Log the final signed XML
            final_xml = etree.tostring(root).decode('utf-8')
            logger.info(f"[SAML] Final signed XML: {final_xml}")
            
            return final_xml
            
        except Exception as e:
            logger.error(f"[SAML] Error signing XML: {str(e)}", exc_info=True)
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
        logging.info(f"[SAML] Building SAML Response for user: {user.email}")
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
        
        # Use persistent NameID format and a unique, stable user ID
        persistent_id = getattr(user, 'id', None) or user.username
        
        custom_attributes = ""
        if hasattr(sp, 'attribute_mapping') and sp.attribute_mapping:
            for attr_name, attr_value in sp.attribute_mapping.items():
                # Use Python format string to support any {user.*} field
                try:
                    value = attr_value.format(user=user)
                except Exception:
                    # fallback to raw value if formatting fails
                    value = attr_value
                custom_attributes += f"""
            <saml:Attribute Name=\"{attr_name}\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
                                   xsi:type=\"xs:string\">{value}</saml:AttributeValue>
            </saml:Attribute>"""
        else:
            custom_attributes = f"""
            <saml:Attribute Name=\"username\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" 
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" 
                                   xsi:type=\"xs:string\">{user.username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
                                   xsi:type=\"xs:string\">{user.email}</saml:AttributeValue>
            </saml:Attribute>"""
        
        response_xml = f"""
        <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"{response_id}\" Version=\"2.0\" IssueInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Destination=\"{sp.acs_url}\">
          <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{assertion_id}\" IssueInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Version=\"2.0\">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{persistent_id}</saml:NameID>
            <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
              <saml:SubjectConfirmationData NotOnOrAfter=\"{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Recipient=\"{sp.acs_url}\"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" NotOnOrAfter=\"{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\">
            <saml:AudienceRestriction>
              <saml:Audience>{sp.entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\">
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

    @staticmethod
    def build_gitlab_response(user, sp):
        """
        Build a SAML response for GitLab SSO integration.
        Args:
            user: The user object.
            sp: The service provider object.
        Returns:
            str: Base64-encoded SAML response XML.
        """
        logging.info(f"[SAML] Building GitLab SAML Response for user: {user.email}")
        issuer_value = SAMLConfig.get_entity_id()
        response_id = f"_{uuid.uuid4()}"
        assertion_id = f"_{uuid.uuid4()}"
        now = datetime.datetime.utcnow()
        not_on_or_after = now + datetime.timedelta(minutes=5)
        persistent_id = getattr(user, 'id', None) or user.username
        custom_attributes = ""
        if hasattr(sp, 'attribute_mapping') and sp.attribute_mapping:
            for attr_name, attr_value in sp.attribute_mapping.items():
                try:
                    value = attr_value.format(user=user)
                except Exception:
                    value = attr_value
                custom_attributes += f"""
            <saml:Attribute Name=\"{attr_name}\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
                                   xsi:type=\"xs:string\">{value}</saml:AttributeValue>
            </saml:Attribute>"""
        else:
            custom_attributes = f"""
            <saml:Attribute Name=\"username\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" 
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" 
                                   xsi:type=\"xs:string\">{user.username}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
              <saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
                                   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
                                   xsi:type=\"xs:string\">{user.email}</saml:AttributeValue>
            </saml:Attribute>"""
        response_xml = f"""
        <samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"{response_id}\" Version=\"2.0\" IssueInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Destination=\"{sp.acs_url}\">
          <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{issuer_value}</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
          </samlp:Status>
          
        <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{assertion_id}\" IssueInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Version=\"2.0\">
          <saml:Issuer>{issuer_value}</saml:Issuer>
          <saml:Subject>
            <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{persistent_id}</saml:NameID>
            <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
              <saml:SubjectConfirmationData NotOnOrAfter=\"{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" Recipient=\"{sp.acs_url}\"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotBefore=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\" NotOnOrAfter=\"{not_on_or_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\">
            <saml:AudienceRestriction>
              <saml:Audience>{sp.entity_id}</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement AuthnInstant=\"{now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\">
            <saml:AuthnContext>
              <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
          </saml:AuthnStatement>
          <saml:AttributeStatement>{custom_attributes}
          </saml:AttributeStatement>
        </saml:Assertion>
        
        </samlp:Response>
        """
        key_path = SAMLConfig.get_key_path()
        try:
            signed_response = SAMLResponseBuilder._sign_xml(response_xml, key_path)
            return base64.b64encode(signed_response.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"[SAML] Error signing GitLab SAML response: {str(e)}")
            return base64.b64encode(response_xml.encode('utf-8')).decode('utf-8')
