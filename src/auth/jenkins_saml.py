"""
Jenkins-specific SAML response builder.
Handles SAML authentication flows specifically for Jenkins.
"""
import logging
import base64
from datetime import datetime, timedelta
from lxml import etree
from lxml.etree import Element, SubElement, QName
from ..models import User, ServiceProvider

class JenkinsSAMLResponseBuilder:
    """Class for building SAML responses specifically for Jenkins."""
    
    @staticmethod
    def build_jenkins_response(user, sp, in_response_to=None):
        """
        Build a SAML response specifically formatted for Jenkins.
        
        Args:
            user: The authenticated user
            sp: The service provider (Jenkins)
            in_response_to: The ID of the original SAML request
            
        Returns:
            str: Base64 encoded SAML response
        """
        try:
            # Create namespaces
            nsmap = {
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
            }
            
            # Create response element
            response = Element(QName(nsmap['samlp'], 'Response'), nsmap=nsmap)
            response.set('ID', f'_{sp.id}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}')
            response.set('Version', '2.0')
            response.set('IssueInstant', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
            response.set('Destination', sp.acs_url)
            if in_response_to:
                response.set('InResponseTo', in_response_to)
            
            # Add Issuer
            issuer = SubElement(response, QName(nsmap['saml'], 'Issuer'))
            issuer.text = sp.entity_id
            
            # Add Status
            status = SubElement(response, QName(nsmap['samlp'], 'Status'))
            status_code = SubElement(status, QName(nsmap['samlp'], 'StatusCode'))
            status_code.set('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success')
            
            # Create Assertion
            assertion = SubElement(response, QName(nsmap['saml'], 'Assertion'))
            assertion.set('ID', f'_{sp.id}_assertion_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}')
            assertion.set('Version', '2.0')
            assertion.set('IssueInstant', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
            
            # Add Issuer to Assertion
            assertion_issuer = SubElement(assertion, QName(nsmap['saml'], 'Issuer'))
            assertion_issuer.text = sp.entity_id
            
            # Add Subject
            subject = SubElement(assertion, QName(nsmap['saml'], 'Subject'))
            name_id = SubElement(subject, QName(nsmap['saml'], 'NameID'))
            name_id.set('Format', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
            name_id.text = user.email
            
            subject_confirmation = SubElement(subject, QName(nsmap['saml'], 'SubjectConfirmation'))
            subject_confirmation.set('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
            
            subject_confirmation_data = SubElement(subject_confirmation, QName(nsmap['saml'], 'SubjectConfirmationData'))
            subject_confirmation_data.set('NotOnOrAfter', (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            if in_response_to:
                subject_confirmation_data.set('InResponseTo', in_response_to)
            subject_confirmation_data.set('Recipient', sp.acs_url)
            
            # Add Conditions
            conditions = SubElement(assertion, QName(nsmap['saml'], 'Conditions'))
            conditions.set('NotBefore', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
            conditions.set('NotOnOrAfter', (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            
            # Add Audience Restriction
            audience_restriction = SubElement(conditions, QName(nsmap['saml'], 'AudienceRestriction'))
            audience = SubElement(audience_restriction, QName(nsmap['saml'], 'Audience'))
            audience.text = sp.entity_id
            
            # Add AuthnStatement
            authn_statement = SubElement(assertion, QName(nsmap['saml'], 'AuthnStatement'))
            authn_statement.set('AuthnInstant', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
            authn_statement.set('SessionIndex', f'_{sp.id}_session_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}')
            
            authn_context = SubElement(authn_statement, QName(nsmap['saml'], 'AuthnContext'))
            authn_context_class_ref = SubElement(authn_context, QName(nsmap['saml'], 'AuthnContextClassRef'))
            authn_context_class_ref.text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            
            # Add AttributeStatement
            attribute_statement = SubElement(assertion, QName(nsmap['saml'], 'AttributeStatement'))
            
            # Add email attribute
            email_attribute = SubElement(attribute_statement, QName(nsmap['saml'], 'Attribute'))
            email_attribute.set('Name', 'email')
            email_attribute.set('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
            email_value = SubElement(email_attribute, QName(nsmap['saml'], 'AttributeValue'))
            email_value.text = user.email
            
            # Add username attribute
            username_attribute = SubElement(attribute_statement, QName(nsmap['saml'], 'Attribute'))
            username_attribute.set('Name', 'username')
            username_attribute.set('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic')
            username_value = SubElement(username_attribute, QName(nsmap['saml'], 'AttributeValue'))
            username_value.text = user.username
            
            # Convert to string and encode
            response_str = etree.tostring(response, pretty_print=True, encoding='unicode')
            return base64.b64encode(response_str.encode('utf-8')).decode('utf-8')
            
        except Exception as e:
            logging.error(f"Error building Jenkins SAML response: {str(e)}")
            raise 