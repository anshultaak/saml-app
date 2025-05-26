"""
SAML metadata generation module.
Handles generation of IdP metadata for service providers.
"""
import logging
import os
from .saml_config import SAMLConfig

class SAMLMetadata:
    """Class for generating SAML metadata."""
    
    @staticmethod
    def generate_metadata():
        """
        Generate standard IdP metadata XML with the certificate included.
        
        Returns:
            str: The IdP metadata XML.
        """
        try:
            cert, _ = SAMLConfig.load_cert_and_key()
            
            cert_formatted = cert.replace('-----BEGIN CERTIFICATE-----', '')
            cert_formatted = cert_formatted.replace('-----END CERTIFICATE-----', '')
            cert_formatted = cert_formatted.replace('\n', '')
            
            logging.info(f"Certificate used in metadata (first 60 chars): {cert_formatted[:60]}")
            
            entity_id = SAMLConfig.get_entity_id()
            
            base_url = os.environ.get('SAML_BASE_URL', entity_id)
            
            metadata = f'''<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert_formatted}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{base_url}/auth/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{base_url}/auth/saml/sso"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{base_url}/auth/saml/slo"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{base_url}/auth/saml/slo"/>
  </IDPSSODescriptor>
</EntityDescriptor>
'''
            logging.info(f"Generated SAML metadata for entity ID: {entity_id}, base URL: {base_url}")
            return metadata
        except Exception as e:
            logging.error(f"Error generating SAML metadata: {str(e)}")
            raise
