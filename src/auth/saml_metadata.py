"""
SAML metadata generation module.
Provides functionality for generating SAML IdP metadata.
"""
import os
from .saml_config import SAMLConfig

class SAMLMetadata:
    """Class for generating SAML metadata."""
    
    @staticmethod
    def generate_metadata():
        """
        Generate SAML IdP metadata XML.
        
        Returns:
            str: SAML metadata XML.
        """
        entity_id = SAMLConfig.get_entity_id()
        base_url = SAMLConfig.get_base_url()
        
        cert_path = SAMLConfig.get_cert_path()
        cert_content = ""
        
        if os.path.exists(cert_path):
            with open(cert_path, 'r') as cert_file:
                cert_data = cert_file.read()
                cert_content = cert_data.replace('-----BEGIN CERTIFICATE-----', '')
                cert_content = cert_content.replace('-----END CERTIFICATE-----', '')
                cert_content = cert_content.replace('\n', '').strip()
        
        metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="{entity_id}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>{cert_content}</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{base_url}/auth/saml/sso"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{base_url}/auth/saml/sso"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{base_url}/auth/saml/slo"/>
    </IDPSSODescriptor>
</EntityDescriptor>"""
        
        return metadata_xml
