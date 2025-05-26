import os
import logging
from flask import current_app

def generate_idp_metadata():
    """
    Generate IdP metadata XML with the certificate included.
    """
    cert_file = current_app.config['SAML_CERT_PATH']
    
    with open(cert_file, 'r') as f:
        cert = f.read()
    
    cert_formatted = cert.replace('-----BEGIN CERTIFICATE-----', '')
    cert_formatted = cert_formatted.replace('-----END CERTIFICATE-----', '')
    cert_formatted = cert_formatted.replace('\n', '')
    
    entity_id = current_app.config['SAML_ENTITY_ID']
    
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
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{entity_id}/saml/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{entity_id}/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>
'''
    return metadata
