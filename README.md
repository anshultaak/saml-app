# Python SSO Application

A Single Sign-On (SSO) login application that integrates with multiple cloud services using both SAML 2.0 and OpenID Connect (OIDC) protocols.

## Features

- SAML 2.0 Identity Provider (IdP) and Service Provider (SP) support
- OpenID Connect (OIDC) Provider and Relying Party support
- User management and authentication
- Integration with multiple cloud services
- Web interface for administration
- MongoDB for data storage

## Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/python-sso-application.git
cd python-sso-application
```

2. Create a `.env` file with your configuration:
```
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
MONGODB_URI=mongodb://mongo:27017/sso
```

3. Start the application with Docker Compose:
```bash
docker-compose up -d
```

4. Access the application at http://localhost:5000

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/python-sso-application.git
cd python-sso-application
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Install and start MongoDB:
```bash
# Follow MongoDB installation instructions for your OS
# https://docs.mongodb.com/manual/installation/
```

4. Create a `.env` file with your configuration:
```
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
MONGODB_URI=mongodb://localhost:27017/sso
```

5. Generate SAML certificates:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/sp.key -out certs/sp.crt -days 365 -nodes
```

6. Run the application:
```bash
flask run
```

## Configuration

### SAML Configuration

To configure SAML providers, you need to:

1. Generate certificates (if not done during installation):
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/sp.key -out certs/sp.crt -days 365 -nodes
```

2. Use the admin interface to add SAML service providers with the following information:
   - Name: A friendly name for the service
   - Entity ID: The entity ID of the service provider
   - Metadata URL: The URL where the service provider's metadata can be found
   - ACS URL: The Assertion Consumer Service URL of the service provider

### OIDC Configuration

To configure OIDC providers, you need to:

1. Register your application with the OIDC provider to get client credentials
2. Use the admin interface to add OIDC service providers with the following information:
   - Name: A friendly name for the service
   - Client ID: The client ID provided by the OIDC provider
   - Client Secret: The client secret provided by the OIDC provider
   - Metadata URL: The URL of the OIDC provider's discovery document (usually ends with `.well-known/openid-configuration`)

## Usage

1. Access the application at http://localhost:5000
2. Log in using the configured authentication providers
3. Manage service providers in the admin interface

## Development

1. Run tests:
```bash
pytest
```

2. Check code style:
```bash
flake8
```

## Security Considerations

- Always use HTTPS in production
- Keep your SAML certificates and OIDC client secrets secure
- Regularly update dependencies to patch security vulnerabilities
- Use strong passwords for admin accounts
- Configure proper session timeouts
