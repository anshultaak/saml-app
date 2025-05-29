from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, ServiceProvider
from ..auth.saml_manager import SAMLManager
from ..auth.oidc import oidc_manager
from werkzeug.security import check_password_hash
import logging
import mongoengine as me

saml_manager = SAMLManager()

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Main login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.objects(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!')
            
            # Check if there's a SAML request in the session
            saml_request = session.pop('saml_request', None)
            relay_state = session.pop('saml_relay_state', None)
            sp_id = session.pop('saml_sp_id', None)
            
            if saml_request and sp_id:
                return redirect(url_for('auth.saml_sso', 
                                     sp_id=sp_id,
                                     SAMLRequest=saml_request,
                                     RelayState=relay_state))
            elif sp_id:
                return redirect(url_for('auth.saml_login', sp_id=sp_id))
            
            return redirect(request.args.get('next') or url_for('main.index'))
        else:
            flash('Invalid username or password.')
    
    service_providers = ServiceProvider.objects(active=True).all()
    return render_template('auth/login.html', providers=service_providers)

@auth_bp.route('/login/saml/<sp_id>', methods=['GET', 'POST'])
def saml_login(sp_id):
    sp = ServiceProvider.objects(id=sp_id).first()
    if not sp:
        flash('Service Provider not found.')
        return redirect(url_for('auth.login'))
        
    is_aws_provider = sp.entity_id and 'aws' in sp.entity_id.lower() or \
                      sp.name and 'aws' in sp.name.lower()
    
    is_jenkins_provider = sp.entity_id and 'jenkins' in sp.entity_id.lower() or \
                         sp.name and 'jenkins' in sp.name.lower()
                      
    # Forward SAMLRequest and RelayState if present
    saml_request = request.args.get('SAMLRequest') or request.form.get('SAMLRequest')
    relay_state = request.args.get('RelayState') or request.form.get('RelayState')
    sig_alg = request.args.get('SigAlg') or request.form.get('SigAlg')
    signature = request.args.get('Signature') or request.form.get('Signature')
    
    if current_user.is_authenticated:
        if saml_request:
            return redirect(url_for('auth.saml_sso', sp_id=sp_id, SAMLRequest=saml_request, RelayState=relay_state, SigAlg=sig_alg, Signature=signature))
        if is_aws_provider:
            return redirect(url_for('auth.saml_aws', sp_id=sp_id))
        elif is_jenkins_provider:
            return redirect(url_for('auth.saml_jenkins', sp_id=sp_id))
        else:
            # For other SPs, generate a SAML response
            return saml_manager.process_sso_request(sp_id)

    if saml_request:
        return redirect(url_for('auth.saml_sso', sp_id=sp_id, SAMLRequest=saml_request, RelayState=relay_state, SigAlg=sig_alg, Signature=signature))

    # If not logged in, store the SP ID and redirect to login
    session['saml_sp_id'] = sp_id
    return_to = request.args.get('next', url_for('main.index'))
    return redirect(url_for('auth.login', next=return_to))

@auth_bp.route('/login/oidc/<sp_id>')
def oidc_login(sp_id):
    """Initiate OIDC authentication"""
    return_to = request.args.get('next', url_for('main.index'))
    return oidc_manager.login(sp_id, return_to)

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth_bp.route('/saml/acs/<sp_id>', methods=['POST'])
def saml_acs(sp_id):
    """SAML Assertion Consumer Service endpoint"""
    success, result = saml_manager.process_response(sp_id)
    
    if success:
        login_user(result)
        flash('Login successful!')
        
        return_to = session.get('saml_return_to')
        if return_to:
            del session['saml_return_to']
            return redirect(return_to)
            
        return redirect(url_for('main.index'))
    else:
        flash(f'Login failed: {result}')
        return redirect(url_for('auth.login'))

@auth_bp.route('/saml/sls/<sp_id>', methods=['GET', 'POST'])
def saml_sls(sp_id):
    """SAML Single Logout Service endpoint"""
    sp = ServiceProvider.objects(id=sp_id).first()
    if sp and (sp.entity_id and 'aws' in sp.entity_id.lower() or sp.name and 'aws' in sp.name.lower()):
        return redirect(url_for('main.dashboard'))
    else:
        logout_user()
        flash('You have been logged out.')
        return redirect(url_for('main.index'))

@auth_bp.route('/saml/metadata/<sp_id>')
def saml_metadata(sp_id):
    """SAML metadata endpoint"""
    metadata = saml_manager.get_metadata()
    return metadata, 200, {'Content-Type': 'text/xml'}

@auth_bp.route('/saml/metadata.xml')
def saml_metadata_public():
    """Public SAML metadata endpoint for Jenkins to consume"""
    metadata = saml_manager.get_metadata()
    return metadata, 200, {'Content-Type': 'text/xml'}

@auth_bp.route('/oidc/callback/<sp_id>')
def oidc_callback(sp_id):
    """OIDC authentication callback endpoint"""
    success, result = oidc_manager.process_callback(sp_id)
    
    if success:
        login_user(result)
        flash('Login successful!')
        
        return_to = session.get('oidc_return_to')
        if return_to:
            del session['oidc_return_to']
            return redirect(return_to)
            
        return redirect(url_for('main.index'))
    else:
        flash(f'Login failed: {result}')
        return redirect(url_for('auth.login'))

@auth_bp.route('/saml/aws/<sp_id>', methods=['GET'])
@login_required
def saml_aws(sp_id):
    """Generate and POST SAML Response for AWS"""
    return saml_manager.handle_aws_login(sp_id)

@auth_bp.route('/saml/jenkins/<sp_id>', methods=['GET'])
@login_required
def saml_jenkins(sp_id):
    """Generate and POST SAML Response for Jenkins"""
    relay_state = request.args.get('RelayState')
    return saml_manager.handle_jenkins_login(sp_id, relay_state)

@auth_bp.route('/saml/sso', methods=['GET', 'POST'])
@auth_bp.route('/saml/sso/<sp_id>', methods=['GET', 'POST'])
def saml_sso(sp_id=None):
    """SAML Single Sign-On Service endpoint"""
    try:
        saml_request = request.args.get('SAMLRequest') or request.form.get('SAMLRequest')
        relay_state = request.args.get('RelayState') or request.form.get('RelayState')
        sig_alg = request.args.get('SigAlg') or request.form.get('SigAlg')
        signature = request.args.get('Signature') or request.form.get('Signature')
        
        logging.info(f"SAML SSO request received with parameters: SAMLRequest={saml_request is not None}, "
                     f"RelayState={relay_state is not None}, SigAlg={sig_alg is not None}, "
                     f"Signature={signature is not None}")
        
        if not current_user.is_authenticated:
            # Store SAML request details in session
            if saml_request:
                session['saml_request'] = saml_request
                session['saml_relay_state'] = relay_state
                session['saml_sp_id'] = sp_id
            return redirect(url_for('auth.login'))
            
        if saml_request:
            # This is an SP-initiated login from Jenkins or other service provider
            return saml_manager.process_sso_request(sp_id, relay_state, saml_request, sig_alg, signature)
        elif sp_id:
            return saml_manager.process_sso_request(sp_id, relay_state)
        else:
            flash('Invalid SAML request')
            return redirect(url_for('auth.login'))
    except Exception as e:
        current_app.logger.error(f"Error processing SAML request: {str(e)}")
        flash('Error processing SAML request.')
        return redirect(url_for('auth.login'))

@auth_bp.route('/saml/jenkins/auth', methods=['GET', 'POST'])
def jenkins_saml_auth():
    """Handle SAML authentication request from Jenkins"""
    try:
        saml_request = request.args.get('SAMLRequest')
        relay_state = request.args.get('RelayState')
        sig_alg = request.args.get('SigAlg')
        signature = request.args.get('Signature')
        
        if not saml_request:
            flash('Missing SAMLRequest parameter')
            return redirect(url_for('auth.login'))
        
        # Find Jenkins service provider
        sp = ServiceProvider.objects(name__icontains='jenkins', protocol='saml').first()
        if not sp:
            flash('Jenkins service provider not found')
            return redirect(url_for('auth.login'))
            
        return saml_manager.process_sso_request(str(sp.id), relay_state, saml_request, sig_alg, signature)
    except Exception as e:
        current_app.logger.error(f"Error processing Jenkins SAML request: {str(e)}")
        flash('Error processing Jenkins SAML request')
        return redirect(url_for('auth.login'))
