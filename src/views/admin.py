from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from ..models import ServiceProvider
import mongoengine as me

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
@login_required
def index():
    """Admin dashboard"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin area.')
        return redirect(url_for('main.index'))
    
    return render_template('admin/index.html')

@admin_bp.route('/providers')
@login_required
def providers():
    """List all service providers"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin area.')
        return redirect(url_for('main.index'))
    
    providers = ServiceProvider.objects.all()
    return render_template('admin/providers.html', providers=providers)

@admin_bp.route('/providers/new', methods=['GET', 'POST'])
@login_required
def new_provider():
    """Create a new service provider"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin area.')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        protocol = request.form.get('protocol')
        
        
        if not name or not protocol:
            flash('Name and protocol are required fields.')
            return redirect(url_for('admin.new_provider'))
            
        provider = ServiceProvider(
            name=name,
            description=description,
            protocol=protocol,
            active=True
        )
        
        if protocol == 'saml':
            provider.entity_id = request.form.get('entity_id')
            provider.metadata_url = request.form.get('metadata_url')
            acs_url = request.form.get('acs_url', '').rstrip(',')
            provider.acs_url = acs_url
            provider.sso_url = request.form.get('sso_url')
            provider.slo_url = request.form.get('slo_url')
            provider.x509cert = request.form.get('x509cert')
            
            if provider.entity_id and 'aws' in provider.entity_id.lower() or provider.name and 'aws' in provider.name.lower():
                provider.aws_account_id = request.form.get('aws_account_id')
                provider.aws_role = request.form.get('aws_role')
                provider.aws_provider = request.form.get('aws_provider')
        elif protocol == 'oidc':
            provider.client_id = request.form.get('client_id')
            provider.client_secret = request.form.get('client_secret')
            provider.metadata_url = request.form.get('metadata_url')
        
        provider.save()
        
        flash(f'Service provider {name} created successfully!')
        return redirect(url_for('admin.providers'))
        
    return render_template('admin/provider_form.html', provider=None)

@admin_bp.route('/providers/edit/<sp_id>', methods=['GET', 'POST'])
@login_required
def edit_provider(sp_id):
    """Edit an existing service provider"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin area.')
        return redirect(url_for('main.index'))
    
    try:
        provider = ServiceProvider.objects(id=sp_id).first()
        if not provider:
            abort(404)
    except me.ValidationError:
        abort(404)
    
    if request.method == 'POST':
        provider.name = request.form.get('name')
        provider.description = request.form.get('description')
        provider.active = 'active' in request.form
        
        if provider.protocol == 'saml':
            provider.entity_id = request.form.get('entity_id')
            provider.metadata_url = request.form.get('metadata_url')
            acs_url = request.form.get('acs_url', '').rstrip(',')
            provider.acs_url = acs_url
            provider.sso_url = request.form.get('sso_url')
            provider.slo_url = request.form.get('slo_url')
            provider.x509cert = request.form.get('x509cert')
            
            if provider.entity_id and 'aws' in provider.entity_id.lower() or provider.name and 'aws' in provider.name.lower():
                provider.aws_account_id = request.form.get('aws_account_id')
                provider.aws_role = request.form.get('aws_role')
                provider.aws_provider = request.form.get('aws_provider')
        elif provider.protocol == 'oidc':
            provider.client_id = request.form.get('client_id')
            provider.client_secret = request.form.get('client_secret')
            provider.metadata_url = request.form.get('metadata_url')
        
        provider.save()
        
        flash(f'Service provider {provider.name} updated successfully!')
        return redirect(url_for('admin.providers'))
        
    return render_template('admin/provider_form.html', provider=provider)

@admin_bp.route('/providers/delete/<sp_id>', methods=['POST'])
@login_required
def delete_provider(sp_id):
    """Delete a service provider"""
    if not current_user.is_admin:
        flash('You do not have permission to access the admin area.')
        return redirect(url_for('main.index'))
    
    try:
        provider = ServiceProvider.objects(id=sp_id).first()
        if not provider:
            abort(404)
        name = provider.name
        provider.delete()
        flash(f'Service provider {name} deleted successfully!')
    except me.ValidationError:
        flash('Invalid service provider ID.')
    
    return redirect(url_for('admin.providers'))
