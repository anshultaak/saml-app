from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from ..models import User, ServiceProvider
from werkzeug.security import generate_password_hash
import json
import logging

main_bp = Blueprint('main', __name__)

def admin_required(f):
    """Decorator to require admin access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required.')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@main_bp.route('/')
def index():
    """Main landing page."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    providers = ServiceProvider.objects(active=True).all()
    users_count = User.objects.count()
    providers_count = ServiceProvider.objects.count()
    
    return render_template('main/dashboard.html', 
                         providers=providers,
                         users_count=users_count,
                         providers_count=providers_count)

@main_bp.route('/admin/providers')
@login_required
@admin_required
def admin_providers():
    """List all service providers."""
    providers = ServiceProvider.objects.all()
    return render_template('admin/providers.html', providers=providers)

@main_bp.route('/admin/providers/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_provider_new():
    """Create a new service provider."""
    if request.method == 'POST':
        try:
            custom_attributes = {}
            attribute_mapping = {}
            
            if request.form.get('custom_attributes'):
                custom_attributes = json.loads(request.form.get('custom_attributes'))
            
            if request.form.get('attribute_mapping'):
                attribute_mapping = json.loads(request.form.get('attribute_mapping'))
            
            provider = ServiceProvider(
                name=request.form.get('name'),
                description=request.form.get('description'),
                protocol=request.form.get('protocol'),
                provider_type=request.form.get('provider_type'),
                entity_id=request.form.get('entity_id'),
                acs_url=request.form.get('acs_url'),
                sso_url=request.form.get('sso_url'),
                slo_url=request.form.get('slo_url'),
                x509cert=request.form.get('x509cert'),
                aws_role=request.form.get('aws_role'),
                aws_provider=request.form.get('aws_provider'),
                aws_account_id=request.form.get('aws_account_id'),
                custom_attributes=custom_attributes,
                attribute_mapping=attribute_mapping,
                active=request.form.get('active') == 'on'
            )
            provider.save()
            flash('Service provider created successfully!', 'success')
            return redirect(url_for('main.admin_providers'))
        except json.JSONDecodeError as e:
            flash(f'Invalid JSON in custom attributes or attribute mapping: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error creating provider: {str(e)}', 'error')
    
    return render_template('admin/provider_form.html', provider=None)

@main_bp.route('/admin/providers/<provider_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_provider_edit(provider_id):
    """Edit an existing service provider."""
    provider = ServiceProvider.objects(id=provider_id).first()
    if not provider:
        flash('Provider not found.', 'error')
        return redirect(url_for('main.admin_providers'))
    
    if request.method == 'POST':
        try:
            custom_attributes = {}
            attribute_mapping = {}
            
            if request.form.get('custom_attributes'):
                custom_attributes = json.loads(request.form.get('custom_attributes'))
            
            if request.form.get('attribute_mapping'):
                attribute_mapping = json.loads(request.form.get('attribute_mapping'))
            
            provider.name = request.form.get('name')
            provider.description = request.form.get('description')
            provider.protocol = request.form.get('protocol')
            provider.provider_type = request.form.get('provider_type')
            provider.entity_id = request.form.get('entity_id')
            provider.acs_url = request.form.get('acs_url')
            provider.sso_url = request.form.get('sso_url')
            provider.slo_url = request.form.get('slo_url')
            provider.x509cert = request.form.get('x509cert')
            provider.aws_role = request.form.get('aws_role')
            provider.aws_provider = request.form.get('aws_provider')
            provider.aws_account_id = request.form.get('aws_account_id')
            provider.custom_attributes = custom_attributes
            provider.attribute_mapping = attribute_mapping
            provider.active = request.form.get('active') == 'on'
            
            provider.save()
            flash('Service provider updated successfully!', 'success')
            return redirect(url_for('main.admin_providers'))
        except json.JSONDecodeError as e:
            flash(f'Invalid JSON in custom attributes or attribute mapping: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error updating provider: {str(e)}', 'error')
    
    return render_template('admin/provider_form.html', provider=provider)

@main_bp.route('/admin/providers/<provider_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_provider_delete(provider_id):
    """Delete a service provider."""
    provider = ServiceProvider.objects(id=provider_id).first()
    if provider:
        provider.delete()
        flash('Service provider deleted successfully!', 'success')
    else:
        flash('Provider not found.', 'error')
    return redirect(url_for('main.admin_providers'))

@main_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """List all users."""
    users = User.objects.all()
    return render_template('admin/users.html', users=users)

@main_bp.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_new():
    """Create a new user."""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin') == 'on'
            active = request.form.get('active') == 'on'
            
            if User.objects(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('admin/user_form.html', user=None)
            
            if User.objects(email=email).first():
                flash('Email already exists.', 'error')
                return render_template('admin/user_form.html', user=None)
            
            user = User(
                username=username,
                email=email,
                is_admin=is_admin,
                active=active
            )
            user.set_password(password)
            user.save()
            
            flash('User created successfully!', 'success')
            return redirect(url_for('main.admin_users'))
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'error')
    
    return render_template('admin/user_form.html', user=None)

@main_bp.route('/admin/users/<user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    """Edit an existing user."""
    user = User.objects(id=user_id).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('main.admin_users'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            is_admin = request.form.get('is_admin') == 'on'
            active = request.form.get('active') == 'on'
            
            existing_user = User.objects(username=username, id__ne=user.id).first()
            if existing_user:
                flash('Username already exists.', 'error')
                return render_template('admin/user_form.html', user=user)
            
            existing_user = User.objects(email=email, id__ne=user.id).first()
            if existing_user:
                flash('Email already exists.', 'error')
                return render_template('admin/user_form.html', user=user)
            
            user.username = username
            user.email = email
            user.is_admin = is_admin
            user.active = active
            
            if password:  # Only update password if provided
                user.set_password(password)
            
            user.save()
            flash('User updated successfully!', 'success')
            return redirect(url_for('main.admin_users'))
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    return render_template('admin/user_form.html', user=user)

@main_bp.route('/admin/users/<user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_user_delete(user_id):
    """Delete a user."""
    user = User.objects(id=user_id).first()
    if user:
        if user.id == current_user.id:
            flash('Cannot delete your own account.', 'error')
        else:
            user.delete()
            flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('main.admin_users'))
