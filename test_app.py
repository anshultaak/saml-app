#!/usr/bin/env python3
"""
Test Flask application for SSO login service without MongoDB dependency.
Used for testing admin UI functionality.
"""
import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

mock_users = {
    'admin': {
        'id': '1',
        'username': 'admin',
        'email': 'admin@example.com',
        'password_hash': generate_password_hash('admin123'),
        'is_admin': True,
        'active': True,
        'created_at': datetime(2025, 1, 1)
    }
}

mock_providers = {
    '1': {
        'id': '1',
        'name': 'AWS SSO',
        'provider_type': 'aws',
        'protocol': 'saml',
        'entity_id': 'urn:amazon:webservices',
        'acs_url': 'https://signin.aws.amazon.com/saml',
        'custom_attributes': {'role_arn': 'arn:aws:iam::123456789012:role/SAMLRole'},
        'attribute_mapping': {'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'},
        'active': True,
        'description': 'AWS Single Sign-On',
        'created_at': datetime(2025, 1, 1)
    },
    '2': {
        'id': '2',
        'name': 'Jenkins CI',
        'provider_type': 'jenkins',
        'protocol': 'saml',
        'entity_id': 'jenkins.example.com',
        'acs_url': 'https://jenkins.example.com/securityRealm/finishLogin',
        'custom_attributes': {'groups': ['developers', 'admins']},
        'attribute_mapping': {'username': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'},
        'active': True,
        'description': 'Jenkins CI/CD Server',
        'created_at': datetime(2025, 1, 2)
    }
}

class MockUser(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.is_admin = user_data['is_admin']
        self.active = user_data['active']
        self.created_at = user_data.get('created_at', datetime.now())

def create_test_app():
    """Create and configure the test Flask application."""
    app = Flask(__name__, template_folder='src/templates', static_folder='src/static')
    
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['TESTING'] = True
    
    logging.basicConfig(level=logging.INFO)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        for user_data in mock_users.values():
            if user_data['id'] == user_id:
                return MockUser(user_data)
        return None
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            user_data = mock_users.get(username)
            if user_data and check_password_hash(user_data['password_hash'], password):
                user = MockUser(user_data)
                login_user(user)
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.')
        
        return render_template('auth/login.html', providers=[])
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.')
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('main/dashboard.html')
    
    @app.route('/admin/providers')
    @login_required
    def admin_providers():
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        return render_template('admin/providers.html', providers=list(mock_providers.values()))
    
    @app.route('/admin/providers/new', methods=['GET', 'POST'])
    @login_required
    def admin_provider_new():
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            provider_id = str(len(mock_providers) + 1)
            mock_providers[provider_id] = {
                'id': provider_id,
                'name': request.form.get('name'),
                'provider_type': request.form.get('provider_type'),
                'protocol': request.form.get('protocol', 'saml'),
                'entity_id': request.form.get('entity_id'),
                'acs_url': request.form.get('acs_url'),
                'custom_attributes': {},
                'attribute_mapping': {},
                'active': 'active' in request.form,
                'description': request.form.get('description', ''),
                'created_at': datetime.now()
            }
            flash('Provider created successfully!')
            return redirect(url_for('admin_providers'))
        
        return render_template('admin/provider_form.html', provider=None)
    
    @app.route('/admin/providers/<provider_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_provider_edit(provider_id):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        
        provider = mock_providers.get(provider_id)
        if not provider:
            flash('Provider not found.')
            return redirect(url_for('admin_providers'))
        
        if request.method == 'POST':
            provider.update({
                'name': request.form.get('name'),
                'provider_type': request.form.get('provider_type'),
                'protocol': request.form.get('protocol', 'saml'),
                'entity_id': request.form.get('entity_id'),
                'acs_url': request.form.get('acs_url'),
                'active': 'active' in request.form,
                'description': request.form.get('description', '')
            })
            flash('Provider updated successfully!')
            return redirect(url_for('admin_providers'))
        
        return render_template('admin/provider_form.html', provider=provider)
    
    @app.route('/admin/users')
    @login_required
    def admin_users():
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        return render_template('admin/users.html', users=[MockUser(u) for u in mock_users.values()])
    
    @app.route('/admin/users/new', methods=['GET', 'POST'])
    @login_required
    def admin_user_new():
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            if username in mock_users:
                flash('Username already exists.')
                return render_template('admin/user_form.html', user=None)
            
            user_id = str(len(mock_users) + 1)
            mock_users[username] = {
                'id': user_id,
                'username': username,
                'email': request.form.get('email'),
                'password_hash': generate_password_hash(request.form.get('password')),
                'is_admin': 'is_admin' in request.form,
                'active': 'active' in request.form,
                'created_at': datetime.now()
            }
            flash('User created successfully!')
            return redirect(url_for('admin_users'))
        
        return render_template('admin/user_form.html', user=None)
    
    @app.route('/admin/users/<user_id>/edit', methods=['GET', 'POST'])
    @login_required
    def admin_user_edit(user_id):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        
        user_data = None
        for u in mock_users.values():
            if u['id'] == user_id:
                user_data = u
                break
        
        if not user_data:
            flash('User not found.')
            return redirect(url_for('admin_users'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            if password:
                user_data['password_hash'] = generate_password_hash(password)
            
            user_data.update({
                'email': request.form.get('email'),
                'is_admin': 'is_admin' in request.form,
                'active': 'active' in request.form
            })
            flash('User updated successfully!')
            return redirect(url_for('admin_users'))
        
        return render_template('admin/user_form.html', user=MockUser(user_data))
    
    return app

if __name__ == '__main__':
    app = create_test_app()
    app.run(debug=True, host='0.0.0.0', port=5001)
