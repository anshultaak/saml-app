from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from ..models import ServiceProvider

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Home page"""
    return render_template('main/index.html')

@main_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('main/profile.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing all configured apps"""
    providers = ServiceProvider.objects(active=True).all()
    return render_template('main/dashboard.html', providers=providers)
