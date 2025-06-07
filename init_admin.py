#!/usr/bin/env python3
"""
Initialize default admin user for testing
"""
import os
import sys
from werkzeug.security import generate_password_hash
from mongoengine import connect
from src.models import User

def create_admin_user():
    """Create default admin user"""
    mongodb_uri = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/sso')
    connect(host=mongodb_uri)
    
    admin_user = User.objects(username='admin').first()
    if admin_user:
        print("Admin user already exists")
        return
    
    admin_user = User(
        username='admin',
        email='admin@example.com',
        password_hash=generate_password_hash('admin123'),
        is_admin=True,
        active=True
    )
    admin_user.save()
    print("Admin user created successfully: admin/admin123")

if __name__ == '__main__':
    create_admin_user()
