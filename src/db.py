from mongoengine import connect, disconnect
from flask import Flask
import os
import mongomock
from mongoengine.connection import get_connection, DEFAULT_CONNECTION_NAME
from mongoengine.connection import _connection_settings
from werkzeug.security import generate_password_hash
from .models import User

def init_db(app: Flask):
    """Initialize MongoDB connection"""
    try:
        # Log the MongoDB URI being used (without sensitive info)
        mongodb_uri = app.config.get('MONGODB_URI', '')
        if not mongodb_uri:
            app.logger.error("MONGODB_URI is not set in the application configuration")
            raise ValueError("MONGODB_URI is not set")
            
        app.logger.info(f"Initializing MongoDB connection with URI: {mongodb_uri}")
        
        # Clear any existing connection settings
        if DEFAULT_CONNECTION_NAME in _connection_settings:
            app.logger.info("Clearing existing MongoDB connection settings")
            del _connection_settings[DEFAULT_CONNECTION_NAME]
            
        # Disconnect any existing connections
        try:
            disconnect(alias=DEFAULT_CONNECTION_NAME)
            app.logger.info("Disconnected from any existing MongoDB connections")
        except Exception as e:
            app.logger.warning(f"Error disconnecting from MongoDB: {str(e)}")
        
        if app.config.get('TESTING', False):
            app.logger.info("Using mock MongoDB for testing")
            connect(
                db=app.config.get('MONGODB_NAME', 'sso'),
                alias=DEFAULT_CONNECTION_NAME,
                mongo_client_class=mongomock.MongoClient
            )
        else:
            # Connect with the configured URI
            app.logger.info("Connecting to MongoDB...")
            connect(
                host=mongodb_uri,
                alias=DEFAULT_CONNECTION_NAME,
                connect=True,  # Force connection
                serverSelectionTimeoutMS=5000  # 5 second timeout
            )
            
        # Verify connection
        conn = get_connection(alias=DEFAULT_CONNECTION_NAME)
        if conn is None:
            app.logger.error("Failed to get MongoDB connection after connect call")
            raise ConnectionError("Failed to establish MongoDB connection")
            
        # Test the connection by executing a simple command
        conn.admin.command('ping')
        app.logger.info("MongoDB connection established successfully")
        
        # Create admin user if it doesn't exist
        create_default_admin()
        
    except Exception as e:
        app.logger.error(f"Failed to initialize MongoDB connection: {str(e)}")
        raise

def create_default_admin():
    """Create default admin user if no admin exists"""
    # Check if any admin user exists
    admin_exists = User.objects(is_admin=True).first()
    
    if not admin_exists:
        # Create default admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),  # Default password: admin123
            is_admin=True,
            active=True
        )
        admin.save()
        print("Default admin user created with username: 'admin' and password: 'admin123'")

