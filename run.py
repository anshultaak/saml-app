#!/usr/bin/env python3
"""
Entry point for the SSO Flask application.
This file is used for compatibility with docker-compose setups that expect run.py.
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
