#!/usr/bin/env python
"""
Entry point for the Threat Detection Framework
Run this file to start the application
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app, socketio

if __name__ == '__main__':
    print("Starting Cyber Threat Detection Framework...")
    print("Access the dashboard at http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
