#!/bin/bash

# ============================================
# Threat Detection Framework Setup Script
# ============================================

set -e

echo "🚀 Threat Detection Framework Setup"
echo "===================================="

# Check Python version
echo "✓ Checking Python version..."
python_version=$(python3 --version | cut -d ' ' -f 2)
echo "  Python version: $python_version"

# Create virtual environment
echo "✓ Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "✓ Installing dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Create necessary directories
echo "✓ Creating directories..."
mkdir -p logs
mkdir -p data
mkdir -p models

# Copy environment file
if [ ! -f .env ]; then
    echo "✓ Creating .env file from template..."
    cp .env.example .env
    echo "  ⚠️  Please edit .env with your configuration"
fi

# Initialize database
echo "✓ Initializing database..."
python3 -c "
from backend.app import app, db
from backend.database.models import Threat, Alert, SystemMetrics, NetworkFlow, IncidentResponse

with app.app_context():
    db.create_all()
    print('  ✓ Database tables created')
"

# Create initial admin user (optional)
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Run: python backend/app.py"
echo "3. Access dashboard at: http://localhost:5000"
echo ""
echo "For production deployment, see README.md"
