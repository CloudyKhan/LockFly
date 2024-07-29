#!/bin/bash

echo "Setting up LockFly..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 could not be found. Please install Python 3 to continue."
    exit 1
fi

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Run the application
python lockfly.py

