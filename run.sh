#!/bin/bash
# Cybersecurity Mentor Chatbot - Setup and Run Script
# Automates virtual environment creation, dependency installation, and server startup
# Production-grade with gunicorn WSGI server and auto-fallback

set -e

CHATBOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$CHATBOT_DIR"

echo "========================================="
echo "  Cybersecurity Mentor Chatbot"
echo "  Setup & Launch Script"
echo "========================================="

# Step 1: Check for Python 3
echo ""
echo "[1/5] Checking for Python 3..."
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 not found. Please install Python 3 first."
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "✅ Python $PYTHON_VERSION found"

# Step 2: Create virtual environment
echo ""
echo "[2/5] Creating virtual environment (.venv)..."
if [ -d "$PROJECT_DIR/.venv" ]; then
    echo "ℹ️  Virtual environment already exists at .venv"
else
    python3 -m venv "$PROJECT_DIR/.venv"
    echo "✅ Virtual environment created"
fi

# Step 3: Activate virtual environment and install requirements
echo ""
echo "[3/5] Installing dependencies..."
source "$PROJECT_DIR/.venv/bin/activate"
pip install --upgrade pip setuptools wheel &>/dev/null

if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    pip install -r "$PROJECT_DIR/requirements.txt"
    echo "✅ Dependencies installed"
else
    echo "❌ requirements.txt not found in $PROJECT_DIR"
    exit 1
fi

# Step 4: Check .env file presence
echo ""
echo "[4/5] Checking .env configuration..."
if [ -f "$PROJECT_DIR/.env" ]; then
    echo "✅ .env file found"
else
    echo "⚠️  .env file not found"
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        echo "  Copying .env.example to .env..."
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        echo "  Please edit .env with your OpenAI/NVIDIA API keys and settings."
    else
        echo "  Creating minimal .env file..."
        echo "OPENAI_API_KEY=your_key_here" > "$PROJECT_DIR/.env"
        echo "  OPENAI_API_KEY=your_key_here" >> "$PROJECT_DIR/.env"
    fi
fi

# Step 5: Start the Flask application with gunicorn + auto-fallback
echo ""
echo "[5/5] Starting Cybersecurity Mentor Chatbot..."
echo "   Application will be available at: http://127.0.0.1:5000"
echo "   Press Ctrl+C to stop the server"
echo "========================================="

# Export FLASK_APP and run
export FLASK_APP="$PROJECT_DIR/app.py"
export FLASK_ENV="${FLASK_ENV:-development}"

# Function to start gunicorn
start_gunicorn() {
    gunicorn --bind 127.0.0.1:5000 --workers 2 --timeout 120 app:app \
        --access-logfile - --error-logfile -
}

# Function to start Flask dev server
start_flask() {
    flask run --host 127.0.0.1 --port 5000
}

# Try gunicorn first, fall back to Flask development server
if command -v gunicorn &>/dev/null; then
    echo "Using gunicorn production server (2 workers, timeout 120s)..."
    if start_gunicorn; then
        echo "✅ Gunicorn started successfully"
    else
        echo "⚠️  Gunicorn failed, falling back to Flask development server..."
        start_flask
    fi
else
    echo "Gunicorn not found, using Flask development server..."
    start_flask
fi
