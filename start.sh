#!/bin/bash

# start.sh — One-click launcher for the Adaptive Triage Engine

# Define paths
PROJECT_ROOT="/home/darsh_run/DS_Final/sentinel_ds"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

# Check if directories exist
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "Error: Project root $PROJECT_ROOT not found."
    exit 1
fi

if [ ! -d "$FRONTEND_DIR" ]; then
    echo "Error: Frontend directory $FRONTEND_DIR not found."
    exit 1
fi

# Function to handle script termination
cleanup() {
    echo -e "\n🛑 Shutting down services..."
    # Kill background jobs
    kill $(jobs -p) 2>/dev/null
    echo "Done."
    exit
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

echo "FastAPI Backend"
cd "$PROJECT_ROOT"
# Start uvicorn in the background
uvicorn api:app --host 0.0.0.0 --port 8000 --reload > backend.log 2>&1 &
BACKEND_PID=$!
echo "   Backend running (PID: $BACKEND_PID). Logs in $PROJECT_ROOT/backend.log"

echo "Frontend"
cd "$FRONTEND_DIR"
# Start vite in the background
npm run dev > frontend.log 2>&1 &
FRONTEND_PID=$!
echo "   Frontend running (PID: $FRONTEND_PID). Logs in $FRONTEND_DIR/frontend.log"

echo "   Dashboard: http://localhost:5173"
echo "   API Base:  http://localhost:8000"
echo ""


# Keep script running to maintain trap intercept
wait
