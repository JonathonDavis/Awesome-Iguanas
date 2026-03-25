#!/bin/bash

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Virtual environment Python (override via env var if desired)
VENV_PYTHON="${VENV_PYTHON:-"${PROJECT_DIR}/python_venvs/osv_env/bin/python3"}"

# Logging
LOG_DIR="${LOG_DIR:-"${PROJECT_DIR}/logs"}"
LOG_FILE="${LOG_DIR}/osv_update_$(date +\%Y-\%m-\%d).log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Change to the script directory
cd "$SCRIPT_DIR"

# Timestamp for logging
echo "OSV Update started at $(date)" >> "$LOG_FILE"

# Run the OSV update script first
"$VENV_PYTHON" osv.py >> "$LOG_FILE" 2>&1

# Then run the tracking timestamp update script
"$VENV_PYTHON" update_tracking_timestamp.py >> "$LOG_FILE" 2>&1

# Log completion
echo "OSV Update completed at $(date)" >> "$LOG_FILE"