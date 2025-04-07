#!/bin/bash

# Set the path to your Python scripts and virtual environment
SCRIPT_DIR="/mnt/disk-2"
VENV_PYTHON="/mnt/disk-2/python_venvs/osv_env/bin/python3"

# Logging
LOG_FILE="/mnt/disk-2/logs/osv_update_$(date +\%Y-\%m-\%d).log"

# Ensure log directory exists
mkdir -p /mnt/disk-2/logs

# Change to the script directory
cd "$SCRIPT_DIR"

# Timestamp for logging
echo "OSV Update started at $(date)" >> "$LOG_FILE"

# Run the OSV update script first
"$VENV_PYTHON" incrementOSV3.py >> "$LOG_FILE" 2>&1

# Then run the tracking timestamp update script
"$VENV_PYTHON" update_tracking_timestamp.py >> "$LOG_FILE" 2>&1

# Log completion
echo "OSV Update completed at $(date)" >> "$LOG_FILE"