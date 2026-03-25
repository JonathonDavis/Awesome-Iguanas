#!/bin/bash

# Directory containing the repositories
REPO_DIR="/mnt/disk-2/repos"

# Iterate through each directory in the repo directory
for repo in "$REPO_DIR"/*; do
    if [ -d "$repo" ]; then
        echo "Running linguist on $(basename "$repo"):"
        cd "$repo"
        github-linguist
        echo "-------------------"
    fi
done