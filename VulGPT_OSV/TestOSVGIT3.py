#!/usr/bin/env python3
import os
import re
import json
import gc
import zipfile
import io
import requests
import shutil
import datetime
import signal
import time
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from neo4j import GraphDatabase
from collections import defaultdict
from ortools.sat.python import cp_model
from urllib.parse import urlparse

# -------------------------
# CONFIGURATION
# -------------------------
NEO4J_URI = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "jaguarai"
OSV_ZIP_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
BATCH_SIZE = 100
PROCESSING_BATCH_SIZE = 100
MAX_WORKERS = 8
MAX_RECORDS_PER_RUN = 1000  # Process this many records per run
REPO_BASE_DIR = "repos"
LINGUIST_CMD = "github-linguist"  # Requires linguist installed
KEEP_REPOS = True  # Always keep repositories for continuous updates
CHECKPOINT_FILE = "osv_checkpoint.json"
REPOSITORY_PROGRESS_FILE = "repo_progress.json"
CONTINUE_FROM_CHECKPOINT = True  # Set to True to continue from last run
OSV_ZIP_CACHE = "osv_all.zip"  # Cache the downloaded zip file
STARTING_REPO_BATCH_SIZE = 50  # Increased from 5 to 50
MAX_REPO_BATCH_SIZE = 100  # Increased from 20 to 100
REPO_BATCH_SIZE_INCREMENT = 5  # Increased from 1 to 5

# GitHub token from environment or set directly
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')  # Replace with your token


# -------------------------
# EXCEPTION HANDLING
# -------------------------
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    """
    Handler for SIGALRM signal.

    Raises a TimeoutException when a signal is received, indicating that an
    operation has timed out.

    :param signum: The signal number.
    :param frame: The current stack frame.
    :raises TimeoutException: Always raised when a signal is received.
    """
    raise TimeoutException("Operation timed out")

# -------------------------
# DATABASE CONNECTION
# -------------------------
def test_neo4j_connection() -> bool:
    """
    Test connection to Neo4j database.

    Tests that we can connect to the Neo4j database using the provided
    connection URI and credentials.

    Returns:
        True if the connection is successful, False otherwise.
    """
    # Create a driver for the Neo4j connection
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    try:
        # Create a session to test the connection
        with driver.session() as session:
            # Run a simple query to test the connection
            result = session.run("RETURN 'Connected' as status")
            # Get the result of the query
            record = result.single()
            # Check if the connection was successful
            if record and record["status"] == "Connected":
                print("Successfully connected to Neo4j database")
                return True
            else:
                print("Could not verify Neo4j connection")
                return False
    except Exception as e:
        # Handle any exceptions that occur while trying to connect
        print(f"Error connecting to Neo4j database: {e}")
        return False

# -------------------------
# CHECKPOINT FUNCTIONS
# -------------------------
def save_checkpoint(processed_files, last_vulnerability_id=None):
    """
    Save checkpoint of processed files and last vulnerability ID.

    Saves a checkpoint file with the processed files and last vulnerability ID.
    This allows the script to continue from the last processed file if interrupted.
    """
    # Create a dictionary to store the checkpoint data
    checkpoint = {
        "processed_files": list(processed_files),  # List of processed files
        "last_vulnerability_id": last_vulnerability_id,  # Last processed vulnerability ID
        "timestamp": datetime.datetime.now().isoformat()  # Timestamp of the checkpoint
    }

    # Save the checkpoint to a file
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(checkpoint, f)

    print(f"Checkpoint saved: {len(processed_files)} files processed")

def load_checkpoint():
    """
    Load checkpoint if it exists.

    If the checkpoint file exists and the `CONTINUE_FROM_CHECKPOINT` flag is set,
    load the checkpoint and return the set of processed files and the last
    processed vulnerability ID.

    Returns:
        A tuple containing the set of processed files and the last processed
        vulnerability ID, or a tuple of an empty set and None if the checkpoint
        does not exist.
    """
    # Check if the checkpoint file exists and the flag is set
    if os.path.exists(CHECKPOINT_FILE) and CONTINUE_FROM_CHECKPOINT:
        try:
            # Load the checkpoint from the file
            with open(CHECKPOINT_FILE, 'r') as f:
                checkpoint = json.load(f)
            # Print a message indicating that the checkpoint was loaded
            print(f"Loaded checkpoint from {checkpoint.get('timestamp')}")
            # Return the set of processed files and the last processed vulnerability ID
            return set(checkpoint.get("processed_files", [])), checkpoint.get("last_vulnerability_id")
        except Exception as e:
            # Handle any exceptions that occur while loading the checkpoint
            print(f"Error loading checkpoint: {e}")

    # Return an empty set and None if the checkpoint does not exist
    return set(), None

def save_repository_progress(processed_repos, current_batch_size=None):
    """
    Save progress of processed repositories.

    Saves the list of processed repositories and the current batch size to a file.
    This allows the script to continue from the last processed repository if interrupted.

    Args:
        processed_repos (set): Set of processed repository URLs.
        current_batch_size (int, optional): The current batch size to save. Defaults to None.
    """
    if current_batch_size is None:
        current_batch_size = STARTING_REPO_BATCH_SIZE

    progress = {
        "processed_repos": list(processed_repos),  # List of processed repository URLs
        "current_batch_size": current_batch_size,  # Current batch size
        "timestamp": datetime.datetime.now().isoformat()  # Timestamp of the progress
    }

    # Save the progress to a file
    with open(REPOSITORY_PROGRESS_FILE, 'w') as f:
        json.dump(progress, f)

    # Print a message indicating that the progress was saved
    print(f"Repository progress saved: {len(processed_repos)} repositories processed")

def load_repository_progress():
    """
    Load repository progress if exists.

    If the repository progress file exists and the `CONTINUE_FROM_CHECKPOINT` flag
    is set, load the repository progress and return the set of processed
    repository URLs and the next batch size.

    The batch size is increased by `REPO_BATCH_SIZE_INCREMENT` for the next
    run, up to a maximum of `MAX_REPO_BATCH_SIZE`.

    If the file does not exist or the flag is not set, return an empty set and
    the starting batch size.

    Returns:
        A tuple containing the set of processed repository URLs and the next
        batch size.
    """
    if os.path.exists(REPOSITORY_PROGRESS_FILE) and CONTINUE_FROM_CHECKPOINT:
        try:
            # Load the progress from the file
            with open(REPOSITORY_PROGRESS_FILE, 'r') as f:
                progress = json.load(f)
            # Print a message indicating that the progress was loaded
            print(f"Loaded repository progress from {progress.get('timestamp')}")
            # Get the current batch size from the progress
            batch_size = progress.get("current_batch_size", STARTING_REPO_BATCH_SIZE)
            # Increase batch size for next run
            next_batch_size = min(batch_size + REPO_BATCH_SIZE_INCREMENT, MAX_REPO_BATCH_SIZE)
            # Return the set of processed repository URLs and the next batch size
            return set(progress.get("processed_repos", [])), next_batch_size
        except Exception as e:
            # Handle any exceptions that occur while loading the progress
            print(f"Error loading repository progress: {e}")

    # Return an empty set and the starting batch size if the file does not exist
    return set(), STARTING_REPO_BATCH_SIZE

# -------------------------
# SETUP FUNCTIONS
# -------------------------
def setup_git_ssh():
    """
    Configure git to automatically accept SSH host keys.

    This is necessary because the script may encounter new SSH host keys
    when cloning repositories. By automatically accepting them, the script
    can continue to run without interruption.

    The environment variable `GIT_SSH_COMMAND` is set to a command that
    tells SSH to not prompt the user about new host keys.
    """
    # Use StrictHostKeyChecking=no to automatically accept new host keys
    # and UserKnownHostsFile=/dev/null to not store the host keys
    git_ssh_cmd = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    os.environ['GIT_SSH_COMMAND'] = git_ssh_cmd

# -------------------------
# OSV DOWNLOAD & PROCESSING
# -------------------------
def download_osv_all_zip(url):
    """
    Downloads the OSV 'all vulnerabilities' zip file from the given URL.

    Args:
        url (str): The URL to download the zip file from.

    Returns:
        BytesIO: A BytesIO object containing the downloaded zip file content.
    """
    print(f"Downloading OSV data from {url} ...")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    # Get content length for progress bar if available
    total_size = int(response.headers.get('content-length', 0))

    # Setup progress bar with the total size of the download
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading")

    # Create a BytesIO object to store the downloaded content
    content = io.BytesIO()

    # Download the file in chunks and update the progress bar
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            progress_bar.update(len(chunk))
            content.write(chunk)

    # Close the progress bar after download is complete
    progress_bar.close()

    # Reset the content position to the beginning
    content.seek(0)
    print("Download complete!")
    return content

def process_vulnerabilities(zip_bytes, max_records=MAX_RECORDS_PER_RUN):
    """
    Opens the provided ZIP and extracts vulnerability records incrementally.
    Uses checkpoints to continue from last run.

    Args:
        zip_bytes (BytesIO): The BytesIO object containing the downloaded zip file content.
        max_records (int, optional): The maximum number of vulnerability records to process at once.
            Defaults to MAX_RECORDS_PER_RUN.

    Returns:
        List of processed vulnerability records.
    """
    vulnerabilities = []
    processed_files, _ = load_checkpoint()
    new_processed_files = processed_files.copy()

    def process_file(file):
        """
        Process a single file from the ZIP archive.

        Args:
            file (str): The name of the file to process.

        Returns:
            dict or None: The JSON content of the file as a dictionary, or None if an error occurs.
        """
        try:
            # Open the file within the ZIP archive
            with zf.open(file) as f:
                # Load and return the JSON content
                return json.load(f)
        except Exception as e:
            # Print an error message if any exception occurs
            print(f"\nError processing file {file}: {e}")
            return None

    with zipfile.ZipFile(zip_bytes, 'r') as zf:
        file_list = zf.namelist()
        total_files = len(file_list)
        print(f"Found {total_files} files in the archive.")

        # Find unprocessed files
        unprocessed_files = [f for f in file_list if f not in processed_files]
        files_to_process = unprocessed_files[:max_records]

        print(f"Processing {len(files_to_process)} new files out of {len(unprocessed_files)} unprocessed files")

        # Process files in batches using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            with tqdm(total=len(files_to_process), desc="Processing files", unit="files") as pbar:
                for batch_start in range(0, len(files_to_process), PROCESSING_BATCH_SIZE):
                    batch_files = files_to_process[batch_start:batch_start + PROCESSING_BATCH_SIZE]
                    results = list(executor.map(process_file, batch_files))

                    # Only add successful results to vulnerabilities
                    valid_results = list(filter(None, results))
                    vulnerabilities.extend(valid_results)

                    # Update processed files
                    new_processed_files.update(batch_files)

                    # Save checkpoint periodically
                    if len(new_processed_files) % (PROCESSING_BATCH_SIZE * 5) == 0:
                        save_checkpoint(new_processed_files)

                    pbar.update(len(batch_files))
                    del results
                    gc.collect()

    # Save final checkpoint
    last_vuln_id = vulnerabilities[-1].get("id") if vulnerabilities else None
    save_checkpoint(new_processed_files, last_vuln_id)

    print(f"Processed {len(vulnerabilities)} new vulnerability records")
    return vulnerabilities

def greedy_minimum_version_set(vulnerabilities):
    """
    Uses a fast greedy approach to find a near-optimal minimum version set.
    Returns both the filtered vulnerabilities and the selected versions.

    Args:
        vulnerabilities (list): List of vulnerability records.

    Returns:
        tuple: A tuple containing the filtered vulnerabilities and the selected versions.
    """
    print("Using greedy algorithm for minimum version set...")

    # First pass: extract all versions and their associated vulnerabilities
    version_to_vulns = defaultdict(set)
    version_dates = {}

    print("Extracting version information from vulnerabilities...")
    for vuln_idx, vuln in tqdm(enumerate(vulnerabilities), total=len(vulnerabilities),
                             desc="Mapping versions", unit="vulns"):
        vuln_id = vuln.get("id")
        affected = vuln.get("affected", [])

        if not vuln_id or not affected:
            continue

        for affected_package in affected:
            versions = affected_package.get("versions", [])
            if not versions:
                # If no explicit versions, try to extract from ranges
                ranges = affected_package.get("ranges", [])
                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        # Extract version from 'introduced' or 'fixed' event
                        version = event.get("introduced", event.get("fixed", ""))
                        if version:
                            versions.append(version)
                            # Try to get the date from 'introduced_at' or 'fixed_at'
                            date_str = event.get("introduced_at", event.get("fixed_at", ""))
                            if date_str:
                                try:
                                    date_obj = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                                    version_dates[version] = date_obj
                                except ValueError:
                                    pass

            # Add each version to the mapping
            for version in versions:
                version_to_vulns[version].add(vuln_id)

    print(f"Found {len(version_to_vulns)} unique versions across {len(vulnerabilities)} vulnerabilities")

    if not version_to_vulns:
        print("No version information found in vulnerabilities.")
        return [], set()

    # Greedy algorithm - iteratively select version covering most uncovered vulnerabilities
    print("Starting greedy selection algorithm...")
    selected_versions = []
    uncovered_vulns = set()

    # Create set of all vulnerability IDs
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id")
        if vuln_id:
            uncovered_vulns.add(vuln_id)

    total_vulns = len(uncovered_vulns)
    print(f"Total vulnerabilities to cover: {total_vulns}")

    with tqdm(total=total_vulns, desc="Selecting versions") as pbar:
        while uncovered_vulns:
            # Find version that covers most uncovered vulnerabilities
            best_version = None
            best_coverage = 0

            for version, vulns in version_to_vulns.items():
                coverage = len(vulns.intersection(uncovered_vulns))
                if coverage > best_coverage:
                    best_version = version
                    best_coverage = coverage
                # If tied, prefer version with newer date
                elif coverage == best_coverage and best_version is not None:
                    best_date = version_dates.get(best_version, datetime.datetime.min)
                    current_date = version_dates.get(version, datetime.datetime.min)
                    if current_date > best_date:  # Prefer newer date
                        best_version = version
                        best_coverage = coverage

            if best_version is None or best_coverage == 0:
                print(f"Warning: Cannot cover all vulnerabilities. {len(uncovered_vulns)} remain uncovered.")
                break

            # Add best version to selected set
            selected_versions.append(best_version)
            newly_covered = version_to_vulns[best_version].intersection(uncovered_vulns)
            uncovered_vulns -= newly_covered
            pbar.update(len(newly_covered))

    # Filter vulnerabilities to only include those covered by selected versions
    covered_vuln_ids = set()
    for version in selected_versions:
        covered_vuln_ids.update(version_to_vulns[version])

    print("Filtering vulnerabilities...")
    result_vulns = []
    for vuln in tqdm(vulnerabilities, desc="Filtering vulnerabilities", unit="vulns"):
        if vuln.get("id") in covered_vuln_ids:
            result_vulns.append(vuln)

    print(f"Greedy algorithm selected {len(selected_versions)} versions covering {len(covered_vuln_ids)} vulnerabilities")
    print(f"Final result: {len(result_vulns)} vulnerabilities")

    return result_vulns, selected_versions

# -------------------------
# REPOSITORY FUNCTIONS
# -------------------------
def extract_repo_info(vuln):
    """
    Extracts and cleans repository URLs from a vulnerability record.

    Args:
        vuln (dict): A dictionary representing vulnerability data, potentially
                     containing affected packages, references, and other fields.

    Returns:
        list: A list of cleaned, unique GitHub repository URLs extracted from
              the vulnerability data.
    """
    repos = set()

    # Debug counter for repository discovery
    if not hasattr(extract_repo_info, 'repos_found'):
        extract_repo_info.repos_found = 0

    def clean_github_url(url):
        """
        Cleans and standardizes GitHub URLs.

        Args:
            url (str): The URL to clean.

        Returns:
            str or None: The cleaned GitHub repository URL, or None if the URL
                         is invalid or not from GitHub.
        """
        if not url or not isinstance(url, str):
            return None

        # Skip non-GitHub URLs
        if "github.com" not in url:
            return None

        # Remove specific file/blob/advisory paths and fragments
        url = url.split('/blob/')[0]
        url = url.split('/tree/')[0]
        url = url.split('/commit/')[0]
        url = url.split('/security/advisories/')[0]
        url = url.split('/releases')[0]
        url = url.split('#')[0]

        # Ensure base repository URL
        if url.startswith('https://github.com/'):
            parts = url.replace('https://github.com/', '').split('/')
            if len(parts) >= 2:
                # Debugging print statement
                clean_url = f"https://github.com/{parts[0]}/{parts[1]}"
                extract_repo_info.repos_found += 1
                if extract_repo_info.repos_found % 10 == 0:
                    print(f"Found repository: {clean_url}")
                return clean_url
        return None

    # Check package information for all ecosystems
    def is_github_url(url: str) -> bool:
        """
        Return True if the given URL clearly points to github.com.
        """
        if not url:
            return False
        parsed = urlparse(url)
        # If no scheme is present, try parsing again assuming https.
        if not parsed.scheme:
            parsed = urlparse("https://" + url)
        host = parsed.hostname or ""
        return host.lower() in ("github.com", "www.github.com")

    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        pkg_name = package.get("name", "")
        ecosystem = package.get("ecosystem", "")

        # Process Go ecosystem packages
        if ecosystem == "Go" and pkg_name:
            parts = pkg_name.split("/")
            if len(parts) >= 3 and parts[0] == "github.com":
                repos.add(f"https://github.com/{parts[1]}/{parts[2]}")
            elif "/" in pkg_name and not pkg_name.startswith("http"):
                repos.add(f"https://github.com/{pkg_name}")

        # Process NPM packages
        elif ecosystem == "npm" and pkg_name:
            common_npm_repos = {
                "react": "https://github.com/facebook/react",
                "angular": "https://github.com/angular/angular",
                "vue": "https://github.com/vuejs/vue",
                "lodash": "https://github.com/lodash/lodash",
                "express": "https://github.com/expressjs/express",
                "jquery": "https://github.com/jquery/jquery",
                "moment": "https://github.com/moment/moment",
                "axios": "https://github.com/axios/axios"
            }
            if pkg_name in common_npm_repos:
                repos.add(common_npm_repos[pkg_name])

            # Find GitHub repo from references
            for ref in vuln.get("references", []):
                url = ref.get("url", "")
                if is_github_url(url) and pkg_name.lower() in url.lower():
                    clean_url = clean_github_url(url)
                    if clean_url:
                        repos.add(clean_url)

        # Process Python packages
        elif ecosystem == "PyPI" and pkg_name:
            common_pypi_repos = {
                "django": "https://github.com/django/django",
                "flask": "https://github.com/pallets/flask",
                "requests": "https://github.com/psf/requests",
                "numpy": "https://github.com/numpy/numpy",
                "pandas": "https://github.com/pandas-dev/pandas",
                "tensorflow": "https://github.com/tensorflow/tensorflow"
            }
            if pkg_name in common_pypi_repos:
                repos.add(common_pypi_repos[pkg_name])

        # Check Package URL (PURL)
        purl = package.get("purl", "")
        if is_github_url(purl):
            clean_url = clean_github_url(purl)
            if clean_url:
                repos.add(clean_url)

    # Check all references for GitHub URLs
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        if url and "github.com" in url:
            clean_url = clean_github_url(url)
            if clean_url:
                repos.add(clean_url)

    # Check database_specific information
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        ghsa_url = db_specific.get("github_repo")
        if ghsa_url:
            clean_url = clean_github_url(ghsa_url)
            if clean_url:
                repos.add(clean_url)

        # Check all string fields
        for key, value in db_specific.items():
            if isinstance(value, str) and "github.com" in value:
                clean_url = clean_github_url(value)
                if clean_url:
                    repos.add(clean_url)

    # Check details and summary fields for URLs
    details = vuln.get("details", "")
    if details and isinstance(details, str):
        urls = re.findall(r'https?://github\.com/[a-zA-Z0-9\-_\.]+/[a-zA-Z0-9\-_\.]+', details)
        for url in urls:
            clean_url = clean_github_url(url)
            if clean_url:
                repos.add(clean_url)

    summary = vuln.get("summary", "")
    if summary and isinstance(summary, str):
        urls = re.findall(r'https?://github\.com/[a-zA-Z0-9\-_\.]+/[a-zA-Z0-9\-_\.]+', summary)
        for url in urls:
            clean_url = clean_github_url(url)
            if clean_url:
                repos.add(clean_url)

    # Validate and return the list of unique repository URLs
    valid_repos = []
    for repo in repos:
        parts = repo.replace("https://github.com/", "").split("/")
        if len(parts) == 2 and all(parts):
            valid_repos.append(repo)

    return valid_repos
def safe_clone_repository(repo_url, base_dir=REPO_BASE_DIR, max_retries=3):
    """
    Clone a GitHub repository to a local directory with retries and authentication.

    This function attempts to clone a GitHub repository to a specified local directory.
    It checks if the repository already exists locally and tries to update it if possible.
    If cloning fails, it retries using different strategies, including using a GitHub token
    for authentication and switching from HTTPS to SSH.

    Args:
        repo_url (str): The URL of the repository to clone.
        base_dir (str): The base directory to clone the repository into.
        max_retries (int): The maximum number of retry attempts for cloning.

    Returns:
        str: The local path to the cloned repository, or None if cloning fails.
    """
    # Sanitize repository name for local path
    repo_name = repo_url.replace('https://github.com/', '').replace('/', '_')
    repo_path = os.path.join(base_dir, repo_name)

    # Check if repository already exists locally
    if os.path.exists(repo_path):
        print(f"Repository already exists locally: {repo_path}")

        # Try to update the existing repository
        try:
            print(f"Updating existing repository: {repo_url}")
            subprocess.run(
                ["git", "-C", repo_path, "fetch", "--depth", "1"],
                check=True, capture_output=True, text=True
            )
            return repo_path
        except subprocess.CalledProcessError as e:
            print(f"Error updating repository {repo_url}: {e}")
            # If update fails, try to remove and re-clone
            try:
                shutil.rmtree(repo_path)
                print(f"Removed problematic repository: {repo_path}")
            except Exception as rm_error:
                print(f"Error removing repository directory: {rm_error}")
                return None

    # Add GitHub token to URL if it's a GitHub repository and token is available
    authenticated_url = repo_url
    if 'github.com' in repo_url and GITHUB_TOKEN and not repo_url.startswith('git@'):
        authenticated_url = repo_url.replace('https://github.com/', f'https://{GITHUB_TOKEN}@github.com/')

    # Attempt to clone the repository with retry strategies
    for attempt in range(max_retries):
        try:
            # Strategy 1: Shallow clone with depth 1
            print(f"Cloning repository: {repo_url} (attempt {attempt+1})...")
            subprocess.run([
                "git", "clone",
                "--depth", "1",  # Shallow clone
                "--single-branch",  # Single branch
                authenticated_url,
                repo_path
            ], check=True, capture_output=True, text=True)
            print(f"Successfully cloned {repo_url}")
            return repo_path

        except subprocess.CalledProcessError as e:
            print(f"Clone attempt {attempt + 1} failed for {repo_url}: {e}")

            # Remove partial/failed clone directory
            if os.path.exists(repo_path):
                try:
                    shutil.rmtree(repo_path)
                except Exception as cleanup_error:
                    print(f"Error cleaning up repository directory: {cleanup_error}")
                    pass

            # Alternative strategies for the first attempt
            if attempt == 0:
                # Try converting HTTPS URL to SSH
                ssh_url = repo_url.replace('https://github.com/', 'git@github.com:')
                try:
                    print(f"Trying SSH URL: {ssh_url}")
                    subprocess.run([
                        "git", "clone",
                        ssh_url,
                        repo_path
                    ], check=True, capture_output=True, text=True)
                    print(f"Successfully cloned {ssh_url} using SSH")
                    return repo_path
                except subprocess.CalledProcessError as ssh_error:
                    print(f"SSH clone failed: {ssh_error}")
                    pass

            # Add a delay before retry to avoid rate limiting
            time.sleep(2)

    print(f"Failed to clone repository: {repo_url} after {max_retries} attempts")
    return None

def safe_checkout_version(repo_path, version):
    """
    Safely checkout a specific version in the repository.

    Args:
        repo_path (str): Path to the repository.
        version (str): Version to checkout.

    Returns:
        bool: Whether the checkout was successful.
    """
    try:
        # Attempt to checkout the specified version
        print(f"Checking out version {version}...")
        subprocess.run(
            ["git", "-C", repo_path, "checkout", version],
            check=True, capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        print(f"Could not checkout version {version} for repository at {repo_path}")

        # Attempt to find and checkout the default branch
        try:
            # Get the default branch from the remote origin
            default_branch = subprocess.check_output(
                ["git", "-C", repo_path, "symbolic-ref", "refs/remotes/origin/HEAD"],
                text=True
            ).strip().split('/')[-1]  # Extract branch name

            # Checkout the default branch
            print(f"Falling back to default branch: {default_branch}")
            subprocess.run(
                ["git", "-C", repo_path, "checkout", default_branch],
                check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            print(f"Failed to checkout default branch for repository at {repo_path}")
            return False

def get_valid_repository_versions(repo_path):
    """
    Retrieve all valid tags and branches for a repository.

    Args:
        repo_path (str): Path to the local repository.

    Returns:
        list: A list of unique tags and branch names.
    """
    try:
        # Get all tags in the repository
        tags_output = subprocess.check_output(
            ["git", "-C", repo_path, "tag"],
            stderr=subprocess.PIPE,
            text=True
        ).strip().split('\n')

        # Get all remote branches in the repository
        branches_output = subprocess.check_output(
            ["git", "-C", repo_path, "branch", "-r"],
            stderr=subprocess.PIPE,
            text=True
        ).strip().split('\n')

        # Use a set to collect unique version names
        versions = set()

        # Process and add tags to the versions set
        for tag in tags_output:
            tag = tag.strip()
            if tag:  # Ensure the tag is not empty
                versions.add(tag)

        # Process and add branches to the versions set
        for branch in branches_output:
            branch = branch.strip().replace('origin/', '')  # Remove remote prefix
            if branch and branch not in ['HEAD', '']:  # Filter out unwanted branches
                versions.add(branch)

        # Convert the set to a list before returning
        return list(versions)
    except subprocess.CalledProcessError as e:
        # Handle errors during the subprocess execution
        print(f"Error getting versions: {e}")
        return []

def find_closest_version(available_versions, target_versions):
    """
    Find the closest matching versions from available versions based on target versions.

    Args:
        available_versions (list): List of available version strings.
        target_versions (list): List of target version strings.

    Returns:
        list: List of closest matching version strings.
    """
    def version_key(v):
        """
        Create a sortable key for version comparison. Handles various version formats.

        Args:
            v (str): Version string.

        Returns:
            tuple: A tuple representing the version in numeric parts.
        """
        # Remove 'v' prefix if present
        v = v.lstrip('v')

        # Split version into numeric components
        parts = v.split('.')

        # Convert to numeric parts, using 0 for non-numeric parts
        numeric_parts = []
        for part in parts:
            try:
                numeric_parts.append(int(part))
            except ValueError:
                # If part is not fully numeric, try to extract numeric prefix
                numeric_match = re.match(r'^(\d+)', part)
                if numeric_match:
                    numeric_parts.append(int(numeric_match.group(1)))
                else:
                    numeric_parts.append(0)

        # Pad with zeros to ensure consistent comparison
        return tuple(numeric_parts + [0] * (5 - len(numeric_parts)))

    # If no specific target versions, return a subset of available versions
    if not target_versions:
        return available_versions[:5]  # Limit to 5 versions if no targets specified

    # Filter and map versions
    matched_versions = []
    for target in target_versions:
        # Try exact match first
        if target in available_versions:
            matched_versions.append(target)
            continue

        # If exact match fails, find the closest version
        sorted_versions = sorted(available_versions, key=version_key)

        # Find version closest to the target
        if sorted_versions:
            closest = min(sorted_versions, key=lambda x: abs(version_key(x)[0] - version_key(target)[0]))
            matched_versions.append(closest)

    return list(set(matched_versions))

def run_linguist(repo_path):
    """
    Run GitHub Linguist on a repository and parse the output properly.

    Returns a dictionary of language names to percentage values.

    :param repo_path: Path to the local repository.
    :type repo_path: str
    :return: Dictionary of language names to percentage values.
    :rtype: dict
    """
    try:
        # Run GitHub Linguist with breakdown option
        print(f"Running Linguist on {repo_path}...")
        result = subprocess.run(
            [LINGUIST_CMD, "--breakdown", repo_path],
            capture_output=True,
            text=True,
            check=True
        )

        # Parse output into a dictionary
        languages = {}
        for line in result.stdout.strip().split("\n"):
            # Match pattern: "73.21% 23813410 PHP"
            match = re.search(r"([\d\.]+)%\s+(\d+)\s+([\w\+\#\.]+(?:\s[\w\+\#\.]+)*)", line)
            if match:
                # Extract percentage, bytes count, and language name
                percentage = float(match.group(1))
                bytes_count = int(match.group(2))
                language = match.group(3).strip()
                languages[language] = percentage

        print(f"Linguist detected languages: {languages}")
        return languages
    except subprocess.CalledProcessError as e:
        # If Linguist fails, manually detect languages
        print(f"Error running Linguist: {e}")
        return manual_language_detection(repo_path)
    except Exception as e:
        # Handle any other exceptions
        print(f"General error during language detection: {e}")
        return {}

def manual_language_detection(repo_path):
    """
    Manual language detection as a fallback.

    This function counts the number of files by extension to determine the language
    distribution of the repository. The result is a dictionary of language names to
    percentage values.
    """
    language_stats = {}
    total_files = 0

    # Mapping of language names to file extensions
    language_extensions = {
        'Python': ['.py'],
        'JavaScript': ['.js', '.jsx'],
        'Ruby': ['.rb'],
        'Java': ['.java'],
        'C++': ['.cpp', '.cxx', '.cc', '.hpp'],
        'C': ['.c', '.h'],
        'Go': ['.go'],
        'Rust': ['.rs'],
        'TypeScript': ['.ts', '.tsx'],
        'PHP': ['.php'],
        'C#': ['.cs'],
        'HTML': ['.html', '.htm'],
        'CSS': ['.css'],
        'Shell': ['.sh', '.bash'],
        'SQL': ['.sql'],
        'Swift': ['.swift'],
        'Kotlin': ['.kt', '.kts']
    }

    # Iterate through all files in the repository
    for root, _, files in os.walk(repo_path):
        for file in files:
            # Get the file extension in lowercase
            ext = os.path.splitext(file)[1].lower()
            # Increment the total file count
            total_files += 1

            # Loop through the language extensions
            for lang, extensions in language_extensions.items():
                # If the file extension matches the language extension, increment the count
                if ext in extensions:
                    language_stats[lang] = language_stats.get(lang, 0) + 1

    # Convert the counts to percentage output similar to linguist
    if total_files > 0:
        for lang in language_stats:
            # Round to two decimal places
            language_stats[lang] = round((language_stats[lang] / total_files * 100), 2)

    print(f"Manual language detection result: {language_stats}")
    return language_stats

def analyze_repository(repo_url, versions, timeout=300):
    """
    Analyze the specified repository and its versions for language composition
    using GitHub Linguist, while checking Neo4j to avoid duplicate analysis.

    Args:
        repo_url (str): The URL of the repository to analyze.
        versions (list): List of version strings to analyze.
        timeout (int): Timeout in seconds for the analysis process.

    Returns:
        list: A list of dictionaries containing version, size, and languages data.
    """
    # Establish Neo4j connection to check already analyzed versions
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    already_analyzed = set()

    # Query Neo4j for versions already analyzed
    with driver.session() as session:
        result = session.run(
            """
            MATCH (r:Repository {url: $url})-[:HAS_VERSION]->(v:Version)
            RETURN v.version as version
            """,
            url=repo_url
        )
        for record in result:
            already_analyzed.add(record["version"])

    # Determine versions that need analysis
    versions_to_analyze = [v for v in versions if v not in already_analyzed]
    if not versions_to_analyze:
        print(f"All versions for {repo_url} have already been analyzed")
        return []

    print(f"Analyzing {len(versions_to_analyze)} new versions for {repo_url}")

    # Clean and validate repository URL
    cleaned_repos = extract_repo_info({"references": [{"url": repo_url}]})
    if not cleaned_repos:
        print(f"Invalid repository URL: {repo_url}")
        return []

    repo_url = cleaned_repos[0]

    # Clone the repository safely
    repo_path = safe_clone_repository(repo_url)
    if not repo_path:
        return []

    results = []
    start_time = time.time()

    try:
        # Retrieve all valid versions from the repository
        available_versions = get_valid_repository_versions(repo_path)
        if not available_versions:
            print(f"No valid versions found for repository: {repo_url}")
            return []

        # Find closest matching versions to analyze
        matched_versions = find_closest_version(available_versions, versions_to_analyze)
        print(f"Found {len(matched_versions)} matching versions for {repo_url}: {matched_versions}")

        for version in matched_versions:
            # Check if approaching timeout
            if time.time() - start_time > timeout * 0.8:  # 80% of timeout reached
                print(f"Warning: Approaching timeout for {repo_url}, skipping remaining versions")
                break

            # Attempt to checkout the specific version
            if not safe_checkout_version(repo_path, version):
                continue

            try:
                # Run linguist to detect languages
                languages = run_linguist(repo_path)

                # Determine repository size
                try:
                    size_output = subprocess.check_output(
                        f"du -sh {repo_path}",
                        shell=True,
                        text=True
                    ).split()[0]
                except Exception as size_error:
                    print(f"Error getting repository size: {size_error}")
                    size_output = "unknown"

                print(f"Repository {repo_url} version {version} size: {size_output}, languages: {languages}")

                # Append analysis results
                results.append({
                    "version": version,
                    "size": size_output,
                    "languages": languages
                })
            except Exception as analysis_error:
                print(f"Error analyzing {repo_url} version {version}: {analysis_error}")
                continue

    except Exception as e:
        print(f"Error processing {repo_url}: {str(e)}")

    return results

def group_by_repository(vulnerabilities):
    """
    Group vulnerabilities by their associated repositories.

    Args:
        vulnerabilities (list): List of vulnerability records.

    Returns:
        dict: A dictionary mapping repository URLs to lists of associated vulnerabilities.
    """
    repo_map = defaultdict(list)
    
    # Iterate over each vulnerability record
    for vuln in vulnerabilities:
        # Extract repository URLs from the vulnerability
        repos = extract_repo_info(vuln)
        
        # Map each repository to its corresponding vulnerabilities
        for repo in repos:
            repo_map[repo].append(vuln)
    
    return repo_map

def update_language_data_for_repos(repo_urls):
    """
    Update language data for specific repositories.

    This function processes repositories to update their language data by analyzing
    each version that lacks language information. It uses GitHub Linguist to detect
    language usage, calculates primary languages, and updates the data in a Neo4j database.

    Args:
        repo_urls (list): List of repository URLs to update language data for.
    """
    if not repo_urls:
        print("No repositories to update language data for")
        return

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # Ensure the repo directory exists
    os.makedirs(REPO_BASE_DIR, exist_ok=True)

    print(f"Starting language analysis for {len(repo_urls)} repositories...")

    # Process specified repositories
    with driver.session() as session:
        # Determine which repositories need language data updates
        needs_update = []
        for repo_url in repo_urls:
            result = session.run("""
                MATCH (r:Repository {url: $url})-[:HAS_VERSION]->(v:Version)
                WHERE v.language_json IS NULL OR v.primary_language IS NULL
                RETURN count(v) as needs_update
            """, url=repo_url)

            record = result.single()
            if record and record["needs_update"] > 0:
                needs_update.append(repo_url)

        print(f"Found {len(needs_update)} repositories that need language data updates")

        # Initialize language statistics
        all_languages = {}
        lang_repo_count = {}

        # Process each repository that needs updates
        for repo_url in tqdm(needs_update, desc="Processing repositories"):
            try:
                # Clone the repository to a local directory
                repo_path = safe_clone_repository(repo_url)
                if not repo_path:
                    print(f"Failed to clone repository: {repo_url}")
                    continue

                # Identify versions that require language data updates
                result = session.run("""
                    MATCH (r:Repository {url: $url})-[:HAS_VERSION]->(v:Version)
                    WHERE v.language_json IS NULL OR v.primary_language IS NULL
                    RETURN v.version as version, v.id as id
                """, url=repo_url)

                versions_to_update = [(record["version"], record["id"]) for record in result]
                print(f"Found {len(versions_to_update)} versions to update for {repo_url}")

                # Process each version to update language data
                for version, version_id in versions_to_update:
                    if not safe_checkout_version(repo_path, version):
                        print(f"Skipping version {version} as checkout failed")
                        continue

                    # Use GitHub Linguist to get language data
                    languages = run_linguist(repo_path)

                    if languages:
                        # Determine the primary language used in the repository
                        primary_language = "Unknown"
                        max_percentage = 0
                        for lang, percentage in languages.items():
                            # Update global language statistics
                            all_languages[lang] = all_languages.get(lang, 0) + percentage
                            lang_repo_count[lang] = lang_repo_count.get(lang, 0) + 1

                            if percentage > max_percentage:
                                max_percentage = percentage
                                primary_language = lang

                        # Update version's language data in Neo4j
                        session.run("""
                            MATCH (v:Version {id: $id})
                            SET v.language_json = $languages,
                                v.primary_language = $primary_language,
                                v.language_count = $language_count
                        """,
                            id=version_id,
                            languages=json.dumps(languages),
                            primary_language=primary_language,
                            language_count=len(languages)
                        )

                        print(f"Updated language data for {repo_url} version {version}")
                    else:
                        print(f"No language data found for {repo_url} version {version}")
            except Exception as e:
                print(f"Error processing repository {repo_url}: {e}")

        # Calculate and update language statistics in Neo4j
        if all_languages:
            total_repos = len(needs_update)
            language_stats = []

            for lang, total_percentage in all_languages.items():
                repo_count = lang_repo_count.get(lang, 0)
                if repo_count > 0:
                    avg_percentage = total_percentage / repo_count
                    language_stats.append({
                        "language": lang,
                        "repo_count": repo_count,
                        "avg_percentage": avg_percentage,
                        "usage_percentage": (repo_count / total_repos * 100) if total_repos > 0 else 0
                    })

            # Sort statistics by the number of repositories using the language
            language_stats.sort(key=lambda x: x["repo_count"], reverse=True)

            # Update language statistics in Neo4j
            session.run("""
                MATCH (s:LanguageStats)
                DELETE s
            """)

            session.run("""
                CREATE (s:LanguageStats {
                    updated: datetime(),
                    total_repositories: $total_repos,
                    stats: $language_stats
                })
            """, total_repos=total_repos, language_stats=json.dumps(language_stats))

            # Display language statistics
            print("\nLanguage Statistics:")
            print(f"{'Language':<15} | {'Repositories':<12} | {'Usage %':<8} | {'Avg %':<8}")
            print("-" * 50)

            for stat in language_stats[:20]:  # Display top 20 languages
                print(f"{stat['language']:<15} | {stat['repo_count']:<12} | {stat['usage_percentage']:<8.2f} | {stat['avg_percentage']:<8.2f}")

    driver.close()
    print("Language analysis complete!")

def update_all_language_data():
    """
    Update language data for all repositories in Neo4j database.
    Only updates repositories that need it.

    This function queries Neo4j to find all repositories that need language data
    updates, and then calls `update_language_data_for_repos` to perform the
    updates.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # Find repositories that need language data updates
    with driver.session() as session:
        result = session.run("""
            # Find all repositories
            MATCH (r:Repository)
            # Get the URL of each repository
            WITH r.url as url
            # Find all versions of each repository
            MATCH (r:Repository {url: url})-[:HAS_VERSION]->(v:Version)
            # Filter out repositories that have language data
            WHERE v.language_json IS NULL OR v.primary_language IS NULL
            # Get the URLs of the repositories that need updates
            RETURN DISTINCT url
        """)

        # Get the URLs of the repositories that need language data updates
        repos_to_update = [record["url"] for record in result]

    print(f"Found {len(repos_to_update)} repositories that need language data updates")

    # Update language data for repositories that need it
    update_language_data_for_repos(repos_to_update)

# -------------------------
# NEO4J FUNCTIONS
# -------------------------
def get_existing_vuln_ids():
    """
    Retrieve a set of vulnerability IDs currently stored in the Neo4j database.

    This function establishes a connection to the Neo4j database and fetches
    all existing vulnerability IDs to prevent duplicate entries during data insertion.

    Returns:
        set: A set containing the IDs of existing vulnerabilities. If an error
        occurs during retrieval, an empty set is returned to ensure all records
        are processed.
    """
    # Establish connection to Neo4j database
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    existing_ids = set()

    try:
        # Open a session to interact with the database
        with driver.session() as session:
            # Execute a query to retrieve all vulnerability IDs
            result = session.run("MATCH (v:Vulnerability) RETURN v.id as id")
            # Iterate over the results and add each ID to the set
            for record in result:
                if record and "id" in record and record["id"]:
                    existing_ids.add(record["id"])
    except Exception as e:
        # Log the error in case of a connection issue and return an empty set
        print(f"Error retrieving existing vulnerability IDs: {e}")
        return set()

    # Return the set of existing vulnerability IDs
    return existing_ids

def insert_all_vulnerabilities_into_neo4j(vuln_records, selected_versions, repo_data=None):
    """
    Enhances vulnerability records with repository information into Neo4j.
    Only inserts new vulnerabilities to avoid duplicates.

    Args:
        vuln_records (list): List of vulnerability records.
        selected_versions (list): List of selected versions.
        repo_data (list): List of repository data.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    print("Starting Neo4j insertion...")

    # Get existing vulnerability IDs
    existing_vuln_ids = get_existing_vuln_ids()

    # Filter out vulnerabilities that already exist
    new_vuln_records = [v for v in vuln_records if v.get("id") not in existing_vuln_ids]
    print(f"Found {len(new_vuln_records)} new vulnerabilities out of {len(vuln_records)}")

    if not new_vuln_records:
        print("No new vulnerabilities to insert")

        # Still update language data for any new repositories
        if repo_data:
            repo_urls = [repo.get("url") for repo in repo_data]
            update_language_data_for_repos(repo_urls)

        return

    with driver.session() as session:
        # Create indices for faster lookups if they don't exist
        print("Ensuring indices exist...")
        session.run("CREATE INDEX vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)")
        session.run("CREATE INDEX package_ecosystem_name IF NOT EXISTS FOR (p:Package) ON (p.ecosystem, p.name)")
        session.run("CREATE INDEX cve_id IF NOT EXISTS FOR (c:CVE) ON (c.id)")
        session.run("CREATE INDEX reference_url IF NOT EXISTS FOR (r:Reference) ON (r.url)")
        session.run("CREATE INDEX repository_url IF NOT EXISTS FOR (r:Repository) ON (r.url)")
        session.run("CREATE INDEX version_id IF NOT EXISTS FOR (v:Version) ON (v.id)")
        session.run("CREATE INDEX version_primary_language IF NOT EXISTS FOR (v:Version) ON (v.primary_language)")

        # Process vulnerability records to filter affected versions
        print("Processing vulnerability records to filter affected versions...")
        processed_records = []
        with tqdm(total=len(new_vuln_records), desc="Filtering vulnerability records") as pbar:
            for vuln in new_vuln_records:
                processed_vuln = vuln.copy()

                # Filter affected packages to only include selected versions
                if "affected" in processed_vuln:
                    filtered_affected = []
                    for affected_item in processed_vuln["affected"]:
                        if "versions" in affected_item:
                            # Filter to keep only selected versions
                            filtered_versions = [v for v in affected_item["versions"] if v in selected_versions]
                            if filtered_versions:
                                # Create a new affected item with only selected versions
                                new_affected = affected_item.copy()
                                new_affected["versions"] = filtered_versions
                                filtered_affected.append(new_affected)

                    # Replace with filtered affected list
                    processed_vuln["affected"] = filtered_affected

                processed_records.append(processed_vuln)
                pbar.update(1)

        # Process vulnerabilities in batches
        total_batches = (len(processed_records) + BATCH_SIZE - 1) // BATCH_SIZE

        with tqdm(total=total_batches, desc="Inserting vulnerability records", unit="batch") as pbar:
            for i in range(0, len(processed_records), BATCH_SIZE):
                batch = processed_records[i:i + BATCH_SIZE]

                for vuln in batch:
                    # 1. Create vulnerability node
                    vuln_id = vuln.get("id")
                    if not vuln_id:
                        continue

                    vuln_props = {
                        "id": vuln_id,
                        "schema_version": vuln.get("schema_version"),
                        "modified": vuln.get("modified"),
                        "published": vuln.get("published"),
                        "summary": vuln.get("summary"),
                        "details": vuln.get("details"),
                        "severity": json.dumps(vuln.get("severity", [])) if vuln.get("severity") else None,
                        "database_specific": json.dumps(vuln.get("database_specific", {})) if vuln.get("database_specific") else None,
                        "affected": json.dumps(vuln.get("affected", [])) if vuln.get("affected") else None
                    }

                    # Create vulnerability node - use MERGE to avoid duplicates
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v.schema_version = $schema_version,
                            v.modified = $modified,
                            v.published = $published,
                            v.summary = $summary,
                            v.details = $details,
                            v.severity = $severity,
                            v.database_specific = $database_specific,
                            v.affected = $affected
                        """,
                        vuln_props
                    )

                    # 2. Create package nodes and relationships
                    affected = vuln.get("affected", [])
                    for affected_pkg in affected:
                        pkg_name = affected_pkg.get("package", {}).get("name")
                        ecosystem = affected_pkg.get("package", {}).get("ecosystem")

                        if pkg_name and ecosystem:
                            # Create package node - use MERGE to avoid duplicates
                            session.run(
                                """
                                MERGE (p:Package {name: $name, ecosystem: $ecosystem})
                                """,
                                {"name": pkg_name, "ecosystem": ecosystem}
                            )

                            # Create relationship from package to vulnerability
                            versions = affected_pkg.get("versions", [])
                            version_ranges = json.dumps(affected_pkg.get("ranges", [])) if affected_pkg.get("ranges") else None

                            # Create AFFECTED_BY relationship with version info - use MERGE to avoid duplicates
                            session.run(
                                """
                                MATCH (p:Package {name: $name, ecosystem: $ecosystem})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (p)-[r:AFFECTED_BY]->(v)
                                SET r.versions = $versions,
                                    r.version_ranges = $version_ranges
                                """,
                                {
                                    "name": pkg_name,
                                    "ecosystem": ecosystem,
                                    "vuln_id": vuln_id,
                                    "versions": json.dumps(versions) if versions else None,
                                    "version_ranges": version_ranges
                                }
                            )

                    # 3. Create CVE nodes and relationships
                    aliases = vuln.get("aliases", [])
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            # Create CVE node - use MERGE to avoid duplicates
                            session.run(
                                """
                                MERGE (c:CVE {id: $cve_id})
                                """,
                                {"cve_id": alias}
                            )

                            # Create relationship between CVE and vulnerability - use MERGE to avoid duplicates
                            session.run(
                                """
                                MATCH (c:CVE {id: $cve_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (c)-[:IDENTIFIED_AS]->(v)
                                """,
                                {"cve_id": alias, "vuln_id": vuln_id}
                            )

                    # 4. Create Reference nodes and relationships
                    references = vuln.get("references", [])
                    for ref in references:
                        url = ref.get("url")
                        ref_type = ref.get("type")

                        if url:
                            # Create Reference node - use MERGE to avoid duplicates
                            session.run(
                                """
                                MERGE (r:Reference {url: $url})
                                SET r.type = $type
                                """,
                                {"url": url, "type": ref_type}
                            )

                            # Create relationship from vulnerability to reference - use MERGE to avoid duplicates
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MATCH (r:Reference {url: $url})
                                MERGE (v)-[:REFERS_TO]->(r)
                                """,
                                {"vuln_id": vuln_id, "url": url}
                            )

                    # 5. Create relationships between vulnerabilities
                    related = vuln.get("related", [])
                    for related_id in related:
                        session.run(
                            """
                            MATCH (v1:Vulnerability {id: $source_id})
                            MERGE (v2:Vulnerability {id: $target_id})
                            MERGE (v1)-[:RELATED_TO]->(v2)
                            """,
                            {"source_id": vuln_id, "target_id": related_id}
                        )

                pbar.update(1)

        # Insert repository and version information
        if repo_data:
            print("\nAdding repository and version information...")

            # Get existing repository URLs
            result = session.run("""
                MATCH (r:Repository) RETURN r.url as url
            """)
            existing_repos = {record["url"] for record in result}

            # Get existing version IDs
            result = session.run("""
                MATCH (v:Version) RETURN v.id as id
            """)
            existing_versions = {record["id"] for record in result}

            with tqdm(total=len(repo_data), desc="Processing repositories", unit="repo") as pbar:
                for repo in repo_data:
                    repo_url = repo.get("url")
                    vuln_ids = repo.get("vulnerabilities", [])
                    versions = repo.get("versions", [])

                    if not repo_url:
                        continue

# -------------------------
# MAIN EXECUTION
# -------------------------
def main():
    """
    Main execution function with support for continuous operation.

    This function is the main entry point for the script. It will:

    1. Download the OSV 'all vulnerabilities' zip file from the specified URL.
    2. Process the file incrementally to extract vulnerability records.
    3. Analyze repositories to obtain language information.
    4. Insert all data into a Neo4j database.

    If the script is run with the '--update-languages' command line argument, it
    will only update language data for all repositories.
    """
    # Register timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)

    start_time = datetime.datetime.now()
    print(f"OSV-Neo4j update started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Create output directories
    os.makedirs(REPO_BASE_DIR, exist_ok=True)

    # Setup git SSH
    setup_git_ssh()

    # Test Neo4j connection first
    if not test_neo4j_connection():
        print("Cannot proceed without Neo4j connection. Please check your configuration.")
        return

    try:
        # Check for command line arguments
        if len(sys.argv) > 1 and sys.argv[1] == "--update-languages":
            # Only update language data
            update_all_language_data()
            return

        # Check if GitHub token is available
        if GITHUB_TOKEN:
            print("GitHub token is configured and will be used for authentication")
        else:
            print("WARNING: No GitHub token found. Repository operations may be rate-limited.")
            print("Set GITHUB_TOKEN environment variable or update the script with your token.")

        # Skip downloading again if already downloaded and we're continuing from a checkpoint
        if os.path.exists(OSV_ZIP_CACHE) and CONTINUE_FROM_CHECKPOINT:
            print(f"Using existing OSV zip file: {OSV_ZIP_CACHE}")
            with open(OSV_ZIP_CACHE, 'rb') as f:
                zip_bytes = io.BytesIO(f.read())
        else:
            # Download and save for future runs
            zip_bytes = download_osv_all_zip(OSV_ZIP_URL)
            with open(OSV_ZIP_CACHE, 'wb') as f:
                f.write(zip_bytes.getvalue())

        # Process vulnerabilities incrementally
        all_vulnerabilities = process_vulnerabilities(zip_bytes, max_records=MAX_RECORDS_PER_RUN)

        if not all_vulnerabilities:
            print("No new vulnerabilities to process. Check if all files have been processed.")
            # Still update language data for any missing language information
            update_all_language_data()
            return

        print(f"Processed {len(all_vulnerabilities)} new vulnerability records")

        # Use greedy algorithm to select minimum set of versions
        try:
            # Set timeout for this operation (30 minutes)
            signal.alarm(1800)
            minimum_version_vulns, selected_versions = greedy_minimum_version_set(all_vulnerabilities)
            # Clear the alarm
            signal.alarm(0)
        except TimeoutException:
            print("Greedy algorithm timed out. Proceeding with all vulnerabilities.")
            minimum_version_vulns = all_vulnerabilities
            selected_versions = set()  # Empty set means all versions will be included

        print(f"Selected {len(selected_versions)} versions covering {len(minimum_version_vulns)} vulnerabilities")

        # Group vulnerabilities by repository
        repo_vuln_map = group_by_repository(minimum_version_vulns)
        print(f"Found {len(repo_vuln_map)} unique repositories")

        # Get existing processed repositories and current batch size
        processed_repos, current_batch_size = load_repository_progress()
        print(f"Current repository batch size: {current_batch_size}")

        # Analyze repositories and versions - limit based on batch size
        repo_data = []
        print("Analyzing repositories...")

        # Get repositories that need processing (not already processed)
        repos_to_process = [repo_url for repo_url in repo_vuln_map.keys() if repo_url not in processed_repos]

        print(f"\n--- REPOSITORY PROCESSING DEBUG ---")
        print(f"Total repositories to process: {len(repos_to_process)}")
        print(f"Batch size: {current_batch_size}")

        # Process limited number of repositories per run
        repo_batch = repos_to_process[:current_batch_size]
        print(f"Repositories in this batch: {repo_batch}")

        for repo_url in tqdm(repo_batch, desc="Analyzing repositories"):
            print(f"\n=== PROCESSING REPOSITORY: {repo_url} ===")

            # Robust repository cloning
            try:
                # Force clone the repository first
                clone_path = safe_clone_repository(repo_url)
                if not clone_path:
                    print(f"FAILED to clone repository: {repo_url}")
                    continue

                vulns = repo_vuln_map[repo_url]
                vuln_ids = [v.get("id") for v in vulns if v.get("id")]

                # Get all target versions from vulnerabilities
                target_versions = set()
                for vuln in vulns:
                    for affected in vuln.get("affected", []):
                        versions = affected.get("versions", [])
                        target_versions.update(versions)

                # If no versions, use default branch
                if not target_versions:
                    target_versions = ['master', 'main', 'HEAD']

                print(f"Repository: {repo_url}")
                print(f"Clone Path: {clone_path}")
                print(f"Target Versions: {target_versions}")
                print(f"Vulnerability Count: {len(vuln_ids)}")

                # Analyze repository with versions
                version_info = analyze_repository(repo_url, list(target_versions))

                if version_info:
                    repo_data.append({
                        "url": repo_url,
                        "vulnerabilities": vuln_ids,
                        "versions": version_info
                    })
                else:
                    print(f"NO VERSION INFO OBTAINED FOR {repo_url}")

                # Mark repository as processed
                processed_repos.add(repo_url)

                # Save progress periodically
                if len(repo_data) % 2 == 0:
                    save_repository_progress(processed_repos, current_batch_size)

                # Add a delay to avoid rate limiting
                time.sleep(2)

            except Exception as e:
                print(f"UNEXPECTED ERROR processing {repo_url}: {e}")
                continue

        # Save final repository progress
        save_repository_progress(processed_repos, current_batch_size)

        # Insert all data into Neo4j
        if minimum_version_vulns:
            print(f"Inserting {len(minimum_version_vulns)} vulnerabilities into Neo4j...")
            insert_all_vulnerabilities_into_neo4j(minimum_version_vulns, selected_versions, repo_data)
        else:
            print("WARNING: No vulnerabilities remained after filtering.")
            update_all_language_data()

        # End time and summary
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        print(f"\nOSV-Neo4j update completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total execution time: {duration.total_seconds()/60:.2f} minutes")

        # Summary statistics
        print("\nSummary:")
        print(f"- New vulnerabilities processed: {len(all_vulnerabilities)}")
        print(f"- Repositories analyzed: {len(repo_data)}")
        print(f"- Current repository batch size: {current_batch_size}")
        print(f"- Total repositories processed so far: {len(processed_repos)}")

        # Report where repositories are stored if keeping them
        if KEEP_REPOS:
            print(f"\nRepositories have been preserved in: {os.path.abspath(REPO_BASE_DIR)}")
            print("You can analyze them with GitHub Linguist using:")
            print(f"  cd {os.path.abspath(REPO_BASE_DIR)}/repository_name")
            print("  github-linguist --breakdown")
    except Exception as e:
        print(f"Error in main execution: {e}")
    finally:
        # Clear any pending alarms
        signal.alarm(0)

if __name__ == "__main__":
    main()
