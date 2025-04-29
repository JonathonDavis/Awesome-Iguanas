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
SAMPLE_PERCENTAGE = 5  # Process only 5% of data for testing
REPO_BASE_DIR = "repos"
LINGUIST_CMD = "github-linguist"  # Requires linguist installed
KEEP_REPOS = True  # Set to True to keep repositories after processing

# GitHub token from environment or set directly
GITHUB_TOKEN = ""  # Set your token here if not using env var

# Add timeout handler to prevent hanging
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out")

# Configure git to automatically accept SSH host keys
def setup_git_ssh():
    """Configure git to automatically accept SSH host keys"""
    git_ssh_cmd = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    os.environ['GIT_SSH_COMMAND'] = git_ssh_cmd

# -------------------------
# OSV FUNCTIONS
# -------------------------
def download_osv_all_zip(url):
    """
    Downloads the OSV 'all vulnerabilities' zip file from the given URL
    and returns a BytesIO object.
    """
    print(f"Downloading OSV data from {url} ...")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    # Get content length for progress bar if available
    total_size = int(response.headers.get('content-length', 0))

    # Setup progress bar
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading")

    # Download with progress tracking
    content = io.BytesIO()
    for chunk in response.iter_content(chunk_size=8192):
        if chunk:
            progress_bar.update(len(chunk))
            content.write(chunk)

    progress_bar.close()
    content.seek(0)
    print("Download complete!")
    return content

def process_vulnerabilities(zip_bytes, sample_percentage=SAMPLE_PERCENTAGE, start_percent=0):
    """
    Opens the provided ZIP and extracts vulnerability records.
    Processes only a percentage of the files starting from a specific point.
    
    Parameters:
    -----------
    zip_bytes : BytesIO
        ZIP file contents
    sample_percentage : int
        Percentage of files to process in this run
    start_percent : int
        Starting percentage point (to continue from previous runs)
    """
    vulnerabilities = []

    def process_file(file):
        """Helper function to process a single file."""
        try:
            with zf.open(file) as f:
                return json.load(f)
        except Exception as e:
            print(f"\nError processing file {file}: {e}")
            return None

    with zipfile.ZipFile(zip_bytes, 'r') as zf:
        file_list = zf.namelist()
        total_files = len(file_list)
        print(f"Found {total_files} files in the archive.")

        # Calculate start and end positions
        start_idx = int(total_files * start_percent / 100)
        end_idx = int(total_files * (start_percent + sample_percentage) / 100)
        
        # Ensure we don't go past the end
        end_idx = min(end_idx, total_files)
        
        # Get subset of files for this run
        subset = file_list[start_idx:end_idx]

        print(f"Processing files {start_idx} to {end_idx} ({len(subset)} files, {sample_percentage}% chunk starting at {start_percent}%)...")

        # Process files in batches using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            with tqdm(total=len(subset), desc="Processing files", unit="files") as pbar:
                for batch_start in range(0, len(subset), PROCESSING_BATCH_SIZE):
                    batch_files = subset[batch_start:batch_start + PROCESSING_BATCH_SIZE]
                    results = list(executor.map(process_file, batch_files))
                    vulnerabilities.extend(filter(None, results))
                    pbar.update(len(batch_files))
                    del results
                    gc.collect()
                    print(f"Processed {batch_start + len(batch_files)} / {len(subset)} files.")

    return vulnerabilities

def greedy_minimum_version_set(vulnerabilities):
    """
    Uses a fast greedy approach to find a near-optimal minimum version set.
    Returns both the filtered vulnerabilities and the selected versions.
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

        if vuln_idx > 0 and vuln_idx % 10000 == 0:
            print(f"Processed {vuln_idx}/{len(vulnerabilities)} vulnerabilities, found {len(version_to_vulns)} unique versions")

        for affected_package in affected:
            versions = affected_package.get("versions", [])
            if not versions:
                # If no explicit versions, try to extract from ranges
                ranges = affected_package.get("ranges", [])
                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        version = event.get("introduced", event.get("fixed", ""))
                        if version:
                            versions.append(version)
                            # Try to get the date
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

            if len(selected_versions) % 100 == 0:
                print(f"Selected {len(selected_versions)} versions, {len(uncovered_vulns)} vulnerabilities remain uncovered")

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

    # Debug info about versions selected
    print("\nSelected versions (sample):")
    for i, version in enumerate(selected_versions[:10]):
        vulns_covered = len(version_to_vulns[version])
        date = version_dates.get(version, "Unknown date")
        print(f"{i+1}. {version} - Covers {vulns_covered} vulns - Date: {date}")

    if len(selected_versions) > 10:
        print(f"... and {len(selected_versions) - 10} more versions")

    return result_vulns, selected_versions

# -------------------------
# REPOSITORY FUNCTIONS
# -------------------------
def extract_repo_info(vuln):
    """
    Enhanced repository URL extraction with improved validation
    """
    repos = set()

    def clean_github_url(url):
        """
        Clean and standardize GitHub URLs
        """
        # Remove specific file/blob/advisory paths
        url = url.split('/blob/')[0]
        url = url.split('/security/advisories/')[0]
        url = url.split('/releases')[0]

        # Ensure base repository URL
        if url.startswith('https://github.com/'):
            # Split URL and keep only owner/repo
            parts = url.replace('https://github.com/', '').split('/')
            if len(parts) >= 2:
                return f'https://github.com/{parts[0]}/{parts[1]}'
        return None

    # Check package information
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})

        # Go ecosystem repositories
        if package.get("ecosystem") == "Go" and package.get("name"):
            repos.add(f"https://github.com/{package['name']}")

        # Package URL parsing
        elif package.get("purl"):
            if "github.com" in package["purl"]:
                clean_url = clean_github_url(package["purl"])
                if clean_url:
                    repos.add(clean_url)

    # Check references
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        if "github.com" in url:
            clean_url = clean_github_url(url)
            if clean_url:
                repos.add(clean_url)

    return list(repos)

def safe_clone_repository(repo_url, base_dir=REPO_BASE_DIR, max_retries=3):
    """
    Robust repository cloning with multiple strategies, including GitHub token authentication.
    """
    # Add GitHub token to URL if it's a GitHub repository and token is available
    authenticated_url = repo_url
    if 'github.com' in repo_url and GITHUB_TOKEN and not repo_url.startswith('git@'):
        authenticated_url = repo_url.replace('https://github.com/', f'https://{GITHUB_TOKEN}@github.com/')

    # Sanitize repository name for local path
    repo_name = repo_url.replace('https://github.com/', '').replace('/', '_')
    repo_path = os.path.join(base_dir, repo_name)

    # Cleanup/retry strategies
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
            print(f"Successfully cloned {repo_url} (attempt {attempt+1})")
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

            # Alternative strategies
            if attempt == 0:
                # Try HTTPS to SSH conversion
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
    """
    try:
        # Attempt to checkout the specified version
        print(f"Checking out version {version}...")
        subprocess.run(
            ["git", "-C", repo_path, "checkout", version],
            check=True,
            capture_output=True
        )
        return True
    except subprocess.CalledProcessError:
        print(f"Could not checkout version {version} for repository at {repo_path}")

        # Attempt to find and checkout the default branch
        try:
            default_branch = subprocess.check_output(
                ["git", "-C", repo_path, "symbolic-ref", "refs/remotes/origin/HEAD"],
                text=True
            ).strip().split('/')[-1]  # Extract branch name

            print(f"Falling back to default branch: {default_branch}")
            subprocess.run(
                ["git", "-C", repo_path, "checkout", default_branch],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            print(f"Failed to checkout default branch for repository at {repo_path}")
            return False

def get_valid_repository_versions(repo_path):
    """
    Retrieve all valid tags and commits for a repository
    """
    try:
        # Get all tags
        tags_output = subprocess.check_output(
            ["git", "-C", repo_path, "tag"],
            stderr=subprocess.PIPE,
            text=True
        ).strip().split('\n')

        # Get all branches
        branches_output = subprocess.check_output(
            ["git", "-C", repo_path, "branch", "-r"],
            stderr=subprocess.PIPE,
            text=True
        ).strip().split('\n')

        # Clean and deduplicate versions
        versions = set()

        # Process tags
        for tag in tags_output:
            tag = tag.strip()
            if tag:
                versions.add(tag)

        # Process branches (remove origin/ prefix)
        for branch in branches_output:
            branch = branch.strip().replace('origin/', '')
            if branch and branch not in ['HEAD', '']:
                versions.add(branch)

        return list(versions)
    except subprocess.CalledProcessError as e:
        print(f"Error getting versions: {e}")
        return []

def find_closest_version(available_versions, target_versions):
    """
    Find the closest matching version from available versions
    """
    def version_key(v):
        """
        Create a sortable key for version comparison
        Handles various version formats
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

    # If no specific versions, return all available
    if not target_versions:
        return available_versions[:5]  # Limit to 5 versions if no targets specified

    # Filter and map versions
    matched_versions = []
    for target in target_versions:
        # Try exact match first
        if target in available_versions:
            matched_versions.append(target)
            continue

        # If exact match fails, find closest
        sorted_versions = sorted(available_versions, key=version_key)

        # Find versions close to the target
        closest = min(sorted_versions, key=lambda x: abs(version_key(x)[0] - version_key(target)[0]))
        matched_versions.append(closest)

    return list(set(matched_versions))

def manual_language_detection(repo_path):
    """
    Manual language detection as a fallback
    """
    language_stats = {}
    total_files = 0

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

    for root, _, files in os.walk(repo_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            total_files += 1

            for lang, extensions in language_extensions.items():
                if ext in extensions:
                    language_stats[lang] = language_stats.get(lang, 0) + 1

    # Convert to percentage output similar to linguist
    if total_files > 0:
        for lang in language_stats:
            language_stats[lang] = round((language_stats[lang] / total_files * 100), 2)

    return language_stats

def analyze_repository(repo_url, versions, timeout=300):
    """
    Enhanced repository analysis with improved Linguist output handling
    """
    # Validate and clean repository URL
    cleaned_repos = extract_repo_info({"references": [{"url": repo_url}]})
    if not cleaned_repos:
        print(f"Invalid repository URL: {repo_url}")
        return []

    repo_url = cleaned_repos[0]

    # Clone repository safely
    repo_path = safe_clone_repository(repo_url)
    if not repo_path:
        return []

    results = []
    start_time = time.time()

    try:
        # Get all available versions in the repository
        available_versions = get_valid_repository_versions(repo_path)

        # If no versions are available, log and skip
        if not available_versions:
            print(f"No valid versions found for repository: {repo_url}")
            return []

        # Find closest matching versions
        matched_versions = find_closest_version(available_versions, versions)
        print(f"Found {len(matched_versions)} matching versions for {repo_url}: {matched_versions}")

        for version in matched_versions:
            # Check if we're approaching the timeout
            if time.time() - start_time > timeout * 0.8:  # 80% of timeout reached
                print(f"Warning: Approaching timeout for {repo_url}, skipping remaining versions")
                break

            if not safe_checkout_version(repo_path, version):
                continue

            try:
                # Language detection with improved parsing
                languages = {}

                try:
                    # Run GitHub Linguist with detailed breakdown
                    print(f"Running GitHub Linguist on {repo_url} version {version}...")
                    linguist_result = subprocess.run(
                        [LINGUIST_CMD, "--breakdown", repo_path],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    linguist_output = linguist_result.stdout

                    # Parse output into a dictionary
                    for line in linguist_output.strip().split("\n"):
                        if "%" in line:
                            try:
                                parts = line.strip().split()
                                percentage_part = parts[-1]
                                if "%" in percentage_part:
                                    percentage = float(percentage_part.rstrip("%"))
                                    language = " ".join(parts[:-1])
                                    languages[language] = percentage
                            except (ValueError, IndexError) as parse_error:
                                print(f"Error parsing Linguist line '{line}': {parse_error}")

                    print(f"Linguist detected languages: {languages}")

                except subprocess.CalledProcessError as e:
                    print(f"Linguist error for {repo_url}: {e}, falling back to manual detection")
                    # Fallback to manual language detection
                    languages = manual_language_detection(repo_path)
                    print(f"Manual language detection result: {languages}")

                # Add size info
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

                # Save results
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
    finally:
        # Only clean up repository if not keeping repos
        if not KEEP_REPOS and os.path.exists(repo_path):
            try:
                shutil.rmtree(repo_path)
                print(f"Cleaned up repository {repo_path}")
            except Exception as cleanup_error:
                print(f"Error cleaning up repository {repo_path}: {cleanup_error}")

    return results

def group_by_repository(vulnerabilities):
    """Group vulnerabilities by their associated repositories"""
    repo_map = defaultdict(list)
    for vuln in vulnerabilities:
        repos = extract_repo_info(vuln)
        for repo in repos:
            repo_map[repo].append(vuln)
    return repo_map

# -------------------------
# NEO4J FUNCTIONS
# -------------------------
def insert_all_vulnerabilities_into_neo4j(vuln_records, selected_versions, repo_data=None):
    """
    Enhances vulnerability records with repository information into Neo4j as a comprehensive graph.
    Filters affected versions to only include those in the selected_versions set.
    Appends to existing data rather than clearing the database.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    print("Starting Neo4j insertion...")

    with driver.session() as session:
        # NOTE: Removed the "Clear existing data" section to preserve existing data
        print("Appending to existing data in Neo4j...")

        # Create indices for faster lookups (doesn't hurt to ensure they exist)
        print("Creating indices if they don't exist...")
        session.run("CREATE INDEX vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)")
        session.run("CREATE INDEX package_ecosystem_name IF NOT EXISTS FOR (p:Package) ON (p.ecosystem, p.name)")
        session.run("CREATE INDEX cve_id IF NOT EXISTS FOR (c:CVE) ON (c.id)")
        session.run("CREATE INDEX reference_url IF NOT EXISTS FOR (r:Reference) ON (r.url)")
        session.run("CREATE INDEX repository_url IF NOT EXISTS FOR (r:Repository) ON (r.url)")
        session.run("CREATE INDEX version_id IF NOT EXISTS FOR (v:Version) ON (v.id)")

        # Process vulnerability records to filter affected versions
        print("Processing vulnerability records to filter affected versions...")
        processed_records = []
        with tqdm(total=len(vuln_records), desc="Filtering vulnerability records") as pbar:
            for vuln in vuln_records:
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
                    # 1. Create vulnerability node (MERGE will only create if it doesn't exist)
                    vuln_id = vuln.get("id")
                    if not vuln_id:
                        continue

                    # Check if this vulnerability already exists before processing
                    result = session.run(
                        "MATCH (v:Vulnerability {id: $id}) RETURN count(v) as count",
                        {"id": vuln_id}
                    ).single()
                    
                    # Skip if vulnerability already exists
                    if result["count"] > 0:
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

                    # Create vulnerability node
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
                            # Create package node
                            session.run(
                                """
                                MERGE (p:Package {name: $name, ecosystem: $ecosystem})
                                """,
                                {"name": pkg_name, "ecosystem": ecosystem}
                            )

                            # Create relationship from package to vulnerability
                            versions = affected_pkg.get("versions", [])
                            version_ranges = json.dumps(affected_pkg.get("ranges", [])) if affected_pkg.get("ranges") else None

                            # Create AFFECTED_BY relationship with version info
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
                            # Create CVE node
                            session.run(
                                """
                                MERGE (c:CVE {id: $cve_id})
                                """,
                                {"cve_id": alias}
                            )

                            # Create relationship between CVE and vulnerability
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
                            # Create Reference node
                            session.run(
                                """
                                MERGE (r:Reference {url: $url})
                                SET r.type = $type
                                """,
                                {"url": url, "type": ref_type}
                            )

                            # Create relationship from vulnerability to reference
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
            with tqdm(total=len(repo_data), desc="Processing repositories", unit="repo") as pbar:
                for repo in repo_data:
                    repo_url = repo.get("url")
                    vuln_ids = repo.get("vulnerabilities", [])
                    versions = repo.get("versions", [])

                    if not repo_url:
                        continue

                    # Create Repository node
                    session.run(
                        """
                        MERGE (r:Repository {url: $url})
                        """,
                        {"url": repo_url}
                    )

                    # Create Version nodes and relationships
                    for version_info in versions:
                        version = version_info.get("version")
                        size = version_info.get("size", "0")
                        languages = version_info.get("languages", {})

                        # Check if this version already exists
                        version_id = f"{repo_url}@{version}"
                        result = session.run(
                            "MATCH (v:Version {id: $id}) RETURN count(v) as count",
                            {"id": version_id}
                        ).single()
                        
                        # Skip if version already exists
                        if result["count"] > 0:
                            continue

                        # Identify primary language (if any)
                        primary_language = "Unknown"
                        max_percentage = 0
                        for lang, percentage in languages.items():
                            if percentage > max_percentage:
                                max_percentage = percentage
                                primary_language = lang

                        # Create Version node with improved language handling
                        session.run(
                            """
                            MERGE (v:Version {id: $id})
                            SET v.version = $version,
                                v.size = $size,
                                v.language_json = $language_json,
                                v.primary_language = $primary_language,
                                v.language_count = $language_count
                            """,
                            {
                                "id": version_id,
                                "version": version,
                                "size": size,
                                "language_json": json.dumps(languages),
                                "primary_language": primary_language,
                                "language_count": len(languages)
                            }
                        )

                        # Create relationship from Repository to Version
                        session.run(
                            """
                            MATCH (r:Repository {url: $url})
                            MATCH (v:Version {id: $id})
                            MERGE (r)-[:HAS_VERSION]->(v)
                            """,
                            {"url": repo_url, "id": version_id}
                        )

                    # Create relationship from Vulnerability to Repository
                    for vuln_id in vuln_ids:
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MATCH (r:Repository {url: $url})
                            MERGE (v)-[:FOUND_IN]->(r)
                            """,
                            {"vuln_id": vuln_id, "url": repo_url}
                        )

                    pbar.update(1)

        # Create some useful indices after data insertion
        print("Creating additional indices for performance...")
        session.run("CREATE INDEX reference_type IF NOT EXISTS FOR (r:Reference) ON (r.type)")
        session.run("CREATE INDEX version_primary_language IF NOT EXISTS FOR (v:Version) ON (v.primary_language)")

        # Count statistics for verification
        stats = session.run("""
            MATCH (v:Vulnerability) RETURN count(v) as vuln_count
        """).single()
        print(f"\nTotal vulnerabilities in Neo4j: {stats['vuln_count']}")

        stats = session.run("""
            MATCH (p:Package) RETURN count(p) as pkg_count
        """).single()
        print(f"Total packages in Neo4j: {stats['pkg_count']}")

        stats = session.run("""
            MATCH (r:Repository) RETURN count(r) as repo_count
        """).single()
        print(f"Total repositories in Neo4j: {stats['repo_count']}")

        print("Neo4j insertion complete!")

# -------------------------
# MAIN EXECUTION
# -------------------------
def main():
    """Main execution function"""
    # Add command line argument parsing
    import argparse
    parser = argparse.ArgumentParser(description='OSV vulnerability data processing and Neo4j import')
    parser.add_argument('--start-percent', type=int, default=0,
                      help='Starting percentage of OSV data to process (default: 0)')
    parser.add_argument('--chunk-size', type=int, default=5,
                      help='Percentage chunk size to process in this run (default: 5)')
    parser.add_argument('--max-repos', type=int, default=5,
                      help='Maximum number of repositories to process per run (default: 5)')
    args = parser.parse_args()
    
    # Register timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)

    start_time = datetime.datetime.now()
    print(f"OSV-Neo4j update started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Processing data chunk: {args.start_percent}% to {args.start_percent + args.chunk_size}%")

    # Create output directories
    os.makedirs(REPO_BASE_DIR, exist_ok=True)

    # Setup git SSH
    setup_git_ssh()

    try:
        # Check if GitHub token is available
        if GITHUB_TOKEN:
            print("GitHub token is configured and will be used for authentication")
        else:
            print("WARNING: No GitHub token found. Repository operations may be rate-limited.")
            print("Set GITHUB_TOKEN environment variable or update the script with your token.")

        # Download OSV data
        try:
            zip_bytes = download_osv_all_zip(OSV_ZIP_URL)
        except Exception as e:
            print(f"Error downloading OSV data: {e}")
            return

        # Process vulnerabilities for current chunk
        all_vulnerabilities = process_vulnerabilities(
            zip_bytes, 
            sample_percentage=args.chunk_size, 
            start_percent=args.start_percent
        )
        print(f"Processed {len(all_vulnerabilities)} vulnerability records")

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

        # Analyze repositories and versions
        repo_data = []
        print("Analyzing repositories...")
        
        # Process repositories with the limit from command line
        for repo_url, vulns in tqdm(list(repo_vuln_map.items())[:args.max_repos], desc="Analyzing repositories"):
            vuln_ids = [v.get("id") for v in vulns if v.get("id")]

            # Get all target versions from vulnerabilities
            target_versions = set()
            for vuln in vulns:
                for affected in vuln.get("affected", []):
                    versions = affected.get("versions", [])
                    # Only add versions that are in our selected_versions set
                    for v in versions:
                        if v in selected_versions:
                            target_versions.add(v)

            # Analyze repository with versions
            print(f"Analyzing repository: {repo_url} with {len(target_versions)} target versions")
            version_info = analyze_repository(repo_url, list(target_versions))

            if version_info:
                repo_data.append({
                    "url": repo_url,
                    "vulnerabilities": vuln_ids,
                    "versions": version_info
                })

            # Add a delay to avoid rate limiting
            time.sleep(2)

        # Insert all data into Neo4j using the non-wiping version
        if minimum_version_vulns:
            print(f"Inserting {len(minimum_version_vulns)} vulnerabilities into Neo4j...")
            insert_all_vulnerabilities_into_neo4j(minimum_version_vulns, selected_versions, repo_data)
        else:
            print("WARNING: No vulnerabilities remained after filtering.")

        # Calculate next starting percentage for next run
        next_start = args.start_percent + args.chunk_size
        if next_start >= 100:
            print("Completed processing 100% of OSV data!")
        else:
            print(f"Next run should start at {next_start}% (use --start-percent={next_start})")

        # Save progress to a file
        with open('osv_progress.json', 'w') as f:
            json.dump({
                'last_processed_percent': args.start_percent + args.chunk_size,
                'timestamp': datetime.datetime.now().isoformat(),
                'complete': next_start >= 100
            }, f)
            print(f"Saved progress to osv_progress.json")

        # End time and summary
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        print(f"\nOSV-Neo4j update completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total execution time: {duration.total_seconds()/60:.2f} minutes")

        # Summary statistics
        print("\nSummary:")
        print(f"- Total vulnerabilities processed: {len(all_vulnerabilities)}")
        print(f"- Vulnerabilities after minimum version filtering: {len(minimum_version_vulns)}")
        print(f"- Selected versions: {len(selected_versions)}")
        print(f"- Analyzed repositories: {len(repo_data)}")
        print(f"- Progress: {args.start_percent + args.chunk_size}% complete")
        print(f"- Maximum repositories per run: {args.max_repos}")

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

        # Only clean up repository directory if not keeping repos
        if not KEEP_REPOS and os.path.exists(REPO_BASE_DIR):
            try:
                shutil.rmtree(REPO_BASE_DIR)
                print(f"Cleaned up repository directory: {REPO_BASE_DIR}")
            except Exception as e:
                print(f"Error cleaning up repository directory: {e}")
				
if __name__ == "__main__":
    main()