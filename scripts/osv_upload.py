import os
import json
import gc
import zipfile
import io
import requests
import shutil
import datetime
import signal
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from neo4j import GraphDatabase
from collections import defaultdict

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
SAMPLE_PERCENTAGE = 10  # Process only 10% of data for testing

# Add timeout handler to prevent hanging
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out")

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

def process_vulnerabilities(zip_bytes, sample_percentage=SAMPLE_PERCENTAGE):
    """
    Opens the provided ZIP and extracts vulnerability records.
    Processes only a percentage of the files to speed up testing.
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

        # Calculate the number of files to process (sample_percentage% of total files)
        files_to_process = int(total_files * sample_percentage / 100)
        subset = file_list[:files_to_process]

        print(f"Processing {sample_percentage}% of the files ({files_to_process} files) for faster testing...")

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
        return []

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

    return result_vulns

# -------------------------
# NEO4J FUNCTIONS
# -------------------------
def insert_all_vulnerabilities_into_neo4j(vuln_records):
    """
    Inserses vulnerability records into Neo4j as a comprehensive graph with:
    - Vulnerability nodes (OSV entries)
    - Package nodes (affected software packages)
    - CVE nodes (related CVE identifiers)
    - Reference nodes (links to advisories, fixes, etc.)
    And their relationships.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    print("Starting Neo4j insertion...")

    with driver.session() as session:
        # Clear existing data
        print("Clearing existing vulnerability data...")
        session.run("""
            MATCH (n) 
            WHERE n:Vulnerability OR n:Package OR n:CVE OR n:Reference
            DETACH DELETE n
        """)

        # Create indices for faster lookups
        print("Creating indices...")
        session.run("CREATE INDEX vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)")
        session.run("CREATE INDEX package_ecosystem_name IF NOT EXISTS FOR (p:Package) ON (p.ecosystem, p.name)")
        session.run("CREATE INDEX cve_id IF NOT EXISTS FOR (c:CVE) ON (c.id)")
        session.run("CREATE INDEX reference_url IF NOT EXISTS FOR (r:Reference) ON (r.url)")

        # Process vulnerabilities in batches
        total_batches = (len(vuln_records) + BATCH_SIZE - 1) // BATCH_SIZE
        
        with tqdm(total=total_batches, desc="Processing vulnerability records", unit="batch") as pbar:
            for i in range(0, len(vuln_records), BATCH_SIZE):
                batch = vuln_records[i:i + BATCH_SIZE]
                
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
                        "database_specific": json.dumps(vuln.get("database_specific", {})) if vuln.get("database_specific") else None
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
                            v.database_specific = $database_specific
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
                    
        # Create some useful indexes after data is loaded
        print("Creating additional indices for performance...")
        session.run("CREATE INDEX reference_type IF NOT EXISTS FOR (r:Reference) ON (r.type)")
        
        # Display some statistics
        stats = {}
        stats["vulnerability_count"] = session.run("MATCH (v:Vulnerability) RETURN count(v) AS count").single()["count"]
        stats["package_count"] = session.run("MATCH (p:Package) RETURN count(p) AS count").single()["count"]
        stats["cve_count"] = session.run("MATCH (c:CVE) RETURN count(c) AS count").single()["count"]
        stats["reference_count"] = session.run("MATCH (r:Reference) RETURN count(r) AS count").single()["count"]
        stats["affects_rel_count"] = session.run("MATCH ()-[r:AFFECTED_BY]->() RETURN count(r) AS count").single()["count"]
        
        print("\nDatabase Statistics:")
        print(f"- Vulnerability nodes: {stats['vulnerability_count']}")
        print(f"- Package nodes: {stats['package_count']}")
        print(f"- CVE nodes: {stats['cve_count']}")
        print(f"- Reference nodes: {stats['reference_count']}")
        print(f"- AFFECTED_BY relationships: {stats['affects_rel_count']}")

    driver.close()
    print("Neo4j insertion complete.")

def main():
    # Register timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)

    start_time = datetime.datetime.now()
    print(f"OSV-Neo4j update started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        zip_bytes = download_osv_all_zip(OSV_ZIP_URL)
    except Exception as e:
        print(f"Error downloading OSV data: {e}")
        return

    # Process 10% of vulnerabilities for testing
    all_vulnerabilities = process_vulnerabilities(zip_bytes, sample_percentage=SAMPLE_PERCENTAGE)
    print(f"Processed {len(all_vulnerabilities)} vulnerabilities.")

    if all_vulnerabilities:
        # Use greedy algorithm only - skip CP-SAT entirely
        print("Finding minimum version set to cover all vulnerabilities...")
        try:
            # Set timeout for this operation (30 minutes)
            signal.alarm(1800)
            minimum_version_vulns = greedy_minimum_version_set(all_vulnerabilities)
            # Clear the alarm
            signal.alarm(0)
        except TimeoutException:
            print("Greedy algorithm timed out. Proceeding with all vulnerabilities.")
            minimum_version_vulns = all_vulnerabilities

        print(f"Filtered to {len(minimum_version_vulns)} vulnerabilities with the minimum version set.")

        if minimum_version_vulns:
            # Insert into Neo4j
            print(f"Inserting {len(minimum_version_vulns)} vulnerabilities into Neo4j...")
            insert_all_vulnerabilities_into_neo4j(minimum_version_vulns)
        else:
            print("WARNING: No vulnerabilities remained after version filtering.")

        # End time and summary
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        print(f"\nOSV-Neo4j update completed at {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total execution time: {duration.total_seconds()/60:.2f} minutes")

        # Summary statistics
        print("\nSummary:")
        print(f"- Total vulnerabilities processed: {len(all_vulnerabilities)}")
        print(f"- Vulnerabilities after minimum version filtering: {len(minimum_version_vulns)}")
        print(f"- Reduction ratio: {len(minimum_version_vulns)/len(all_vulnerabilities)*100:.2f}%")
    else:
        print("No vulnerabilities were found to insert.")

if __name__ == "__main__":
    main()
