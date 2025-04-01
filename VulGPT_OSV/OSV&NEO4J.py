import os
import json
import gc
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from neo4j import GraphDatabase

# -------------------------
# CONFIGURATION
# -------------------------
NEO4J_URI = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "jaguarai"

# Path to the directory containing the unzipped OSV JSON files
LOCAL_OSV_DIR = "/mnt/disk-2/OSV-db"

# Batch size for Neo4j insertions (number of vulnerability records per transaction)
BATCH_SIZE = 100

# Number of JSON files to process per batch (to keep memory usage in check)
PROCESSING_BATCH_SIZE = 100

# Number of threads for parallel file reading
MAX_WORKERS = 8

# -------------------------
# FUNCTIONS
# -------------------------
def read_json(file_path):
    """Reads a single JSON file and returns its contents as a dictionary."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return None

def process_vulnerabilities_in_batches(osv_dir, processing_batch_size=PROCESSING_BATCH_SIZE, max_workers=MAX_WORKERS):
    """
    Processes JSON files in the specified directory in batches.
    Yields a list of vulnerability records from each batch.
    """
    files = [os.path.join(osv_dir, f) for f in os.listdir(osv_dir) if f.endswith(".json")]
    print(f"Found {len(files)} JSON files in the directory.")
    total_files = len(files)

    for i in range(0, total_files, processing_batch_size):
        current_batch_files = files[i : i + processing_batch_size]
        vulnerabilities = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Show progress as the files in the current batch are processed
            results = list(tqdm(executor.map(read_json, current_batch_files),
                                  total=len(current_batch_files),
                                  desc=f"Processing files {i+1}-{i+len(current_batch_files)}"))
            vulnerabilities.extend([v for v in results if v is not None])
        yield vulnerabilities

def batch_insert_vulnerabilities(session, vuln_records, batch_size=BATCH_SIZE):
    total = len(vuln_records)
    if total == 0:
        return

    print(f"Inserting {total} vulnerabilities into Neo4j in sub-batches of {batch_size}...")
    processed_vuln_ids = set()
    for i in tqdm(range(0, total, batch_size), desc="Inserting batches"):
        batch = vuln_records[i:i + batch_size]
        tx = session.begin_transaction()
        for vuln in batch:
            vuln_id = vuln.get("id")
            if not vuln_id or vuln_id in processed_vuln_ids:
                continue
            processed_vuln_ids.add(vuln_id)

            # Merge the Vulnerability node (creates or updates)
            props = {
                "details": vuln.get("details"),
                "modified": vuln.get("modified"),
                "published": vuln.get("published")
            }
            tx.run(
                "MERGE (v:Vulnerability {id: $vuln_id}) SET v += $props",
                vuln_id=vuln_id,
                props=props
            )

            for related_id in vuln.get("related", []):
                tx.run(
                    """
                    MERGE (r:CVE {id: $related_id})
                    MERGE (v:Vulnerability {id: $vuln_id})
                    MERGE (v)-[:RELATED_TO]->(r)
                    """,
                    related_id=related_id,
                    vuln_id=vuln_id
                )

            for ref in vuln.get("references", []):
                ref_url = ref.get("url")
                ref_type = ref.get("type")
                if ref_url and ref_type:
                    unique_key = f"{ref_url}:{ref_type}"  # Create a composite key
                    tx.run(
                        """
                        MERGE (ref:Reference {unique_key: $unique_key})
                        ON CREATE SET ref.url = $ref_url, ref.type = $ref_type
                        MERGE (v:Vulnerability {id: $vuln_id})
                        MERGE (v)-[:HAS_REFERENCE]->(ref)
                        """,
                        unique_key=unique_key,
                        ref_url=ref_url,
                        ref_type=ref_type,
                        vuln_id=vuln_id
                    )

            for affected_pkg in vuln.get("affected", []):
                package = affected_pkg.get("package", {})
                pkg_name = package.get("name")
                pkg_ecosystem = package.get("ecosystem")
                pkg_purl = package.get("purl")
                if pkg_name and pkg_ecosystem and pkg_purl:
                    tx.run(
                        """
                        MERGE (pkg:Package {purl: $pkg_purl})
                        ON CREATE SET pkg.name = $pkg_name, pkg.ecosystem = $pkg_ecosystem
                        MERGE (v:Vulnerability {id: $vuln_id})
                        MERGE (v)-[:AFFECTS]->(pkg)
                        """,
                        pkg_name=pkg_name,
                        pkg_ecosystem=pkg_ecosystem,
                        pkg_purl=pkg_purl,
                        vuln_id=vuln_id
                    )
        tx.commit()

def ensure_uniqueness_constraints(driver):
    """
    Sets up regular uniqueness constraints for Neo4j Community Edition.
    """
    with driver.session() as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (r:CVE) REQUIRE r.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (pkg:Package) REQUIRE pkg.purl IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (ref:Reference) REQUIRE ref.unique_key IS UNIQUE")

def main():
    total_processed = 0
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # Ensure that the Neo4j database enforces node uniqueness
    ensure_uniqueness_constraints(driver)

    with driver.session() as session:
        for vulnerabilities_batch in process_vulnerabilities_in_batches(LOCAL_OSV_DIR):
            if vulnerabilities_batch:
                batch_insert_vulnerabilities(session, vulnerabilities_batch, batch_size=BATCH_SIZE)
                total_processed += len(vulnerabilities_batch)
                print(f"Total vulnerabilities processed so far: {total_processed}")
                # Force garbage collection to free up memory for the next batch
                gc.collect()
            else:
                print("Current batch contained no vulnerabilities.")
    driver.close()
    print("Vulnerability ingestion completed.")

# -------------------------
# MAIN EXECUTION
# -------------------------
if __name__ == "__main__":
    main()
