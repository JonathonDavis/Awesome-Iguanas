#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from datetime import datetime
from neo4j import GraphDatabase

# Attempt to auto-load Neo4j Aura credentials from the repo-root TXT file.
try:
    REPO_ROOT = Path(__file__).resolve().parents[1]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from neo4j_aura_config import ensure_neo4j_env_loaded

    ensure_neo4j_env_loaded()
except Exception:
    pass

# Neo4j connection details (do not hard-code secrets)
NEO4J_URI = os.environ.get("NEO4J_URI") or os.environ.get("VITE_NEO4J_URI") or "neo4j://localhost:7687"
NEO4J_USER = (
    os.environ.get("NEO4J_USERNAME")
    or os.environ.get("NEO4J_USER")
    or os.environ.get("VITE_NEO4J_USER")
    or "neo4j"
)
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD") or os.environ.get("VITE_NEO4J_PASSWORD") or ""
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE") or os.environ.get("VITE_NEO4J_DATABASE")


def neo4j_session(driver):
    if NEO4J_DATABASE:
        return driver.session(database=NEO4J_DATABASE)
    return driver.session()

def update_tracking_timestamp():
    """Update the UpdateTracking node with current timestamp"""
    if not NEO4J_PASSWORD:
        print("Error: NEO4J_PASSWORD (or VITE_NEO4J_PASSWORD) is not set")
        return

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    try:
        with neo4j_session(driver) as session:
            # Update the UpdateTracking node
            session.run(
                """
                MERGE (t:UpdateTracking)
                SET t.last_update = datetime()
                """
            )

            print(f"Successfully updated UpdateTracking node at {datetime.now().isoformat()}")
    
    except Exception as e:
        print(f"Error updating UpdateTracking node: {e}")
    
    finally:
        driver.close()

if __name__ == "__main__":
    update_tracking_timestamp()