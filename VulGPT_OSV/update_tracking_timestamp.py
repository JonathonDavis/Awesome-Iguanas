#!/usr/bin/env python3
from neo4j import GraphDatabase
import os
from datetime import datetime


def load_env_file(env_file_path):
    if not os.path.exists(env_file_path):
        return
    try:
        with open(env_file_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, value = stripped.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


DEFAULT_ENV_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend", ".env.production")
)
load_env_file(os.environ.get("APP_ENV_FILE", DEFAULT_ENV_PATH))

# Neo4j connection details
NEO4J_URI = os.environ.get("VITE_NEO4J_URI", os.environ.get("NEO4J_URI", "neo4j://localhost:7687"))
NEO4J_USER = os.environ.get("VITE_NEO4J_USER", os.environ.get("NEO4J_USER", "neo4j"))
NEO4J_PASSWORD = os.environ.get("VITE_NEO4J_PASSWORD", os.environ.get("NEO4J_PASSWORD", ""))

def update_tracking_timestamp():
    """Update the UpdateTracking node with current timestamp"""
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    try:
        with driver.session() as session:
            # Update the UpdateTracking node
            result = session.run("""
                MATCH (t:UpdateTracking) 
                SET t.last_update = datetime()
            """)
            
            print(f"Successfully updated UpdateTracking node at {datetime.now()}")
    
    except Exception as e:
        print(f"Error updating UpdateTracking node: {e}")
    
    finally:
        driver.close()

if __name__ == "__main__":
    update_tracking_timestamp()
