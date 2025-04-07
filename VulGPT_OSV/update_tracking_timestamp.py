#!/usr/bin/env python3
from neo4j import GraphDatabase

# Neo4j connection details
NEO4J_URI = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "jaguarai"

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