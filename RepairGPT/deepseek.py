#!/usr/bin/env python3
import logging
import os
import sys
import time
from datetime import datetime
from neo4j import GraphDatabase
import torch

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class RepairGPT:
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="password", 
                 model_name="deepseek-ai/deepseek-coder-1.3b-instruct", severity_threshold=5.0):
        """
        Initialize RepairGPT with configurable parameters
        
        Args:
            neo4j_uri: Connection URI for Neo4j database
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            model_name: Name of the AI model to use for analysis
            severity_threshold: Minimum severity score (0.0-10.0) for vulnerabilities
        """
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.model_name = model_name
        self.severity_threshold = severity_threshold
        self.driver = None
        self.model = None

    def connect_to_neo4j(self):
        """Connect to Neo4j database and verify connection"""
        try:
            self.driver = GraphDatabase.driver(
                self.neo4j_uri, 
                auth=(self.neo4j_user, self.neo4j_password)
            )
            
            # Test connection by counting nodes
            with self.driver.session() as session:
                node_count = session.run("MATCH (n) RETURN count(n) as count").single()["count"]
                logger.info(f"Successfully connected to Neo4j (found {node_count} nodes)")
                
            self.discover_database_schema()
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            return False

    def discover_database_schema(self):
        """Discover the database schema to understand available data"""
        try:
            with self.driver.session() as session:
                # Find node labels
                labels = session.run("CALL db.labels()").value()
                logger.info(f"Found node labels: {', '.join(labels)}")
                
                # Find relationship types
                rel_types = session.run("CALL db.relationshipTypes()").value()
                logger.info(f"Found relationship types: {', '.join(rel_types)}")
                
                # Find property keys
                prop_keys = session.run("CALL db.propertyKeys()").value()
                logger.info(f"Found property keys: {', '.join(prop_keys)}")
                
                # Sample properties from key nodes for better understanding
                for label in ['Repository', 'Version', 'VulnerabilityAnalysis']:
                    result = session.run(f"""
                        MATCH (n:{label}) 
                        WITH n LIMIT 1 
                        RETURN keys(n) as props
                    """).single()
                    if result:
                        logger.info(f"Sample {label} node properties: {result['props']}")
        except Exception as e:
            logger.error(f"Error discovering schema: {e}")

    def initialize_model(self):
        """Initialize the AI model for vulnerability analysis"""
        try:
            logger.info(f"Initializing {self.model_name} model...")
            
            # Determine device (use CUDA if available)
            device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Using device: {device}")
            
            # Here you would initialize your actual model
            # For example with transformers:
            # from transformers import AutoModelForCausalLM, AutoTokenizer
            # self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            # self.model = AutoModelForCausalLM.from_pretrained(self.model_name).to(device)
            
            # Simulating model initialization for this example
            time.sleep(2)  # Simulate model loading time
            self.model = {"name": self.model_name, "device": device}
            
            logger.info("Model initialization complete")
            return True
        except Exception as e:
            logger.error(f"Error initializing model: {e}")
            return False

    def find_vulnerabilities(self, limit=10):
        """
        Find vulnerabilities in the database based on severity threshold
        
        Returns:
            list: List of vulnerability objects or None if error occurs
        """
        try:
            with self.driver.session() as session:
                # First check if severity property exists on vulnerabilities
                has_severity = session.run("""
                    MATCH (v:Vulnerability) 
                    WHERE v.severity IS NOT NULL 
                    RETURN count(v) > 0 as has_severity
                """).single()["has_severity"]
                
                if not has_severity:
                    logger.warning("No vulnerabilities with severity property found. Checking for alternate fields...")
                    # Try to find vulnerabilities using different criteria if severity isn't available
                    vulnerabilities = session.run("""
                        MATCH (v:Vulnerability)
                        RETURN v.id as id, v.headline as headline, 
                               v.cve as cve, v.published as published, 
                               COALESCE(v.classification, 'unknown') as classification
                        LIMIT $limit
                    """, limit=limit).data()
                else:
                    # Find vulnerabilities based on severity threshold
                    logger.info(f"Finding top vulnerabilities with severity >= {self.severity_threshold}...")
                    vulnerabilities = session.run("""
                        MATCH (v:Vulnerability)
                        WHERE v.severity >= $threshold
                        RETURN v.id as id, v.headline as headline, 
                               v.severity as severity, v.cve as cve,
                               v.published as published, 
                               COALESCE(v.classification, 'unknown') as classification
                        ORDER BY v.severity DESC
                        LIMIT $limit
                    """, threshold=self.severity_threshold, limit=limit).data()
                
                if not vulnerabilities:
                    # If no results with current threshold, try with a lower threshold as fallback
                    fallback_threshold = max(0.0, self.severity_threshold - 2.0)
                    logger.info(f"No vulnerabilities found at threshold {self.severity_threshold}. " +
                              f"Trying with lower threshold {fallback_threshold}...")
                    
                    vulnerabilities = session.run("""
                        MATCH (v:Vulnerability)
                        WHERE v.severity >= $threshold
                        RETURN v.id as id, v.headline as headline, 
                               v.severity as severity, v.cve as cve,
                               v.published as published, 
                               COALESCE(v.classification, 'unknown') as classification
                        ORDER BY v.severity DESC
                        LIMIT $limit
                    """, threshold=fallback_threshold, limit=limit).data()
                
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
                return vulnerabilities
        except Exception as e:
            logger.error(f"Error finding vulnerabilities: {e}")
            return None

    def assess_vulnerabilities(self, vulnerabilities):
        """
        Analyze vulnerabilities using the AI model
        
        Args:
            vulnerabilities: List of vulnerability objects
            
        Returns:
            bool: Success/failure of assessment
        """
        if not vulnerabilities:
            logger.warning("No vulnerabilities available for assessment")
            return False
            
        logger.info(f"Starting vulnerability assessment for {len(vulnerabilities)} vulnerabilities")
        
        # Here you would normally process each vulnerability with your AI model
        # For example:
        # for vuln in vulnerabilities:
        #     input_text = f"Analyze vulnerability: {vuln['headline']} (CVE: {vuln['cve']})"
        #     tokenized = self.tokenizer(input_text, return_tensors="pt").to(self.model.device)
        #     output = self.model.generate(**tokenized)
        #     analysis = self.tokenizer.decode(output[0])
        #     vuln['ai_analysis'] = analysis
        
        return True

    def run(self):
        """Main execution function"""
        try:
            logger.info("=== RepairGPT Vulnerability Assessment System ===")
            
            logger.info("Connecting to Neo4j vulnerability database...")
            if not self.connect_to_neo4j():
                return False
                
            if not self.initialize_model():
                return False
                
            vulnerabilities = self.find_vulnerabilities()
            
            # Even if no vulnerabilities found, we continue without error
            if vulnerabilities:
                self.assess_vulnerabilities(vulnerabilities)
                # Additional processing would happen here
            else:
                logger.warning("No vulnerabilities to assess - system continuing with other tasks")
                # Additional tasks could be performed here
                
            return True
            
        except Exception as e:
            logger.error(f"Unhandled exception: {e}")
            return False
        finally:
            if self.driver:
                self.driver.close()
                logger.info("Neo4j connection closed")
            logger.info("RepairGPT execution completed")

def main():
    # Allow configuration via environment variables
    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD", "password")
    model_name = os.environ.get("MODEL_NAME", "deepseek-ai/deepseek-coder-1.3b-instruct")
    severity_threshold = float(os.environ.get("SEVERITY_THRESHOLD", "2.0"))
    
    repair_gpt = RepairGPT(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        model_name=model_name,
        severity_threshold=severity_threshold
    )
    
    success = repair_gpt.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
