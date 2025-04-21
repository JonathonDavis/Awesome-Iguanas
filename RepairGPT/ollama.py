from neo4j import GraphDatabase
import difflib
from collections import Counter
import logging
import os
import sys
import argparse
import json
import requests
from tqdm import tqdm

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("repairgpt.log")
    ]
)
logger = logging.getLogger("RepairGPT")


class RepairGPT:
    """
    A system that uses Neo4j graph database and LLMs to detect and repair memory safety issues in code.
    Compatible with both Joern and CVE-based database schemas.
    """
    
    def __init__(self, neo4j_uri="bolt://localhost:7687",
                 neo4j_user="neo4j",
                 neo4j_password="jaguarai",
                 ollama_model="codellama",
                 ollama_url="http://localhost:11434"):
        """
        Initialize RepairGPT with Neo4j connection and Ollama model.

        Args:
            neo4j_uri (str): URI for Neo4j database connection
            neo4j_user (str): Neo4j username
            neo4j_password (str): Neo4j password
            ollama_model (str): Name of the Ollama model to use
            ollama_url (str): URL for the Ollama API server
        """
        # Store configuration
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        
        # Initialize counters and settings
        self.repair_attempts = {}
        self.max_sequence_length = 2048
        self.db_schema = {}
        
        # Connect to Neo4j and initialize model
        self._connect_to_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        self._discover_schema()
        self._check_ollama_connection()

    def _connect_to_neo4j(self, uri: str, user: str, password: str) -> None:
        """
        Establish connection to Neo4j database.

        Args:
            uri (str): URI for Neo4j database connection
            user (str): Neo4j username
            password (str): Neo4j password

        Raises:
            Exception: If the connection to Neo4j fails
        """
        logger.info("Connecting to Neo4j database...")

        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))

            # Verify the connection
            with self.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                logger.info(f"Successfully connected to Neo4j (found {count} nodes)")

        except Exception as e:
            logger.error(f"Neo4j connection error: {str(e)}")
            raise

    def _check_ollama_connection(self):
        """Verify that Ollama API is accessible and the model is available."""
        logger.info(f"Checking Ollama API connection at {self.ollama_url}...")
        
        try:
            # Check if Ollama server is running
            response = requests.get(f"{self.ollama_url}/api/tags")
            
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [model.get('name') for model in models]
                logger.info(f"Available Ollama models: {model_names}")
                
                if self.ollama_model not in model_names:
                    logger.warning(f"Model '{self.ollama_model}' not found in available models.")
                    logger.info(f"You may need to run: ollama pull {self.ollama_model}")
                else:
                    logger.info(f"Ollama model '{self.ollama_model}' is available")
            else:
                logger.warning(f"Ollama API returned status code {response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"Failed to connect to Ollama API: {str(e)}")
            logger.info("Make sure Ollama is running with: ollama serve")
            logger.info("You may need to install Ollama from https://ollama.ai")

    def _discover_schema(self):
        """Discover the actual schema of the connected Neo4j database."""
        logger.info("Discovering database schema...")

        # Initialize schema structure
        self.db_schema = {
            "labels": [],
            "relationships": [],
            "properties": []
        }

        try:
            with self.driver.session() as session:
                # Use db.schema() procedure to discover schema (Neo4j 4.0+)
                try:
                    result = session.run(
                        "CALL db.schema.visualization() YIELD nodes, relationships "
                        "RETURN nodes, relationships"
                    )
                    record = result.single()
                    
                    if record:
                        for node in record["nodes"]:
                            self.db_schema["labels"].append(node["name"])
                        
                        for rel in record["relationships"]:
                            self.db_schema["relationships"].append(rel["type"])
                except Exception:
                    # Fallback to simpler schema detection method
                    logger.info("Falling back to manual schema discovery")
                    
                    # Get node labels
                    result = session.run("CALL db.labels()")
                    self.db_schema["labels"] = [record["label"] for record in result]
                    
                    # Get relationship types
                    result = session.run("CALL db.relationshipTypes()")
                    self.db_schema["relationships"] = [record["relationshipType"] for record in result]
                    
                    # Get property keys
                    result = session.run("CALL db.propertyKeys()")
                    self.db_schema["properties"] = [record["propertyKey"] for record in result]

            # Log discovered schema
            logger.info(f"Database schema: {len(self.db_schema['labels'])} node labels, "
                        f"{len(self.db_schema['relationships'])} relationship types")
            
            # Determine if schema is Joern-based, CVE-based, or unknown
            if "CALL" in self.db_schema["labels"] and "AST" in self.db_schema["relationships"]:
                self.schema_type = "joern"
                logger.info("Detected Joern-based CPG schema")
            elif "Vulnerability" in self.db_schema["labels"] and "Function" in self.db_schema["labels"]:
                self.schema_type = "cve"
                logger.info("Detected CVE-based vulnerability schema")
            else:
                self.schema_type = "unknown"
                logger.info("Unknown database schema - will try multiple query strategies")

        except Exception as e:
            logger.error(f"Schema discovery error: {str(e)}")
            self.schema_type = "unknown"
            logger.info("Will try multiple query strategies due to schema discovery failure")

    def close(self):
        """Clean up resources and connections."""
        if hasattr(self, 'driver'):
            try:
                self.driver.close()
                logger.info("Neo4j connection closed")
            except Exception as e:
                logger.error(f"Error closing Neo4j connection: {str(e)}")

    def detect_memory_safety_issues(self):
        """
        Detect memory safety issues in the codebase by querying Neo4j.
        
        Returns:
            A list of memory safety issues found in the codebase
        """
        logger.info("Analyzing code for memory safety issues...")
        results = []
        
        try:
            with self.driver.session() as session:
                # Choose query strategy based on schema type
                if self.schema_type == "joern":
                    results = self._detect_issues_joern(session)
                elif self.schema_type == "cve":
                    results = self._detect_issues_cve(session)
                else:
                    # Try both strategies
                    logger.info("Trying multiple query strategies...")
                    results = self._detect_issues_cve(session)
                    if not results:
                        results = self._detect_issues_joern(session)
                    
        except Exception as e:
            logger.error(f"Error in memory safety analysis: {str(e)}")
            
        # Log the results
        if results:
            logger.info(f"Found {len(results)} potential memory safety issues")
        else:
            logger.info("No memory safety issues detected")
            
        return results

    def _detect_issues_joern(self, session):
        """
        Detect memory safety issues using Joern CPG schema.
        
        Args:
            session: Neo4j database session
            
        Returns:
            List of detected issues
        """
        logger.info("Using Joern CPG schema for issue detection")
        
        results = []
        
        # Query for unsafe function calls
        query = """
        MATCH (c:CALL)
        WHERE c.METHOD_FULL_NAME IN [
            'malloc', 'free', 'strcpy', 'strncpy', 'sprintf',
            'gets', 'memcpy', 'realloc', 'alloca', 'fgets'
        ]
        OPTIONAL MATCH (c)-[:AST*]->(b:BLOCK)
        OPTIONAL MATCH (c)-[:CONTAINS]->(param:IDENTIFIER)
        OPTIONAL MATCH (c)-[:AST*]->(file:FILE)
        RETURN c.METHOD_FULL_NAME as function,
               c.CODE as code,
               c.LINE_NUMBER as line,
               collect(DISTINCT b.CODE) as context,
               collect(DISTINCT param.CODE) as parameters,
               file.NAME as file_name
        """
        
        try:
            results_data = session.run(query).data()
            
            for r in results_data:
                # Format context as single string
                context_str = "\n".join(filter(None, r.get('context', [])))
                
                results.append({
                    'id': f"line-{r.get('line', 'unknown')}",
                    'function': r.get('function', 'unknown'),
                    'code': r.get('code', ''),
                    'line': r.get('line'),
                    'file': r.get('file_name'),
                    'context': context_str,
                    'parameters': r.get('parameters', [])
                })
                
        except Exception as e:
            logger.error(f"Error in Joern query: {str(e)}")
            
        return results

    def _detect_issues_cve(self, session):
        """
        Detect memory safety issues using CVE-based schema.
        
        Args:
            session: Neo4j database session
            
        Returns:
            List of detected issues
        """
        logger.info("Using CVE schema for issue detection")
        
        results = []
        
        # First, verify if Function nodes actually exist in the database
        function_nodes_exist = False
        try:
            count_query = "MATCH (f:Function) RETURN count(f) as count LIMIT 1"
            count_result = session.run(count_query).single()
            function_nodes_exist = count_result and count_result["count"] > 0
            logger.info(f"Function nodes exist: {function_nodes_exist}")
        except Exception as e:
            logger.warning(f"Error checking for Function nodes: {str(e)}")
            function_nodes_exist = False
        
        if function_nodes_exist:
            # Original approach with Function nodes
            try:
                # Query for memory safety vulnerabilities
                query = """
                MATCH (v:Vulnerability)-[:CONCERNS_FUNCTION]->(f:Function)
                WHERE v.Type CONTAINS 'memory' OR v.Summary CONTAINS 'buffer' OR
                    v.Summary CONTAINS 'overflow' OR v.Summary CONTAINS 'use-after-free' OR
                    v.Summary CONTAINS 'malloc' OR v.Summary CONTAINS 'free' OR
                    v.Summary CONTAINS 'memcpy' OR v.Summary CONTAINS 'strcpy'
                RETURN v.Id as vulnerability_id,
                    v.Summary as summary,
                    f.Name as function_name,
                    f.Details as code,
                    id(f) as function_id
                LIMIT 25
                """
                
                vulnerability_results = session.run(query).data()
                
                if vulnerability_results:
                    logger.info(f"Found {len(vulnerability_results)} memory safety vulnerabilities")
                    
                    for vuln in vulnerability_results:
                        if vuln.get('code'):
                            results.append({
                                'vulnerability_id': vuln.get('vulnerability_id'),
                                'summary': vuln.get('summary'),
                                'function': vuln.get('function_name'),
                                'code': vuln.get('code'),
                                'id': vuln.get('function_id'),
                                'context': []
                            })
                
                # If no results, try alternative query focusing on function names
                if not results:
                    logger.info("Trying alternative approach based on function names...")
                    query = """
                    MATCH (f:Function)
                    WHERE f.Name IN [
                        'malloc', 'free', 'strcpy', 'strncpy', 'sprintf',
                        'gets', 'memcpy', 'realloc', 'alloca', 'fgets'
                    ] OR f.Name CONTAINS 'memcpy' OR f.Name CONTAINS 'strcpy'
                    RETURN f.Name as function,
                        f.Details as code,
                        id(f) as id
                    LIMIT 25
                    """
                    
                    function_results = session.run(query).data()
                    
                    if function_results:
                        for func in function_results:
                            if func.get('code'):
                                results.append({
                                    'function': func.get('function'),
                                    'code': func.get('code'),
                                    'id': func.get('id'),
                                    'context': [] 
                                })
            except Exception as e:
                logger.error(f"Error in CVE schema query: {str(e)}")
        
        # If we still have no results, try using generic node queries with code-based detection
        if not results:
            logger.info("Trying generic code content approach...")
            try:
                # Look for any nodes that might contain code with memory functions
                generic_query = """
                MATCH (n)
                WHERE (n.code IS NOT NULL OR n.CODE IS NOT NULL OR n.Details IS NOT NULL OR n.source IS NOT NULL) 
                AND (
                    toString(n.code) CONTAINS 'malloc' OR 
                    toString(n.CODE) CONTAINS 'malloc' OR
                    toString(n.Details) CONTAINS 'malloc' OR
                    toString(n.source) CONTAINS 'malloc' OR
                    toString(n.code) CONTAINS 'strcpy' OR
                    toString(n.CODE) CONTAINS 'strcpy' OR
                    toString(n.Details) CONTAINS 'strcpy' OR
                    toString(n.source) CONTAINS 'strcpy' OR
                    toString(n.code) CONTAINS 'memcpy' OR
                    toString(n.CODE) CONTAINS 'memcpy' OR
                    toString(n.Details) CONTAINS 'memcpy' OR
                    toString(n.source) CONTAINS 'memcpy'
                )
                RETURN labels(n) as node_type,
                    COALESCE(n.code, n.CODE, n.Details, n.source) as code,
                    id(n) as id,
                    COALESCE(n.name, n.Name, n.METHOD_FULL_NAME, n.filename, '') as name
                LIMIT 25
                """
                
                generic_results = session.run(generic_query).data()
                
                if generic_results:
                    logger.info(f"Found {len(generic_results)} nodes with potential memory safety issues")
                    
                    for node in generic_results:
                        code = node.get('code')
                        if code and isinstance(code, str):
                            results.append({
                                'function': node.get('name', 'Unknown'),
                                'code': code,
                                'id': node.get('id'),
                                'node_type': node.get('node_type', []),
                                'context': []
                            })
            except Exception as e:
                logger.error(f"Error in generic code query: {str(e)}")
                
        return results

    def analyze_codebase(self):
        """
        Analyze overall codebase structure from Neo4j.
        
        Returns:
            Dict containing analysis of code structure
        """
        logger.info("Analyzing codebase structure...")

        analysis = {
            "schema": self.db_schema,
            "schema_type": self.schema_type
        }
        
        try:
            with self.driver.session() as session:
                if self.schema_type == "joern":
                    # For Joern schema
                    queries = {
                        "languages": """
                            MATCH (f:FILE)
                            RETURN f.LANGUAGE as language, count(*) as count
                            ORDER BY count DESC
                            LIMIT 10
                        """,
                        "methods": """
                            MATCH (m:METHOD)
                            RETURN count(m) as method_count
                        """,
                        "calls": """
                            MATCH (c:CALL)
                            RETURN c.METHOD_FULL_NAME as function, count(*) as count
                            ORDER BY count DESC
                            LIMIT 15
                        """
                    }
                else:
                    # For CVE or unknown schema
                    queries = {
                        "vulnerabilities": """
                            MATCH (v:Vulnerability)
                            RETURN count(v) as vuln_count
                        """,
                        "functions": """
                            MATCH (f:Function)
                            RETURN count(f) as function_count
                        """,
                        "packages": """
                            MATCH (p:Package)
                            RETURN p.Name as name, count(*) as count
                            ORDER BY count DESC
                            LIMIT 10
                        """
                    }
                
                # Execute queries
                for key, query in queries.items():
                    try:
                        analysis[key] = session.run(query).data()
                    except Exception as e:
                        logger.warning(f"Query '{key}' failed: {str(e)}")
                        analysis[key] = []
                
        except Exception as e:
            logger.error(f"Error analyzing codebase: {str(e)}")

        # Log summary
        logger.info("Codebase analysis complete")
        return analysis

    def generate_safety_patch(self, vulnerable_code, context=""):
        """
        Generate a memory-safe patch using Ollama.
        
        Args:
            vulnerable_code: The code containing the vulnerability
            context: Surrounding code context for better understanding
                
        Returns:
            String containing the patched code or None if generation failed
        """
        if not vulnerable_code:
            logger.warning("Cannot generate patch: No code provided")
            return None
                
        logger.info("Generating safety patch using Ollama")
            
        try:
            # Create system prompt for the LLM
            system_prompt = """You are a memory safety expert. Generate a secure patch considering:
- Buffer overflow prevention
- Proper bounds checking
- Memory initialization
- Pointer validation
- Resource cleanup
Return ONLY the fixed code without explanations."""

            # Add specific guidance based on detected function
            if "fgets" in vulnerable_code:
                system_prompt += "\nFor fgets calls, ensure:\n- Buffer size is checked\n- Newline handling is safe\n- Input validation"
            elif "malloc" in vulnerable_code:
                system_prompt += "\nFor malloc calls, ensure:\n- Null pointer checks\n- Proper size calculation\n- Error handling"
            elif "strcpy" in vulnerable_code:
                system_prompt += "\nFor strcpy calls, replace with safer alternatives like strncpy with proper size checks"

            # Truncate inputs if too long
            max_context_len = self.max_sequence_length // 4
            max_code_len = self.max_sequence_length // 2
            
            context = context[:max_context_len] if context else ""
            vulnerable_code = vulnerable_code[:max_code_len]

            # Prepare messages for Ollama
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Vulnerable code:\n```c\n{vulnerable_code}\n```\n" +
                                        (f"Code context:\n```c\n{context}\n```\n" if context else "") +
                                        "Provide safe version:"}
            ]

            # Send request to Ollama API
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": messages,
                    "options": {
                        "temperature": 0.3,
                        "top_p": 0.9
                    }
                }
            )

            if response.status_code == 200:
                result = response.json()
                patch = result.get('message', {}).get('content', '')
                clean_patch = self._clean_patch(patch)
                
                logger.info("Patch generation successful")
                return clean_patch
            else:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.RequestException as e:
            logger.error(f"Error communicating with Ollama API: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error generating patch: {str(e)}")
            return None

    def validate_patch(self, original_code, patched_code):
        """
        Validate patch using static analysis and differential testing.
        
        Args:
            original_code: The original vulnerable code
            patched_code: The generated patched code
                
        Returns:
            Dict containing validation results
        """
        if patched_code is None:
            logger.warning("Cannot validate: patch generation failed")
            return {
                "sanitizers_clean": False, 
                "semantic_equivalence": False,
                "safety_checks": {
                    "buffer_check": False,
                    "null_check": False,
                    "bounds_check": False,
                    "has_changes": False
                }
            }

        # Step 1: Basic semantic validation using code diffs
        diff = difflib.ndiff(original_code.splitlines(), patched_code.splitlines())
        diff_lines = list(diff)
        has_changes = any(line.startswith('+') or line.startswith('-') for line in diff_lines)
        
        # Count significant changes
        added = sum(1 for line in diff_lines if line.startswith('+') and not line[1:].isspace())
        removed = sum(1 for line in diff_lines if line.startswith('-') and not line[1:].isspace())

        # Step 2: Basic safety checks
        safety_checks = {
            "buffer_check": "sizeof" in patched_code and not ("sizeof" in original_code),
            "null_check": ("NULL" in patched_code or "null" in patched_code) and not ("NULL" in original_code or "null" in original_code),
            "bounds_check": any(op in patched_code for op in ["<=", ">=", "<", ">"]) and not any(op in original_code for op in ["<=", ">=", "<", ">"]),
            "has_changes": has_changes,
            "significant_changes": added + removed > 0
        }

        # Calculate overall validity
        sanitizers_clean = safety_checks["significant_changes"] and (
            safety_checks["buffer_check"] or 
            safety_checks["null_check"] or 
            safety_checks["bounds_check"]
        )
        
        semantic_equivalence = has_changes and ("return" in original_code) == ("return" in patched_code)

        validation_result = {
            "sanitizers_clean": sanitizers_clean,
            "semantic_equivalence": semantic_equivalence,
            "safety_checks": safety_checks,
            "diff_stats": {
                "added_lines": added,
                "removed_lines": removed
            }
        }
        
        logger.info(f"Patch validation: sanitizers_clean={validation_result['sanitizers_clean']}, "
                f"semantic_equivalence={validation_result['semantic_equivalence']}")
        
        return validation_result  

    def _clean_patch(self, patch):
        """
        Remove markdown formatting from generated patch.
        
        Args:
            patch: Raw patch text from model
                
        Returns:
            Cleaned patch code
        """
        # Remove code block markers and extra whitespace
        cleaned = patch.replace("```c", "").replace("```cpp", "").replace("```", "").strip()
        
        # Remove common explanation prefixes
        prefixes = [
            "Here's the fixed code:", 
            "Fixed code:", 
            "Secure version:",
            "Here is the patched code:",
            "The patched code:"
        ]
        
        for prefix in prefixes:
            if cleaned.lower().startswith(prefix.lower()):
                cleaned = cleaned[len(prefix):].strip()
                    
        return cleaned

    def _update_failure_context(self, vuln, patch, validation):
        """
        Store failure context for model feedback.
        
        Args:
            vuln: The vulnerability info
            patch: The generated patch
            validation: Validation results
        """
        if not hasattr(self, 'repair_attempts'):
            self.repair_attempts = {}
                
        # Store attempt data keyed by vulnerability ID or function ID
        key = vuln.get('vulnerability_id', vuln.get('id', 'unknown'))
        self.repair_attempts.setdefault(key, []).append({
            "patch": patch,
            "validation": validation
        })

    def repair_cycle(self, max_attempts=3):
        """
        Run the full cycle of detecting memory safety issues and repairing them.
        
        Args:
            max_attempts: Maximum number of repair attempts per issue
                
        Returns:
            List of repair results
        """
        logger.info(f"Starting repair cycle with max {max_attempts} attempts per issue...")
        
        # Step 1: Detect memory safety issues
        issues = self.detect_memory_safety_issues()
        if not issues:
            logger.info("No memory safety issues detected to repair")
            return []
        
        # Step 2: Repair each issue
        repair_results = []
        
        for issue in tqdm(issues, desc="Repairing issues"):
            # Get essential issue details
            issue_id = issue.get('vulnerability_id', issue.get('id', 'unknown'))
            issue_function = issue.get('function', 'unknown function')
            issue_code = issue.get('code', '')
            issue_context = issue.get('context', '')
            if isinstance(issue_context, list):
                issue_context = '\n'.join(issue_context)
            
            logger.info(f"Attempting to repair issue {issue_id} in {issue_function}")
            
            # Track attempts for this specific issue
            attempts = 0
            best_patch = None
            best_validation = None
            
            while attempts < max_attempts:
                attempts += 1
                logger.info(f"  Attempt {attempts}/{max_attempts}")
                
                # Generate patch
                patch = self.generate_safety_patch(issue_code, issue_context)
                
                if not patch:
                    logger.warning(f"  Failed to generate patch on attempt {attempts}")
                    continue
                    
                # Validate patch
                validation = self.validate_patch(issue_code, patch)
                
                # Track best patch based on validation scores
                if best_validation is None or (
                    validation['sanitizers_clean'] and not best_validation['sanitizers_clean']
                ) or (
                    validation['sanitizers_clean'] == best_validation['sanitizers_clean'] and
                    validation['semantic_equivalence'] and not best_validation['semantic_equivalence']
                ):
                    best_patch = patch
                    best_validation = validation
                    
                # If patch is good enough, we can stop attempts
                if validation['sanitizers_clean'] and validation['semantic_equivalence']:
                    logger.info(f"  Found valid patch on attempt {attempts}")
                    break
                    
                # Update failure context for better next attempt
                self._update_failure_context(issue, patch, validation)
            
            # Determine final status
            if best_validation and best_validation['sanitizers_clean'] and best_validation['semantic_equivalence']:
                status = 'success'
            elif best_validation and (best_validation['sanitizers_clean'] or best_validation['semantic_equivalence']):
                status = 'partial'
            else:
                status = 'failed'
                
            # Record repair result
            result = {
                'issue_id': issue_id,
                'function': issue_function,
                'original_code': issue_code,
                'patched_code': best_patch,
                'validation': best_validation,
                'attempts': attempts,
                'status': status
            }
            
            repair_results.append(result)
            logger.info(f"Repair status for {issue_id}: {status}")
        
        # Log overall results
        success_count = sum(1 for r in repair_results if r['status'] == 'success')
        logger.info(f"Repair cycle complete: {success_count}/{len(repair_results)} successful repairs")
        
        return repair_results

    def generate_report(self, repair_results):
        """
        Generate a comprehensive report of repair actions.
        
        Args:
            repair_results: Results from the repair cycle
            
        Returns:
            Dict containing report data
        """
        total = len(repair_results)
        successful = sum(1 for r in repair_results if r.get('status') == 'success')
        partial = sum(1 for r in repair_results if r.get('status') == 'partial')
        failed = sum(1 for r in repair_results if r.get('status') == 'failed')
        
        report = {
            "summary": {
                "total_vulnerabilities": total,
                "successful_repairs": successful,
                "partial_repairs": partial,
                "failed_repairs": failed,
                "success_rate": successful / total if total > 0 else 0,
                "database_schema": self.db_schema
            },
            "details": repair_results
        }
        
        logger.info(f"Repair report: {successful}/{total} successful, {partial}/{total} partial, {failed}/{total} failed")
        return report


def main():
    """Main entry point for the RepairGPT system."""
    
    # Set up argument parser for command line options
    parser = argparse.ArgumentParser(description="RepairGPT - Automatic memory safety repair tool")

    # Neo4j connection settings
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j database URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="jaguarai", help="Neo4j password")
    
    # LLM settings
    parser.add_argument("--model", default="codellama", help="Ollama model to use")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
    
    # Repair options
    parser.add_argument("--max-attempts", type=int, default=3, help="Maximum repair attempts per issue")
    parser.add_argument("--output", default="repair_report.json", help="Output report filename")
    parser.add_argument("--analyze-only", action="store_true", help="Only analyze issues without repair")
    
    args = parser.parse_args()
    
    try:
        # Initialize RepairGPT
        logger.info("Initializing RepairGPT...")
        repair_system = RepairGPT(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password,
            ollama_model=args.model,
            ollama_url=args.ollama_url
        )
        
        # Perform codebase analysis
        codebase_analysis = repair_system.analyze_codebase()
        logger.info("Codebase analysis complete")
        
        # Detect memory safety issues
        if args.analyze_only:
            # Just detect and report issues without repair
            issues = repair_system.detect_memory_safety_issues()
            logger.info(f"Analysis complete: found {len(issues)} potential memory safety issues")
            
            # Save issues to file
            with open(args.output, 'w') as f:
                json.dump({
                    "detected_issues": issues,
                    "codebase_analysis": codebase_analysis
                }, f, indent=2)
            
            logger.info(f"Analysis results saved to {args.output}")
        else:
            # Full repair cycle
            repair_results = repair_system.repair_cycle(max_attempts=args.max_attempts)
            
            # Generate and save report
            report = repair_system.generate_report(repair_results)
            
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Repair report saved to {args.output}")
            
        # Clean up
        repair_system.close()
        
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
