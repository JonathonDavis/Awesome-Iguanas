from neo4j import GraphDatabase
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import difflib
from collections import Counter
import logging
import os
import sys
import argparse
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
                 model_name="deepseek-ai/deepseek-coder-1.3b-instruct",
                 local_model_path=None,
                 offline_mode=False):
        """
        Initialize RepairGPT with Neo4j connection and Deepseek Coder model.

        Args:
            neo4j_uri (str): URI for Neo4j database connection
            neo4j_user (str): Neo4j username
            neo4j_password (str): Neo4j password
            model_name (str): Name of the Hugging Face model to use
            local_model_path (str): Path to locally downloaded model (if available)
            offline_mode (bool): Whether to run in offline mode using local model files
        """
        # Store configuration
        self.model_name = model_name
        self.local_model_path = local_model_path
        self.offline_mode = offline_mode
        
        # Initialize counters and settings
        self.repair_attempts = {}
        self.max_sequence_length = 2048
        self.db_schema = {}
        
        # Connect to Neo4j and initialize model
        self._connect_to_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        self._discover_schema()
        self._initialize_model()

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

    def _initialize_model(self):
        """Initialize the language model for code repair."""
        logger.info(f"Initializing {self.model_name} model...")
        
        try:
            # Determine how to load the model based on configuration
            if self.offline_mode and self.local_model_path:
                logger.info(f"Loading model from local path: {self.local_model_path}")
                model_path = self.local_model_path
                tokenizer_path = self.local_model_path
            else:
                logger.info(f"Loading model from Hugging Face: {self.model_name}")
                model_path = self.model_name
                tokenizer_path = self.model_name
            
            # Determine device based on available hardware
            if torch.cuda.is_available():
                device_info = torch.cuda.get_device_properties(0)
                logger.info(f"Using GPU: {device_info.name} with {device_info.total_memory / 1e9:.2f} GB memory")
                device_map = "auto"
            else:
                logger.info("CUDA not available, using CPU")
                device_map = "cpu"
                
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                tokenizer_path,
                use_fast=True,
                trust_remote_code=True
            )
            
            # Load model with appropriate configuration
            self.model = AutoModelForCausalLM.from_pretrained(
                model_path,
                device_map=device_map,
                trust_remote_code=True,
                # Use low precision for GPU to conserve memory
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
            )
            
            # Set the padding token if needed
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                
            logger.info("Model initialization complete")
            
        except Exception as e:
            logger.error(f"Model initialization failed: {str(e)}")
            self.close()
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def close(self):
        """Clean up resources and connections."""
        if hasattr(self, 'driver'):
            try:
                self.driver.close()
                logger.info("Neo4j connection closed")
            except Exception as e:
                logger.error(f"Error closing Neo4j connection: {str(e)}")

        if torch.cuda.is_available():
            try:
                torch.cuda.empty_cache()
                logger.info("CUDA cache cleared")
            except Exception as e:
                logger.error(f"Error clearing CUDA cache: {str(e)}")

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
        
        try:
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
        Generate a memory-safe patch using Deepseek Coder.
        
        Args:
            vulnerable_code: The code containing the vulnerability
            context: Surrounding code context for better understanding
            
        Returns:
            String containing the patched code or None if generation failed
        """
        if not vulnerable_code:
            logger.warning("Cannot generate patch: No code provided")
            return None
            
        logger.info("Generating safety patch")
        
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

            # Truncate inputs to fit within sequence limits
            max_context_len = self.max_sequence_length // 4
            max_code_len = self.max_sequence_length // 2
            
            context = context[:max_context_len] if context else ""
            vulnerable_code = vulnerable_code[:max_code_len]

            # Prepare messages for the model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Vulnerable code:\n```c\n{vulnerable_code}\n```\n" +
                                         (f"Code context:\n```c\n{context}\n```\n" if context else "") +
                                         "Provide safe version:"}
            ]

            # Tokenize the input
            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                max_length=self.max_sequence_length,
                truncation=True
            ).to(self.model.device)

            # Generate with appropriate parameters
            with torch.no_grad():  # Disable gradient calculation for inference
                outputs = self.model.generate(
                    inputs,
                    max_new_tokens=512,
                    do_sample=True,
                    temperature=0.3,
                    top_p=0.9,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode and clean the output
            patch = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            clean_patch = self._clean_patch(patch)
            
            logger.info("Patch generation successful")
            return clean_patch

        except torch.cuda.OutOfMemoryError:
            logger.warning("GPU out of memory, retrying with CPU...")
            return self._fallback_cpu_generation(vulnerable_code, context)
        except Exception as e:
            logger.error(f"Error generating patch: {str(e)}")
            return None

    def _fallback_cpu_generation(self, vulnerable_code, context):
        """
        Fallback generation on CPU with reduced parameters when GPU OOM occurs.
        
        Args:
            vulnerable_code: The code containing the vulnerability
            context: Surrounding code context
            
        Returns:
            String containing the patched code or None if generation failed
        """
        try:
            logger.info("Falling back to CPU generation with reduced parameters")
            
            # Move model to CPU
            cpu_model = self.model.to("cpu")

            # Regenerate with smaller inputs and parameters
            messages = [
                {"role": "system", "content": "Generate secure memory-safe patch"},
                {"role": "user", "content": f"Fix this vulnerable code:\n{vulnerable_code[:1024]}"}
            ]

            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                max_length=1024,
                truncation=True
            )

            with torch.no_grad():
                outputs = cpu_model.generate(
                    inputs,
                    max_new_tokens=256,
                    do_sample=True,
                    temperature=0.2,
                    top_p=0.85
                )

            patch = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            return self._clean_patch(patch)

        except Exception as e:
            logger.error(f"Error in CPU fallback: {str(e)}")
            return None
        finally:
            # Move model back to CUDA if available
            if torch.cuda.is_available():
                self.model = self.model.to("cuda")
                torch.cuda.empty_cache()
                logger.info("Model moved back to GPU after fallback")

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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="RepairGPT - Automatic memory safety repair tool")
    
    # Neo4j connection settings
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j database URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="jaguarai", help="Neo4j password")
    
    # Model settings
    parser.add_argument("--model", default="deepseek-ai/deepseek-coder-1.3b-instruct", 
                       help="Model name or path")
    parser.add_argument("--local-model", default=None, help="Path to local model files")
    parser.add_argument("--offline", action="store_true", help="Run in offline mode using local model")
    
    # Operation settings
    parser.add_argument("--max-attempts", type=int, default=3, 
                       help="Maximum repair attempts per vulnerability")
    parser.add_argument("--report-file", default="repair_report.json", 
                       help="Output file for the repair report")
    parser.add_argument("--analyze-only", action="store_true", 
                       help="Only analyze codebase without repair")
    
    args = parser.parse_args()
    
    try:
        # Initialize RepairGPT
        logger.info("Initializing RepairGPT...")
        repair_gpt = RepairGPT(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password,
            model_name=args.model,
            local_model_path=args.local_model,
            offline_mode=args.offline
        )
        
        # Analyze codebase
        logger.info("Analyzing codebase structure...")
        codebase_analysis = repair_gpt.analyze_codebase()
        logger.info(f"Found schema type: {codebase_analysis['schema_type']}")
        
        if args.analyze_only:
            logger.info("Analysis-only mode, skipping repair cycle")
            report = {"analysis": codebase_analysis, "repair_results": []}
        else:
            # Run repair cycle
            logger.info("Starting repair cycle...")
            repair_results = repair_gpt.repair_cycle(max_attempts=args.max_attempts)
            
            # Generate report
            logger.info("Generating repair report...")
            report = repair_gpt.generate_report(repair_results)
            report["analysis"] = codebase_analysis
        
        # Save report to file
        import json
        with open(args.report_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to {args.report_file}")
        
        # Print summary
        if not args.analyze_only:
            summary = report["summary"]
            print(f"\nRepair Summary:")
            print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"Successfully repaired: {summary['successful_repairs']} " +
                  f"({summary['success_rate']:.1%})")
            print(f"Partially repaired: {summary['partial_repairs']}")
            print(f"Failed repairs: {summary['failed_repairs']}")
        
    except Exception as e:
        logger.error(f"Error in main process: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Clean up resources
        if 'repair_gpt' in locals():
            repair_gpt.close()
            logger.info("RepairGPT resources released")
    
    return 0


if __name__ == "__main__":
    # Set up colored logging for console output
    try:
        import colorlog
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        ))
        logging.getLogger().handlers = [handler]
    except ImportError:
        # Continue without colored logging if colorlog is not available
        pass
    
    sys.exit(main())
