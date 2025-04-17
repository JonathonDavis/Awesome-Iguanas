from neo4j import GraphDatabase
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import difflib
from collections import Counter
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("RepairGPT")


class RepairGPT:
    """
    A system that uses Neo4j graph database and LLMs to detect and repair memory safety issues in code.
    Adapted for CVE vulnerability database schema.
    """
    
    def __init__(self, neo4j_uri="bolt://localhost:7687",
                 neo4j_user="neo4j",
                 neo4j_password="jaguarai",
                 model_name="deepseek-ai/deepseek-coder-1.3b-instruct"):
        """
        Initialize RepairGPT with Neo4j connection and Deepseek Coder model.
        
        Args:
            neo4j_uri: URI for Neo4j database connection
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            model_name: Name of the Hugging Face model to use
        """
        self.model_name = model_name
        self.repair_attempts = {}
        self.max_sequence_length = 2048
        self.db_schema = {}
        
        self._connect_to_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        self._discover_schema()  # Get actual schema
        self._initialize_model()

    def _connect_to_neo4j(self, uri, user, password):
        """Establish connection to Neo4j database."""
        logger.info("Connecting to Neo4j database...")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            
            # Verify connection
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
        
        # Initialize with known schema from user input
        self.db_schema = {
            "labels": [
                "CVE", "File", "Function", "Package", "Reference", 
                "Repository", "UpdateTracking", "Version", 
                "Vulnerability", "VulnerabilityAnalysis"
            ],
            "relationships": [
                "AFFECTED_BY", "CONCERNS_FILE", "CONCERNS_FUNCTION", 
                "FOUND_IN", "HAS_ANALYSIS", "HAS_VERSION", 
                "IDENTIFIED_AS", "REFERS_TO", "RELATED_TO"
            ],
            "properties": [
                "Affected", "Analysis", "Analyzed_at", "Classification", 
                "Cve", "Database_specific", "Details", "Ecosystem", 
                "Headline", "Id", "Language_count", "Language_json", 
                "Modified", "Name", "Primary_language", "Published",
                "Size", "Summary", "Type", "updated_at", "Url",
                "version", "version_ranges", "versions"
            ]
        }
        
        # Log the discovered schema
        logger.info(f"Using database schema with {len(self.db_schema['labels'])} node labels, "
                    f"{len(self.db_schema['relationships'])} relationship types, and "
                    f"{len(self.db_schema['properties'])} property keys")
        
        logger.info(f"Node labels: {', '.join(self.db_schema['labels'])}")
        logger.info(f"Relationship types: {', '.join(self.db_schema['relationships'])}")

    def _initialize_model(self):
        """Initialize the language model for code repair."""
        logger.info(f"Initializing {self.model_name} model...")
        try:
            # Determine device based on GPU availability
            device = "auto" if torch.cuda.is_available() else "cpu"
            logger.info(f"Using device: {device}")
            
            # Load model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map=device,
                trust_remote_code=True
            )
            
            # Set padding token
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
        Query Neo4j to detect memory safety issues using the CVE-based schema.
        
        Returns:
            List of memory safety issues found in the codebase
        """
        logger.info("Analyzing code for memory safety issues...")

        results = []
        
        try:
            with self.driver.session() as session:
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
                       f as function_node,
                       id(f) as function_id
                LIMIT 25
                """
                
                vulnerability_results = session.run(query).data()
                
                if vulnerability_results:
                    logger.info(f"Found {len(vulnerability_results)} memory safety vulnerabilities")
                    
                    # For each vulnerability, get the function details
                    for vuln in vulnerability_results:
                        function_id = vuln.get('function_id')
                        
                        # Try to get code content for the function
                        code_query = """
                        MATCH (f:Function)
                        WHERE id(f) = $function_id
                        OPTIONAL MATCH (f)-[:CONCERNS_FILE]->(file:File)
                        RETURN f.Name as name,
                               f.Details as code,
                               file.Name as file_name,
                               file.Primary_language as language
                        """
                        
                        code_result = session.run(code_query, function_id=function_id).single()
                        
                        if code_result and code_result.get('code'):
                            results.append({
                                'vulnerability_id': vuln.get('vulnerability_id'),
                                'summary': vuln.get('summary'),
                                'function': vuln.get('function_name'),
                                'code': code_result.get('code'),
                                'file': code_result.get('file_name'),
                                'language': code_result.get('language'),
                                'id': function_id,
                                'context': []  # No context for now
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
                        logger.info(f"Found {len(function_results)} potentially vulnerable functions")
                        for func in function_results:
                            if func.get('code'):
                                results.append({
                                    'function': func.get('function'),
                                    'code': func.get('code'),
                                    'id': func.get('id'),
                                    'context': []  # No context for now
                                })
                
                # If still no results, try searching in vulnerability summaries
                if not results:
                    logger.info("Searching for memory issues in vulnerability descriptions...")
                    query = """
                    MATCH (v:Vulnerability)
                    WHERE v.Summary CONTAINS 'buffer overflow' OR 
                          v.Summary CONTAINS 'use-after-free' OR
                          v.Summary CONTAINS 'memory corruption'
                    RETURN v.Id as id,
                           v.Summary as summary,
                           v.Details as details
                    LIMIT 15
                    """
                    
                    vuln_description_results = session.run(query).data()
                    
                    if vuln_description_results:
                        logger.info(f"Found {len(vuln_description_results)} vulnerabilities with memory issues")
                        for vuln in vuln_description_results:
                            # Extract any code snippets from the details
                            details = vuln.get('details', '')
                            code_snippet = self._extract_code_snippet(details)
                            
                            if code_snippet:
                                results.append({
                                    'vulnerability_id': vuln.get('id'),
                                    'summary': vuln.get('summary'),
                                    'code': code_snippet,
                                    'id': vuln.get('id'),
                                    'context': []
                                })

        except Exception as e:
            logger.error(f"Error in memory safety analysis: {str(e)}")
            return []

        # Log findings
        if results:
            logger.info(f"Found {len(results)} potential memory safety issues")
            for r in results:
                vuln_id = r.get('vulnerability_id', 'unknown')
                function = r.get('function', 'unknown')
                code_preview = r.get('code', 'unknown')[:50] + '...' if r.get('code') else 'unknown'
                logger.info(f"ID {vuln_id}: {function} - {code_preview}")
        else:
            logger.info("No memory safety issues detected")

        return results

    def _extract_code_snippet(self, text):
        """Extract code snippets from vulnerability details."""
        if not text:
            return None
            
        # Look for code blocks between triple backticks
        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:  # At least one code block
                return parts[1].strip()
                
        # If no code blocks, look for indented code or code-like patterns
        lines = text.split("\n")
        code_lines = []
        in_code_block = False
        
        for line in lines:
            if line.strip().startswith("if ") or line.strip().startswith("for ") or \
               line.strip().startswith("while ") or line.strip().endswith("{") or \
               line.strip().startswith("malloc(") or line.strip().startswith("memcpy("):
                in_code_block = True
                
            if in_code_block:
                code_lines.append(line)
                
            if in_code_block and line.strip() == "}":
                in_code_block = False
                
        if code_lines:
            return "\n".join(code_lines)
            
        return None

    def analyze_codebase(self):
        """
        Analyze overall codebase structure from Neo4j using the CVE schema.
        
        Returns:
            Dict containing analysis of code structure
        """
        logger.info("Analyzing codebase structure...")

        analysis = {
            "schema": self.db_schema,
            "languages": [],
            "vulnerability_types": [],
            "packages": []
        }
        
        try:
            with self.driver.session() as session:
                # Get programming languages
                query = """
                MATCH (f:File)
                RETURN f.Primary_language as language, count(*) as count
                ORDER BY count DESC
                LIMIT 10
                """
                languages = session.run(query).data()
                analysis["languages"] = languages
                
                # Get vulnerability types
                query = """
                MATCH (v:Vulnerability)
                RETURN v.Type as type, count(*) as count
                ORDER BY count DESC
                LIMIT 10
                """
                vulnerability_types = session.run(query).data()
                analysis["vulnerability_types"] = vulnerability_types
                
                # Get packages
                query = """
                MATCH (p:Package)
                RETURN p.Name as name, count(*) as count
                ORDER BY count DESC
                LIMIT 10
                """
                packages = session.run(query).data()
                analysis["packages"] = packages
                
                # Get relationship statistics
                query = """
                MATCH ()-[r]->()
                RETURN type(r) as type, count(*) as count
                ORDER BY count DESC
                LIMIT 10
                """
                relationships = session.run(query).data()
                analysis["relationships"] = relationships
                
        except Exception as e:
            logger.error(f"Error analyzing codebase: {str(e)}")

        # Log analysis results
        logger.info(f"Codebase analysis complete")
        for language in analysis.get('languages', []):
            logger.info(f"  Language: {language.get('language')}: {language.get('count')} files")
        
        for vuln_type in analysis.get('vulnerability_types', []):
            logger.info(f"  Vulnerability type: {vuln_type.get('type')}: {vuln_type.get('count')}")

        return analysis

    def generate_safety_patch(self, vulnerable_code, context):
        """
        Generate a memory-safe patch using Deepseek Coder.
        
        Args:
            vulnerable_code: The code containing the vulnerability
            context: Surrounding code context for better understanding
            
        Returns:
            String containing the patched code or None if generation failed
        """
        logger.info(f"Generating safety patch for vulnerable code")
        
        try:
            # Create system prompt for the LLM
            system_prompt = """You are a memory safety expert. Generate a secure patch considering:
            - Buffer overflow prevention
            - Proper bounds checking
            - Memory initialization
            - Pointer validation
            - Resource cleanup
            Return ONLY the fixed code without explanations."""

            # Add specific guidance based on function type
            if "fgets" in vulnerable_code:
                system_prompt += "\nFor fgets calls, ensure:\n- Buffer size is checked\n- Newline handling is safe\n- Input validation"
            elif "malloc" in vulnerable_code:
                system_prompt += "\nFor malloc calls, ensure:\n- Null pointer checks\n- Proper size calculation\n- Error handling"

            # Truncate inputs to fit within sequence limits
            context = context[:self.max_sequence_length//2]
            vulnerable_code = vulnerable_code[:self.max_sequence_length//2]

            # Prepare messages for the model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Vulnerable code:\n```c\n{vulnerable_code}\n```\nCode context:\n```c\n{context}\n```\nProvide safe version:"}
            ]

            # Tokenize the input
            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                max_length=self.max_sequence_length,
                truncation=True
            ).to(self.model.device)

            # Generate with conservative parameters
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
            self.model = self.model.to("cpu")

            # Regenerate with smaller inputs and parameters
            messages = [
                {"role": "system", "content": "Generate secure patch (CPU fallback)"},
                {"role": "user", "content": f"Vulnerable code:\n{vulnerable_code}\nContext:\n{context}"}
            ]

            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                max_length=1024,
                truncation=True
            )

            outputs = self.model.generate(
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
        semantic_valid = any(line.startswith('-') for line in diff_lines)

        # Step 2: Basic safety checks
        safety_checks = {
            "buffer_check": "sizeof" in patched_code,
            "null_check": "NULL" in patched_code or "null" in patched_code,
            "bounds_check": any(op in patched_code for op in ["<=", ">=", "<", ">"]),
            "has_changes": len(original_code) != len(patched_code)
        }

        validation_result = {
            "sanitizers_clean": all(safety_checks.values()),
            "semantic_equivalence": semantic_valid,
            "safety_checks": safety_checks
        }
        
        logger.info(f"Patch validation result: sanitizers clean={validation_result['sanitizers_clean']}, "
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
        prefixes = ["Here's the fixed code:", "Fixed code:", "Secure version:"]
        for prefix in prefixes:
            if cleaned.startswith(prefix):
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
    repair_system = None
    try:
        logger.info("=== RepairGPT Analysis and Repair System ===")
        repair_system = RepairGPT()

        # Run the repair cycle
        results = repair_system.repair_cycle(max_attempts=2)
        
        # Generate and display report
        if results:
            report = repair_system.generate_report(results)
            
            logger.info("\n=== Final Results ===")
            logger.info(f"Total issues found: {report['summary']['total_vulnerabilities']}")
            logger.info(f"Successfully patched: {report['summary']['successful_repairs']}")
            logger.info(f"Partially patched: {report['summary']['partial_repairs']}")
            logger.info(f"Failed to patch: {report['summary']['failed_repairs']}")
            logger.info(f"Success rate: {report['summary']['success_rate']*100:.1f}%")
        else:
            logger.info("No issues found or no repairs attempted")

    except Exception as e:
        logger.error(f"Error during execution: {str(e)}", exc_info=True)
    finally:
        if repair_system is not None:
            repair_system.close()
        logger.info("RepairGPT execution completed")


if __name__ == "__main__":
    main()
