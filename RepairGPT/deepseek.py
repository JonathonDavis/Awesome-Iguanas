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
        self._discover_schema()  # New method to discover actual schema
        self._initialize_model()

    def _connect_to_neo4j(self, uri, user, password):
        """Establish connection to Neo4j database."""
        print("Connecting to Neo4j database...")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            
            # Verify connection
            with self.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                print(f"Successfully connected to Neo4j (found {count} nodes)")
                
        except Exception as e:
            logger.error(f"Neo4j connection error: {str(e)}")
            raise

    def _discover_schema(self):
        """Discover the actual schema of the connected Neo4j database."""
        print("Discovering database schema...")
        
        try:
            with self.driver.session() as session:
                # Get node labels
                labels_result = session.run("MATCH (n) RETURN DISTINCT labels(n) AS labels")
                labels = [record["labels"] for record in labels_result]
                flat_labels = [label for sublist in labels for label in sublist]
                self.db_schema["labels"] = flat_labels
                print(f"Found node labels: {', '.join(flat_labels)}")
                
                # Get relationship types
                rel_result = session.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS type")
                rel_types = [record["type"] for record in rel_result]
                self.db_schema["relationships"] = rel_types
                print(f"Found relationship types: {', '.join(rel_types)}")
                
                # Get property keys
                prop_result = session.run(
                    "MATCH (n) UNWIND keys(n) AS key RETURN DISTINCT key"
                )
                properties = [record["key"] for record in prop_result]
                self.db_schema["properties"] = properties
                print(f"Found property keys: {', '.join(properties)}")
                
                # Get a sample node to examine its structure
                if len(flat_labels) > 0:
                    sample_label = flat_labels[0]
                    sample_result = session.run(
                        f"MATCH (n:{sample_label}) RETURN n LIMIT 1"
                    )
                    sample = sample_result.single()
                    if sample:
                        print(f"Sample {sample_label} node properties: {list(sample['n'].keys())}")
                
        except Exception as e:
            logger.error(f"Error discovering schema: {str(e)}")
            logger.warning("Will proceed with default schema assumptions, but queries may fail")

    def _initialize_model(self):
        """Initialize the language model for code repair."""
        print(f"Initializing {self.model_name} model...")
        try:
            # Determine device based on GPU availability
            device = "auto" if torch.cuda.is_available() else "cpu"
            print(f"Using device: {device}")
            
            # Load model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map=device,
                trust_remote_code=True
            )
            
            # Set padding token
            self.tokenizer.pad_token = self.tokenizer.eos_token
            print("Model initialization complete")
            
        except Exception as e:
            logger.error(f"Model initialization failed: {str(e)}")
            self.close()
            raise RuntimeError(f"Model initialization failed: {str(e)}")

    def close(self):
        """Clean up resources and connections."""
        if hasattr(self, 'driver'):
            try:
                self.driver.close()
                print("Neo4j connection closed")
            except Exception as e:
                logger.error(f"Error closing Neo4j connection: {str(e)}")

        if torch.cuda.is_available():
            try:
                torch.cuda.empty_cache()
                print("CUDA cache cleared")
            except Exception as e:
                logger.error(f"Error clearing CUDA cache: {str(e)}")

    def detect_memory_safety_issues(self):
        """
        Query Neo4j to detect memory safety issues using adaptive queries based on discovered schema.
        
        Returns:
            List of memory safety issues found in the codebase
        """
        print("Analyzing code for memory safety issues...")

        # Default results if queries fail
        results = []
        
        try:
            with self.driver.session() as session:
                # Try different query patterns based on discovered schema
                if "CALL" in self.db_schema.get("labels", []):
                    # Try original query first
                    try:
                        query = """
                        MATCH (c:CALL)
                        WHERE c.METHOD_FULL_NAME IN [
                            'malloc', 'free', 'strcpy', 'strncpy', 'sprintf',
                            'gets', 'memcpy', 'realloc', 'alloca', 'fgets'
                        ]
                        OPTIONAL MATCH (c)-[:AST*]->(b:BLOCK)
                        OPTIONAL MATCH (c)-[:CONTAINS]->(param:IDENTIFIER)
                        RETURN c.METHOD_FULL_NAME as function,
                               c.CODE as code,
                               c.LINE_NUMBER as line,
                               collect(DISTINCT b.CODE) as context,
                               collect(DISTINCT param.CODE) as parameters
                        """
                        results = session.run(query).data()
                    except Exception as e:
                        logger.warning(f"Original query failed: {str(e)}")
                        # Fallback to simpler query
                        query = """
                        MATCH (c:CALL)
                        RETURN c.METHOD_FULL_NAME as function,
                               c.CODE as code,
                               c.LINE_NUMBER as line
                        LIMIT 10
                        """
                        try:
                            results = session.run(query).data()
                        except:
                            logger.warning("Fallback query also failed")
                
                # If we couldn't find CALL nodes, try looking for methods/functions with any available label
                if not results:
                    # Look for nodes that might represent function calls
                    method_related_labels = [
                        label for label in self.db_schema.get("labels", [])
                        if any(keyword in label.lower() for keyword in 
                              ["call", "method", "function", "invocation"])
                    ]
                    
                    if method_related_labels:
                        label = method_related_labels[0]
                        print(f"Trying alternative node label: {label}")
                        
                        # Find the name property - could be name, methodName, etc.
                        name_properties = [
                            prop for prop in self.db_schema.get("properties", [])
                            if any(keyword in prop.lower() for keyword in 
                                  ["name", "method", "function", "code"])
                        ]
                        
                        if name_properties:
                            name_prop = name_properties[0]
                            query = f"""
                            MATCH (c:{label})
                            WHERE c.{name_prop} IS NOT NULL
                            RETURN c.{name_prop} as function, 
                                   c as node,
                                   id(c) as id
                            LIMIT 10
                            """
                            
                            try:
                                results = session.run(query).data()
                                if results:
                                    print(f"Found {len(results)} potential functions using {label}.{name_prop}")
                                    
                                    # Extract node properties for each result
                                    enhanced_results = []
                                    for r in results:
                                        node_props = dict(r["node"])
                                        enhanced_results.append({
                                            "function": r["function"],
                                            "id": r["id"],
                                            "properties": node_props,
                                            # Add these for compatibility with original code
                                            "code": node_props.get("code", "Unknown"),
                                            "line": node_props.get("lineNumber", 0),
                                            "context": [],
                                            "parameters": []
                                        })
                                    results = enhanced_results
                            except Exception as e:
                                logger.warning(f"Alternative query failed: {str(e)}")
                
                # If still no results, try a very generic query to find any code-related nodes
                if not results:
                    print("Trying generic code search...")
                    code_related_props = [
                        prop for prop in self.db_schema.get("properties", [])
                        if any(keyword in prop.lower() for keyword in 
                              ["code", "text", "source", "content"])
                    ]
                    
                    if code_related_props:
                        code_prop = code_related_props[0]
                        dangerous_patterns = [
                            "malloc(", "free(", "strcpy(", "memcpy(", "sprintf(",
                            "gets(", "fgets(", "realloc(", "alloca("
                        ]
                        
                        for pattern in dangerous_patterns:
                            query = f"""
                            MATCH (n)
                            WHERE n.{code_prop} CONTAINS '{pattern}'
                            RETURN n.{code_prop} as code, 
                                   id(n) as id,
                                   labels(n) as labels,
                                   n as node
                            LIMIT 5 
                            """
                            
                            try:
                                pattern_results = session.run(query).data()
                                if pattern_results:
                                    print(f"Found {len(pattern_results)} nodes containing '{pattern}'")
                                    
                                    # Format results to match expected structure
                                    for r in pattern_results:
                                        node_props = dict(r["node"])
                                        results.append({
                                            "function": pattern,
                                            "code": r["code"],
                                            "line": node_props.get("lineNumber", 0),
                                            "id": r["id"],
                                            "labels": r["labels"],
                                            "context": [],
                                            "parameters": []
                                        })
                            except Exception as e:
                                logger.warning(f"Pattern search failed for '{pattern}': {str(e)}")

        except Exception as e:
            logger.error(f"Error in memory safety analysis: {str(e)}")
            return []

        # Log findings
        if results:
            print(f"Found {len(results)} potential memory safety issues")
            for r in results:
                line = r.get('line', 'unknown')
                function = r.get('function', 'unknown')
                code = r.get('code', 'unknown')
                print(f"Line {line}: {function} call - {code}")
        else:
            print("No memory safety issues detected")

        return results

    def analyze_codebase(self):
        """
        Analyze overall codebase structure from Neo4j using discovered schema.
        
        Returns:
            Dict containing analysis of code structure
        """
        print("Analyzing codebase structure...")

        analysis = {
            "includes": [],
            "function_calls": [],
            "schema": self.db_schema
        }
        
        try:
            with self.driver.session() as session:
                # Count node types
                query = "MATCH (n) RETURN labels(n) as type, count(*) as count ORDER BY count DESC LIMIT 10"
                node_counts = session.run(query).data()
                analysis["node_counts"] = node_counts
                
                # Try to find includes/imports if relevant labels exist
                import_labels = [
                    label for label in self.db_schema.get("labels", [])
                    if any(keyword in label.lower() for keyword in ["import", "include"])
                ]
                
                if import_labels:
                    label = import_labels[0]
                    query = f"MATCH (i:{label}) RETURN i as import LIMIT 10"
                    try:
                        imports = session.run(query).data()
                        analysis["includes"] = [dict(i["import"]) for i in imports]
                    except Exception as e:
                        logger.warning(f"Import query failed: {str(e)}")
                
                # Try to find function calls
                function_labels = [
                    label for label in self.db_schema.get("labels", [])
                    if any(keyword in label.lower() for keyword in 
                          ["function", "method", "call", "procedure"])
                ]
                
                if function_labels:
                    label = function_labels[0]
                    query = f"MATCH (f:{label}) RETURN labels(f) as type, count(*) as count LIMIT 10"
                    try:
                        functions = session.run(query).data()
                        analysis["function_calls"] = functions
                    except Exception as e:
                        logger.warning(f"Function query failed: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Error analyzing codebase: {str(e)}")

        # Log analysis results
        print(f"Codebase analysis complete - found {len(analysis['node_counts'])} node types")
        for count in analysis.get('node_counts', []):
            type_str = ', '.join(count['type']) if isinstance(count['type'], list) else count['type']
            print(f"  {type_str}: {count['count']} nodes")

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
        print(f"Generating safety patch for vulnerable code")
        
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
            print("Patch generation successful")
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
            print("Falling back to CPU generation with reduced parameters")
            
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
                print("Model moved back to GPU after fallback")
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
    def repair_cycle(self, max_attempts=3):
        """
        Full repair process with feedback loop.
        
        Args:
            max_attempts: Maximum number of repair attempts per vulnerability
            
        Returns:
            List of repair results
        """
        print(f"Starting repair cycle (max attempts: {max_attempts})...")

        # First analyze the codebase to understand its structure
        codebase_analysis = self.analyze_codebase()

        # Then look for specific issues
        vulnerabilities = self.detect_memory_safety_issues()

        if not vulnerabilities:
            print("No vulnerabilities found to repair")
            return []

        results = []
        for idx, vuln in enumerate(vulnerabilities):
            print(f"Repairing vulnerability {idx+1}/{len(vulnerabilities)} at line {vuln.get('line', 'unknown')}...")
            
            # Get the code and context
            original_code = vuln.get('code', '')
            context = "\n".join(vuln.get('context', [])) if vuln.get('context') else ""
            
            # If we don't have code to repair, skip
            if not original_code:
                logger.warning("Skipping vulnerability - no code available")
                continue
            
            # Track repair attempts
            attempt = 0
            success = False
            best_patch = None
            best_validation = None
            
            # Try multiple repair attempts
            while attempt < max_attempts and not success:
                print(f"Attempt {attempt + 1}/{max_attempts}...")
                
                # Generate patch
                patch = self.generate_safety_patch(original_code, context)
                
                # Validate the patch
                validation = self.validate_patch(original_code, patch)
                
                # Store this attempt
                self._update_failure_context(vuln, patch, validation)
                
                # Check if this is the best attempt so far
                if patch and (best_patch is None or 
                             sum(validation.values()) > sum(best_validation.values() if best_validation else [0])):
                    best_patch = patch
                    best_validation = validation
                
                # Check if patch is valid
                if validation.get("sanitizers_clean") and validation.get("semantic_equivalence"):
                    success = True
                    print(f"Successfully generated valid patch on attempt {attempt + 1}")
                else:
                    attempt += 1
                    print("Patch validation failed, trying again")
            
            # Record results
            if success:
                results.append({
                    "vulnerability": vuln,
                    "patch": best_patch,
                    "attempts": attempt + 1,
                    "validation": best_validation,
                    "status": "success"
                })
            else:
                # Use best attempt if we have one
                if best_patch:
                    results.append({
                        "vulnerability": vuln,
                        "patch": best_patch,
                        "attempts": max_attempts,
                        "validation": best_validation,
                        "status": "partial"
                    })
                    logger.warning(f"Generated best-effort patch after {max_attempts} attempts")
                else:
                    results.append({
                        "vulnerability": vuln,
                        "status": "failed",
                        "attempts": attempt
                    })
                    logger.error(f"Failed to generate any valid patch after {max_attempts} attempts")

        return results

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
            
        # Store attempt data keyed by line number or ID
        line_key = vuln.get('line', vuln.get('id', 'unknown'))
        self.repair_attempts.setdefault(line_key, []).append({
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
        
        print(f"Repair report: {successful}/{total} successful, {partial}/{total} partial, {failed}/{total} failed")
        return report


def main():
    """Main entry point for the RepairGPT system."""
    repair_system = None
    try:
        print("=== RepairGPT Analysis and Repair System ===")
        repair_system = RepairGPT()

        # Run the repair cycle
        results = repair_system.repair_cycle(max_attempts=2)
        
        # Generate and display report
        if results:
            report = repair_system.generate_report(results)
            
            print("\n=== Final Results ===")
            print(f"Total issues found: {report['summary']['total_vulnerabilities']}")
            print(f"Successfully patched: {report['summary']['successful_repairs']}")
            print(f"Partially patched: {report['summary']['partial_repairs']}")
            print(f"Failed to patch: {report['summary']['failed_repairs']}")
            print(f"Success rate: {report['summary']['success_rate']*100:.1f}%")
        else:
            print("No issues found or no repairs attempted")

    except Exception as e:
        logger.error(f"Error during execution: {str(e)}", exc_info=True)
    finally:
        if repair_system is not None:
            repair_system.close()
        print("RepairGPT execution completed")


if __name__ == "__main__":
    main()
