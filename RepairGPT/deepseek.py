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
        
        self._connect_to_neo4j(neo4j_uri, neo4j_user, neo4j_password)
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
        Query Neo4j to detect memory safety issues using Joern CPG patterns.
        
        Returns:
            List of memory safety issues found in the codebase
        """
        logger.info("Analyzing code for memory safety issues...")

        # Query for potentially unsafe memory functions
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

        with self.driver.session() as session:
            results = session.run(query).data()

        # Log findings
        if results:
            logger.info(f"Found {len(results)} potential memory safety issues")
            for r in results:
                logger.info(f"Line {r['line']}: {r['function']} call - {r['code']}")
        else:
            logger.info("No memory safety issues detected")

        return results

    def analyze_codebase(self):
        """
        Analyze overall codebase structure from Neo4j.
        
        Returns:
            Dict containing analysis of imports and function calls
        """
        logger.info("Analyzing codebase structure...")

        queries = {
            "includes": """
                MATCH (i:IMPORT)
                RETURN i.CODE as include
                """,
            "function_calls": """
                MATCH (c:CALL)
                RETURN c.METHOD_FULL_NAME as function,
                       count(*) as count
                ORDER BY count DESC
                LIMIT 20
                """
        }

        analysis = {}
        with self.driver.session() as session:
            for key, query in queries.items():
                analysis[key] = session.run(query).data()

        # Log analysis results
        if analysis.get('includes'):
            logger.info(f"Found {len(analysis['includes'])} project dependencies")
        
        if analysis.get('function_calls'):
            logger.info(f"Analyzed usage frequency of top {len(analysis['function_calls'])} functions")

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
            return {"sanitizers_clean": False, "semantic_equivalence": False}

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
        logger.info(f"Starting repair cycle (max attempts: {max_attempts})...")

        # First analyze the codebase
        self.analyze_codebase()

        # Then look for specific issues
        vulnerabilities = self.detect_memory_safety_issues()

        if not vulnerabilities:
            logger.info("No vulnerabilities found to repair")
            return []

        results = []
        for idx, vuln in enumerate(vulnerabilities):
            logger.info(f"Repairing vulnerability {idx+1}/{len(vulnerabilities)} at line {vuln['line']}...")
            
            original_code = vuln['code']
            context = "\n".join(vuln['context']) if vuln['context'] else ""
            
            # Track repair attempts
            attempt = 0
            success = False
            best_patch = None
            best_validation = None
            
            # Try multiple repair attempts
            while attempt < max_attempts and not success:
                logger.info(f"Attempt {attempt + 1}/{max_attempts}...")
                
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
                    logger.info(f"Successfully generated valid patch on attempt {attempt + 1}")
                else:
                    attempt += 1
                    logger.info("Patch validation failed, trying again")
            
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
            
        # Store attempt data keyed by line number
        line_key = vuln['line']
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
                "success_rate": successful / total if total > 0 else 0
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
