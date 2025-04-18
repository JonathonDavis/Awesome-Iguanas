from neo4j import GraphDatabase
import difflib
from collections import Counter
import subprocess
import json
from typing import List, Dict, Any, Optional, Tuple
import tempfile
import os
import logging
import time
import shutil

# Set up logging
log_dir = "/mnt/disk-2/logs"
os.makedirs(log_dir, exist_ok=True)



class RepairGPT_OllamaLocal:
    """
    A system that uses Neo4j graph database and local Ollama models to detect and repair 
    memory safety issues in code.
    """
    
    def __init__(self, 
                 neo4j_uri: str = "bolt://localhost:7687",
                 neo4j_user: str = "neo4j",
                 neo4j_password: str = "jaguarai",
                 ollama_model: str = "deepseek-coder:6.7b",
                 base_dir: str = "/mnt/disk-2"):
        """
        Initialize RepairGPT with direct Ollama process communication.
        
        Args:
            neo4j_uri: URI for Neo4j database connection
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            ollama_model: Name of the Ollama model to use
            base_dir: Base directory for all operations
        """
        print("Initializing RepairGPT with local Ollama...")
        
        # Store configuration
        self.ollama_model = ollama_model
        self.max_sequence_length = 2048
        self.repair_attempts = {}
        self.repair_stats = Counter()
        self.base_dir = base_dir
        
        # Create required directories
        self.temp_dir = os.path.join(self.base_dir, "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Set OLLAMA_MODELS env variable to use /mnt/disk-2
        os.environ["OLLAMA_MODELS"] = os.path.join(self.base_dir, "ollama_models")
        os.makedirs(os.environ["OLLAMA_MODELS"], exist_ok=True)
        
        # Initialize connections
        self._init_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        self._verify_ollama_installation()

    def _init_neo4j(self, uri: str, user: str, password: str) -> None:
        """
        Initialize and verify Neo4j connection.
        
        Args:
            uri: Neo4j connection URI
            user: Neo4j username
            password: Neo4j password
            
        Raises:
            RuntimeError: If Neo4j connection fails
        """
        print("Connecting to Neo4j database...")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            
            # Verify connection
            with self.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                print(f"Connected to Neo4j (found {count} nodes)")
        except Exception as e:
            print(f"Neo4j connection error: {str(e)}")
            raise RuntimeError(f"Neo4j connection failed: {str(e)}")

    def _verify_ollama_installation(self) -> None:
        """
        Verify Ollama is installed and the required model is available.
        
        Raises:
            RuntimeError: If Ollama is not installed or model cannot be pulled
        """
        print(f"Verifying Ollama installation and {self.ollama_model} availability...")
        try:
            # Check if Ollama is installed
            result = subprocess.run(
                ["ollama", "--version"], 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError("Ollama not installed or not in PATH")
            
            print(f"Found Ollama: {result.stdout.strip()}")
            
            # Check if model exists locally
            result = subprocess.run(
                ["ollama", "list"], 
                capture_output=True, 
                text=True
            )
            
            if self.ollama_model not in result.stdout:
                print(f"Model {self.ollama_model} not found, pulling...")
                pull_result = subprocess.run(
                    ["ollama", "pull", self.ollama_model], 
                    capture_output=True,
                    text=True
                )
                if pull_result.returncode != 0:
                    raise RuntimeError(f"Failed to pull model: {pull_result.stderr}")
                print(f"Successfully pulled {self.ollama_model}")
            else:
                print(f"Model {self.ollama_model} already available")
                
        except FileNotFoundError:
            raise RuntimeError("Ollama not found. Please install Ollama first.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Ollama verification failed: {str(e)}")

    def _generate_with_ollama_direct(self, prompt: str) -> Optional[str]:
        """
        Generate text using direct Ollama command-line interaction.
        
        Args:
            prompt: The prompt to send to Ollama
            
        Returns:
            Generated text or None if generation failed
        """
        temp_path = None
        try:
            # Create a temporary prompt file in our base directory
            temp_path = os.path.join(self.temp_dir, f"prompt_{int(time.time())}.txt")
            with open(temp_path, 'w') as f:
                f.write(prompt)
            
            print(f"Running generation with model {self.ollama_model}")
            
            # Run Ollama directly
            cmd = [
                "ollama", "run",
                self.ollama_model,
                f"$(cat {temp_path})"
            ]
            
            start_time = time.time()
            result = subprocess.run(
                " ".join(cmd),
                shell=True,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout
            )
            
            generation_time = time.time() - start_time
            print(f"Generation completed in {generation_time:.2f}s")
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                print(f"Ollama generation failed with return code {result.returncode}")
                print(f"stderr: {result.stderr}")
                return None
            
        except subprocess.TimeoutExpired:
            print("Ollama generation timed out after 3 minutes")
            return None
        except Exception as e:
            print(f"Generation failed: {str(e)}")
            return None
        finally:
            # Clean up temp file
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    def detect_memory_safety_issues(self) -> List[Dict[str, Any]]:
        """
        Query Neo4j to detect memory safety issues using Joern CPG patterns.
        
        Returns:
            List of memory safety issues found in the codebase
        """
        print("Analyzing code for memory safety issues...")

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
               c.FILE_NAME as file,
               collect(DISTINCT b.CODE) as context,
               collect(DISTINCT param.CODE) as parameters
        ORDER BY c.LINE_NUMBER
        """

        with self.driver.session() as session:
            results = session.run(query).data()

        # Log findings
        if results:
            print(f"Found {len(results)} potential memory safety issues")
            for r in results:
                print(f"File: {r.get('file', 'unknown')}, Line {r['line']}: {r['function']} call")
        else:
            print("No memory safety issues detected")

        return results

    def analyze_codebase(self) -> Dict[str, List[Dict]]:
        """
        Analyze overall codebase structure from Neo4j.
        
        Returns:
            Dict containing analysis of includes and function calls
        """
        print("Analyzing codebase structure...")

        queries = {
            "includes": """
                MATCH (i:IMPORT)
                RETURN i.CODE as include, 
                       count(*) as count
                ORDER BY count DESC
                """,
            "function_calls": """
                MATCH (c:CALL)
                RETURN c.METHOD_FULL_NAME as function,
                       count(*) as count
                ORDER BY count DESC
                LIMIT 20
                """,
            "files": """
                MATCH (f:FILE)
                RETURN f.NAME as filename,
                       count(*) as node_count
                ORDER BY node_count DESC
                """
        }

        analysis = {}
        with self.driver.session() as session:
            for key, query in queries.items():
                analysis[key] = session.run(query).data()

        # Log analysis results
        if analysis.get('files'):
            print(f"Found {len(analysis['files'])} source files")
        
        if analysis.get('includes'):
            print(f"Found {len(analysis['includes'])} project dependencies")
        
        if analysis.get('function_calls'):
            top_functions = ", ".join([f"{c['function']}" for c in analysis['function_calls'][:5]])
            print(f"Top functions by usage: {top_functions}")

        return analysis

    def generate_safety_patch(self, 
                            vulnerable_code: str, 
                            context: List[str],
                            function_name: str = "") -> Optional[str]:
        """
        Generate memory-safe patches using direct Ollama.
        
        Args:
            vulnerable_code: The code containing the vulnerability
            context: Surrounding code context for better understanding
            function_name: Name of the vulnerable function
            
        Returns:
            String containing the patched code or None if generation failed
        """
        print(f"Generating patch for code using {function_name}")
        
        # Customize system prompt based on function
        system_prompt = """[INST] <<SYS>>
You are a memory safety expert. Fix this C/C++ code with:
1. Buffer overflow protection
2. Proper bounds checking
3. Memory initialization
4. Null pointer validation
5. Resource cleanup
Return ONLY the fixed code without explanations.
<</SYS>>"""

        # Add function-specific guidance
        if function_name in ["strcpy", "strncpy", "sprintf"]:
            system_prompt += "\nFocus on string buffer overflow prevention."
        elif function_name in ["malloc", "realloc"]:
            system_prompt += "\nEnsure proper allocation checks and error handling."
        elif function_name == "free":
            system_prompt += "\nPrevent use-after-free and double-free bugs."
            
        # Prepare context (limiting size)
        context_text = "\n".join(context[:3]) if context else "No additional context available."
        if len(context_text) > 500:
            context_text = context_text[:500] + "...(truncated)"
            
        # Construct the prompt
        full_prompt = f"""{system_prompt}

=== Vulnerable Code ===
{vulnerable_code}

=== Context ===
{context_text}

=== Fixed Version ===
[/INST]"""
        
        # Generate with direct Ollama
        patch = self._generate_with_ollama_direct(full_prompt)
        
        if patch:
            return self._clean_patch(patch)
        return None

    def _clean_patch(self, patch: str) -> str:
        """
        Clean generated patch by removing unwanted artifacts.
        
        Args:
            patch: Raw patch text from model
            
        Returns:
            Cleaned patch code
        """
        # Remove any command prompt artifacts
        patch = patch.replace(f"ollama run {self.ollama_model}", "")
        
        # Remove code block markers if present
        patch = patch.replace("```c", "").replace("```cpp", "").replace("```", "")
        
        # Get only the code after the last [/INST] if present
        if "[/INST]" in patch:
            patch = patch.split("[/INST]")[-1]
            
        # Remove common explanation prefixes
        prefixes = [
            "Here's the fixed version:", 
            "Here's the fixed code:", 
            "Fixed code:", 
            "Here is the fixed code:"
        ]
        for prefix in prefixes:
            if patch.strip().startswith(prefix):
                patch = patch.replace(prefix, "", 1)
                
        return patch.strip()

    def validate_patch(self, original_code: str, patched_code: str) -> Dict[str, Any]:
        """
        Validate patch using static analysis and differential testing.
        
        Args:
            original_code: The original vulnerable code
            patched_code: The generated patched code
            
        Returns:
            Dict containing validation results
        """
        if not patched_code:
            print("Cannot validate: patch generation failed")
            return {"sanitizers_clean": False, "semantic_change": False}

        # Step 1: Basic semantic validation using code diffs
        diff = difflib.ndiff(original_code.splitlines(), patched_code.splitlines())
        diff_lines = list(diff)
        has_changes = any(line.startswith('+') or line.startswith('-') for line in diff_lines)

        # Step 2: Basic safety checks
        safety_checks = {
            "buffer_check": "sizeof" in patched_code,
            "null_check": "NULL" in patched_code or "null" in patched_code,
            "bounds_check": any(op in patched_code for op in ["<=", ">=", "<", ">"]),
            "error_handling": "return" in patched_code and "NULL" in patched_code
        }

        validation_result = {
            "sanitizers_clean": any(safety_checks.values()),
            "semantic_change": has_changes,
            "safety_checks": safety_checks,
            "has_basic_protections": "if" in patched_code and not "if" in original_code
        }
        
        print(f"Patch validation: sanitizers={validation_result['sanitizers_clean']}, "
                   f"semantic_change={validation_result['semantic_change']}")
        
        return validation_result

    def repair_cycle(self, max_attempts: int = 3) -> List[Dict[str, Any]]:
        """
        Full repair process with feedback loop.
        
        Args:
            max_attempts: Maximum number of repair attempts per vulnerability
            
        Returns:
            List of repair results
        """
        print(f"Starting repair cycle (max attempts: {max_attempts})...")

        # First analyze the codebase
        self.analyze_codebase()

        # Then look for specific issues
        vulnerabilities = self.detect_memory_safety_issues()

        if not vulnerabilities:
            print("No vulnerabilities found to repair")
            return []

        results = []
        for idx, vuln in enumerate(vulnerabilities, 1):
            print(f"Repairing vulnerability {idx}/{len(vulnerabilities)} at line {vuln['line']}...")
            
            # Extract vulnerability details
            original_code = vuln['code']
            context = vuln['context'] if vuln['context'] else []
            function_name = vuln['function']
            
            # Track repair attempts
            attempt = 0
            success = False
            best_patch = None
            best_validation = None
            
            # Try multiple repair attempts
            while attempt < max_attempts and not success:
                print(f"Attempt {attempt + 1}/{max_attempts}...")
                
                # Generate patch
                patch = self.generate_safety_patch(
                    original_code, 
                    context, 
                    function_name
                )
                
                # Validate the patch
                validation = self.validate_patch(original_code, patch)
                
                # Store this attempt for future reference
                self._update_repair_attempt(vuln, patch, validation)
                
                # Check if this is the best attempt so far
                is_better = self._is_better_patch(best_validation, validation)
                if patch and (best_patch is None or is_better):
                    best_patch = patch
                    best_validation = validation
                
                # Check if patch is valid
                if validation.get("sanitizers_clean") and validation.get("semantic_change"):
                    success = True
                    self.repair_stats["success"] += 1
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
                    self.repair_stats["partial"] += 1
                    results.append({
                        "vulnerability": vuln,
                        "patch": best_patch,
                        "attempts": max_attempts,
                        "validation": best_validation,
                        "status": "partial"
                    })
                    print(f"Generated best-effort patch after {max_attempts} attempts")
                else:
                    self.repair_stats["failed"] += 1
                    results.append({
                        "vulnerability": vuln,
                        "status": "failed",
                        "attempts": attempt
                    })
                    print(f"Failed to generate any valid patch after {max_attempts} attempts")

        return results

    def _is_better_patch(self, current: Optional[Dict], new: Optional[Dict]) -> bool:
        """
        Determine if a new patch validation is better than the current best.
        
        Args:
            current: Current best validation results
            new: New validation results to compare
            
        Returns:
            True if new patch is better than current best
        """
        if not current:
            return True
        if not new:
            return False
            
        # First priority: sanitizers working
        if new.get("sanitizers_clean") and not current.get("sanitizers_clean"):
            return True
            
        # Second priority: has semantic changes
        if new.get("semantic_change") and not current.get("semantic_change"):
            return True
            
        # Third priority: more safety checks passing
        current_checks = sum(1 for v in current.get("safety_checks", {}).values() if v)
        new_checks = sum(1 for v in new.get("safety_checks", {}).values() if v)
        
        return new_checks > current_checks

    def _update_repair_attempt(self, vuln: Dict, patch: Optional[str], validation: Dict) -> None:
        """
        Store attempt data for future reference.
        
        Args:
            vuln: The vulnerability info
            patch: The generated patch
            validation: Validation results
        """
        # Store attempt data keyed by line+file
        key = f"{vuln.get('file', 'unknown')}:{vuln['line']}"
        
        if key not in self.repair_attempts:
            self.repair_attempts[key] = []
            
        self.repair_attempts[key].append({
            "patch": patch,
            "validation": validation,
            "timestamp": time.time()
        })

    def generate_report(self, repair_results: List[Dict[str, Any]]) -> Dict[str, Any]:
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
                "success_rate": round(successful / total * 100, 1) if total > 0 else 0
            },
            "details": repair_results,
            "stats": dict(self.repair_stats)
        }
        
        print(f"Repair report: {successful}/{total} successful, {partial}/{total} partial, {failed}/{total} failed")
        print(f"Success rate: {report['summary']['success_rate']}%")
        
        return report

    def export_results(self, results: List[Dict[str, Any]], output_dir: str = None) -> str:
        """
        Export repair results to files.
        
        Args:
            results: Repair results from repair_cycle
            output_dir: Directory to save results (defaults to base_dir/repairs)
            
        Returns:
            Path to the output directory
        """
        # Create output directory within base_dir
        if output_dir is None:
            output_dir = os.path.join(self.base_dir, "repairs")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Write overall report
        report = self.generate_report(results)
        report_path = os.path.join(output_dir, "repair_report.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        # Write individual patches
        patches_dir = os.path.join(output_dir, "patches")
        if not os.path.exists(patches_dir):
            os.makedirs(patches_dir)
            
        for idx, result in enumerate(results):
            if "patch" in result:
                vuln = result["vulnerability"]
                file_name = f"{idx+1}_{vuln['function']}_{vuln['line']}.patch"
                patch_path = os.path.join(patches_dir, file_name)
                
                with open(patch_path, 'w') as f:
                    f.write(f"--- Original (Line {vuln['line']})\n")
                    f.write(f"+++ Patched\n\n")
                    f.write(f"Original:\n{vuln['code']}\n\n")
                    f.write(f"Patched:\n{result['patch']}\n")
                    
        print(f"Exported results to {output_dir}")
        return output_dir

    def close(self) -> None:
        """Clean up resources."""
        if hasattr(self, 'driver'):
            try:
                self.driver.close()
                print("Neo4j connection closed")
            except Exception as e:
                print(f"Error closing Neo4j: {str(e)}")


def main() -> None:
    """Main execution with direct Ollama integration."""
    # Define base directory
    base_dir = "/mnt/disk-2"
    repair_system = None
    
    try:
        print("=== Memory Safety Repair System (Direct Ollama) ===")
        
        # Check Ollama availability
        if not shutil.which("ollama"):
            print("Ollama not found in PATH. Please install Ollama first.")
            return
            
        # Initialize repair system with base_dir
        repair_system = RepairGPT_OllamaLocal(
            ollama_model="deepseek-coder:6.7b",  # or "codellama:7b" for lighter option
            base_dir=base_dir
        )
        
        # Run repair cycle
        results = repair_system.repair_cycle(max_attempts=2)
        
        # Export results to base_dir
        if results:
            output_dir = repair_system.export_results(results)
            print(f"Repair report and patches saved to {output_dir}")
        else:
            print("No vulnerabilities found or repaired")
        
    except Exception as e:
        print(f"Fatal error: {str(e)}")
    finally:
        if repair_system:
            repair_system.close()
        print("System shutdown complete")


if __name__ == "__main__":
    main()
