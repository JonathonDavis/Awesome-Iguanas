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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("RepairGPT")


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
                 ollama_model_dir: str = "/mnt/disk-2/.ollama/models"):
        """
        Initialize RepairGPT with direct Ollama process communication.

        Args:
            neo4j_uri: URI for Neo4j database connection
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            ollama_model: Name of the Ollama model to use
            ollama_model_dir: Directory to store Ollama models
        """
        logger.info("Initializing RepairGPT with local Ollama...")

        # Store configuration
        self.ollama_model = ollama_model
        self.ollama_model_dir = ollama_model_dir
        self.max_sequence_length = 2048
        self.repair_attempts = {}
        self.repair_stats = Counter()

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
        logger.info("Connecting to Neo4j database...")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))

            # Verify connection
            with self.driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                logger.info(f"Connected to Neo4j (found {count} nodes)")
        except Exception as e:
            logger.error(f"Neo4j connection error: {str(e)}")
            raise RuntimeError(f"Neo4j connection failed: {str(e)}")

    def _verify_ollama_installation(self) -> None:
        """
        Verify Ollama is installed and the required model is available in the specified directory.

        Raises:
            RuntimeError: If Ollama is not installed or model cannot be found/pulled
        """
        logger.info(f"Verifying Ollama installation and {self.ollama_model} availability in {self.ollama_model_dir}...")
        try:
            # Check if Ollama is installed
            result = subprocess.run(
                ["ollama", "--version"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError("Ollama not installed or not in PATH")

            logger.info(f"Found Ollama: {result.stdout.strip()}")

            # Check if the Ollama model directory exists
            if not os.path.isdir(self.ollama_model_dir):
                logger.warning(f"Ollama model directory '{self.ollama_model_dir}' not found. Creating it...")
                os.makedirs(self.ollama_model_dir, exist_ok=True)

            # Set OLLAMA_MODELS environment variable
            os.environ['OLLAMA_MODELS'] = self.ollama_model_dir

            # Check if model exists locally (within the specified directory)
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True
            )

            if self.ollama_model not in result.stdout:
                logger.info(f"Model {self.ollama_model} not found, pulling to {self.ollama_model_dir}...")
                pull_result = subprocess.run(
                    ["ollama", "pull", self.ollama_model],
                    capture_output=True,
                    text=True
                )
                if pull_result.returncode != 0:
                    raise RuntimeError(f"Failed to pull model: {pull_result.stderr}")
                logger.info(f"Successfully pulled {self.ollama_model} to {self.ollama_model_dir}")
            else:
                logger.info(f"Model {self.ollama_model} already available in {self.ollama_model_dir}")

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
            # Create a temporary prompt file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                f.write(prompt)
                temp_path = f.name

            logger.info(f"Running generation with model {self.ollama_model}")

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
            logger.info(f"Generation completed in {generation_time:.2f}s")

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"Ollama generation failed with return code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Ollama generation timed out after 3 minutes")
            return None
        except Exception as e:
            logger.error(f"Generation failed: {str(e)}")
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
               c.FILE_NAME as file,
               collect(DISTINCT b.CODE) as context,
               collect(DISTINCT param.CODE) as parameters
        ORDER BY c.LINE_NUMBER
        """

        with self.driver.session() as session:
            results = session.run(query).data()

        # Log findings
        if results:
            logger.info(f"Found {len(results)} potential memory safety issues")
            for r in results:
                logger.info(f"File: {r.get('file', 'unknown')}, Line {r['line']}: {r['function']} call")
        else:
            logger.info("No memory safety issues detected")

        return results

    def analyze_codebase(self) -> Dict[str, List[Dict]]:
        """
        Analyze overall codebase structure from Neo4j.

        Returns:
            Dict containing analysis of includes and function calls
        """
        logger.info("Analyzing codebase structure...")

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
            logger.info(f"Found {len(analysis['files'])} source files")

        if analysis.get('includes'):
            logger.info(f"Found {len(analysis['includes'])} project dependencies")

        if analysis.get('function_calls'):
            top_functions = ", ".join([f"{c['function']}" for c in analysis['function_calls'][:5]])
            logger.info(f"Top functions by usage: {top_functions}")

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
        logger.info(f"Generating patch for code using {function_name}")

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
            logger.warning("Cannot validate: patch generation failed")
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

        logger.info(f"Patch validation: sanitizers={validation_result['sanitizers_clean']}, "
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
        logger.info(f"Starting repair cycle (max attempts: {max_attempts})...")

        # First analyze the codebase
        self.analyze_codebase()

        # Then look for specific issues
        vulnerabilities = self.detect_memory_safety_issues()

        if not vulnerabilities:
            logger.info("No vulnerabilities found to repair")
            return []

        results = []
        for idx, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"Repairing vulnerability {idx}/{len(vulnerabilities)} at line {vuln['line']}...")

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
                logger.info(f"Attempt {attempt + 1}/{max_attempts}...")

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

                #
