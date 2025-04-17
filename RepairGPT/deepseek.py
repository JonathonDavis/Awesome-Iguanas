from neo4j import GraphDatabase
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import logging
import json
import os
import re
import requests
from urllib.parse import urlparse
from tempfile import TemporaryDirectory
import subprocess
from pathlib import Path
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("RepairGPT")


class RepairGPT:
    """
    A system that uses Neo4j vulnerability database and LLMs to generate security advisories
    and suggest patches for memory safety issues.
    """
    
    def __init__(self, neo4j_uri="bolt://localhost:7687",
                 neo4j_user="neo4j",
                 neo4j_password="jaguarai",
                 model_name="deepseek-ai/deepseek-coder-1.3b-instruct",
                 github_token=None):
        """
        Initialize RepairGPT with Neo4j connection and Deepseek Coder model.
        
        Args:
            neo4j_uri: URI for Neo4j database connection
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            model_name: Name of the Hugging Face model to use
            github_token: Optional GitHub API token for fetching repository code
        """
        self.model_name = model_name
        self.max_sequence_length = 2048
        self.db_schema = {}
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        
        self._connect_to_neo4j(neo4j_uri, neo4j_user, neo4j_password)
        self._discover_schema()
        self._initialize_model()

    def _connect_to_neo4j(self, uri, user, password):
        """Establish connection to Neo4j database."""
        logger.info("Connecting to Neo4j vulnerability database...")
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
        logger.info("Discovering vulnerability database schema...")
        
        try:
            with self.driver.session() as session:
                # Get node labels
                labels_result = session.run("MATCH (n) RETURN DISTINCT labels(n) AS labels")
                labels = [record["labels"] for record in labels_result]
                flat_labels = [label for sublist in labels for label in sublist]
                self.db_schema["labels"] = flat_labels
                logger.info(f"Found node labels: {', '.join(flat_labels)}")
                
                # Get relationship types
                rel_result = session.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS type")
                rel_types = [record["type"] for record in rel_result]
                self.db_schema["relationships"] = rel_types
                logger.info(f"Found relationship types: {', '.join(rel_types)}")
                
                # Get property keys
                prop_result = session.run(
                    "MATCH (n) UNWIND keys(n) AS key RETURN DISTINCT key"
                )
                properties = [record["key"] for record in prop_result]
                self.db_schema["properties"] = properties
                logger.info(f"Found property keys: {', '.join(properties)}")
                
                # Get sample nodes to understand structure better
                for label in flat_labels[:3]:  # Sample first 3 labels
                    sample_result = session.run(
                        f"MATCH (n:{label}) RETURN n LIMIT 1"
                    )
                    sample = sample_result.single()
                    if sample:
                        logger.info(f"Sample {label} node properties: {list(sample['n'].keys())}")
                
        except Exception as e:
            logger.error(f"Error discovering schema: {str(e)}")
            self.db_schema = {}

    def _initialize_model(self):
        """Initialize the language model for advisory generation."""
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
            
            # Set padding token (properly this time)
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

    def get_top_vulnerabilities(self, limit=10, min_severity=7.0):
        """
        Query the vulnerability database for high-severity issues.
        
        Args:
            limit: Maximum number of vulnerabilities to return
            min_severity: Minimum severity score threshold
            
        Returns:
            List of vulnerability records
        """
        logger.info(f"Finding top vulnerabilities with severity >= {min_severity}...")
        
        vulnerabilities = []
        try:
            with self.driver.session() as session:
                # Check if we have severity_score property
                has_severity_score = "severity_score" in self.db_schema.get("properties", [])
                severity_field = "severity_score" if has_severity_score else "severity"
                
                # Construct appropriate query based on schema
                query = f"""
                MATCH (v:Vulnerability)
                WHERE v.{severity_field} IS NOT NULL AND v.{severity_field} >= $min_severity
                RETURN 
                    v.{severity_field} AS severity,
                    v.id AS id,
                    v.summary AS summary,
                    v.details AS details,
                    elementId(v) AS elementId,
                    v.headline AS headline
                ORDER BY v.{severity_field} DESC
                LIMIT $limit
                """
                
                results = session.run(query, min_severity=min_severity, limit=limit)
                
                for record in results:
                    vuln = {k: v for k, v in record.items()}
                    vulnerabilities.append(vuln)
                    
                logger.info(f"Found {len(vulnerabilities)} high-severity vulnerabilities")
                
                # Enrich with function data if available
                for vuln in vulnerabilities:
                    vuln["functions"] = self._get_affected_functions(vuln["elementId"], session)
                    vuln["cves"] = self._get_related_cves(vuln["elementId"], session)
                    vuln["repos"] = self._get_affected_repos(vuln["elementId"], session)
                
        except Exception as e:
            logger.error(f"Error retrieving vulnerabilities: {str(e)}")
        
        return vulnerabilities

    def _get_affected_functions(self, vuln_id, session):
        """Get functions affected by this vulnerability."""
        functions = []
        try:
            query = """
            MATCH (v)-[:CONCERNS_FUNCTION]->(f:Function)
            WHERE elementId(v) = $id
            RETURN f.name AS name
            LIMIT 5
            """
            results = session.run(query, id=vuln_id)
            functions = [record["name"] for record in results]
        except Exception as e:
            logger.error(f"Error retrieving affected functions: {str(e)}")
        return functions

    def _get_related_cves(self, vuln_id, session):
        """Get CVEs associated with this vulnerability."""
        cves = []
        try:
            query = """
            MATCH (v)-[:IDENTIFIED_AS]->(c:CVE)
            WHERE elementId(v) = $id
            RETURN c.cve AS cve, c.published AS published
            """
            results = session.run(query, id=vuln_id)
            cves = [{"cve": record["cve"], "published": record["published"]} for record in results]
        except Exception as e:
            logger.error(f"Error retrieving CVEs: {str(e)}")
        return cves

    def _get_affected_repos(self, vuln_id, session):
        """Get repositories affected by this vulnerability."""
        repos = []
        try:
            query = """
            MATCH (v)-[:FOUND_IN]->(r:Repository)
            WHERE elementId(v) = $id
            RETURN r.name AS name, r.url AS url
            LIMIT 5
            """
            results = session.run(query, id=vuln_id)
            repos = [{"name": record["name"], "url": record["url"]} for record in results]
        except Exception as e:
            logger.error(f"Error retrieving repositories: {str(e)}")
        return repos

    def analyze_security_pattern(self, vulnerability):
        """
        Analyze vulnerability to identify security pattern and vulnerability class.
        
        Args:
            vulnerability: Vulnerability data from Neo4j
            
        Returns:
            Dictionary with security pattern analysis
        """
        logger.info(f"Analyzing security pattern for vulnerability {vulnerability.get('id')}")
        
        # Combine all relevant vulnerability information
        vuln_text = f"""
        ID: {vulnerability.get('id', 'Unknown')}
        Headline: {vulnerability.get('headline', 'Unknown')}
        Summary: {vulnerability.get('summary', 'Unknown')}
        Details: {vulnerability.get('details', 'Unknown')}
        Severity: {vulnerability.get('severity', 'Unknown')}
        Affected Functions: {', '.join(vulnerability.get('functions', []))}
        """
        
        # Prepare prompt for the model
        system_prompt = """You are a security expert tasked with analyzing vulnerability data.
        Based on the vulnerability description, identify:
        1. The vulnerability class (e.g., buffer overflow, use-after-free, etc.)
        2. The root cause of the vulnerability
        3. Common patterns that lead to this vulnerability
        4. Recommended remediation approaches
        
        Format your response as JSON with the following structure:
        {
            "vulnerability_class": "...",
            "root_cause": "...",
            "common_patterns": ["...", "..."],
            "remediation_approaches": ["...", "..."]
        }
        """
        
        try:
            # Use the model to analyze the vulnerability
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this vulnerability:\n{vuln_text}"}
            ]
            
            # Tokenize input with attention mask properly set
            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                padding=True,
                max_length=self.max_sequence_length,
                truncation=True,
                add_special_tokens=True
            ).to(self.model.device)
            
            attention_mask = torch.ones_like(inputs)
            
            # Generate analysis
            outputs = self.model.generate(
                inputs,
                attention_mask=attention_mask,
                max_new_tokens=512,
                do_sample=True,
                temperature=0.7,
                top_p=0.95
            )
            
            analysis_text = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            
            # Extract JSON from response
            json_match = re.search(r'({.*})', analysis_text.replace('\n', ' '), re.DOTALL)
            if json_match:
                analysis_json = json.loads(json_match.group(0))
                logger.info(f"Successfully generated security pattern analysis")
                return analysis_json
            else:
                # Fallback if no JSON is found
                logger.warning("Could not extract JSON from model response, returning text analysis")
                return {
                    "vulnerability_class": "Unknown",
                    "analysis_text": analysis_text
                }
            
        except Exception as e:
            logger.error(f"Error generating security pattern analysis: {str(e)}")
            return {
                "vulnerability_class": "Error",
                "error": str(e)
            }

    def fetch_repository_code(self, repo_url, function_name=None):
        """
        Fetch code from a repository, optionally focusing on a specific function.
        
        Args:
            repo_url: URL of the repository
            function_name: Optional name of function to look for
            
        Returns:
            Dictionary with repository code information
        """
        if not repo_url:
            return {"error": "No repository URL provided"}
        
        try:
            # Parse the URL to get owner and repo name
            parsed_url = urlparse(repo_url)
            path_parts = parsed_url.path.strip('/').split('/')
            
            if len(path_parts) < 2 or 'github.com' not in parsed_url.netloc:
                return {"error": f"Not a valid GitHub repository URL: {repo_url}"}
            
            owner, repo = path_parts[0], path_parts[1]
            
            with TemporaryDirectory() as temp_dir:
                logger.info(f"Cloning repository {owner}/{repo}...")
                
                # Clone the repository
                clone_cmd = f"git clone --depth 1 https://github.com/{owner}/{repo}.git {temp_dir}"
                if self.github_token:
                    clone_cmd = f"git clone --depth 1 https://{self.github_token}@github.com/{owner}/{repo}.git {temp_dir}"
                
                process = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True)
                if process.returncode != 0:
                    return {"error": f"Failed to clone repository: {process.stderr}"}
                
                # If function name is provided, try to find it
                code_files = []
                if function_name:
                    logger.info(f"Searching for function {function_name}...")
                    
                    # Use grep to find the function
                    grep_patterns = [
                        f"function {function_name}",
                        f"def {function_name}",
                        f"{function_name}\\s*\\(",
                        f"void {function_name}",
                        f"int {function_name}"
                    ]
                    
                    for pattern in grep_patterns:
                        grep_cmd = f"grep -r '{pattern}' --include='*.c' --include='*.cpp' --include='*.h' --include='*.py' --include='*.js' {temp_dir}"
                        process = subprocess.run(grep_cmd, shell=True, capture_output=True, text=True)
                        
                        if process.returncode == 0:
                            lines = process.stdout.strip().split('\n')
                            for line in lines:
                                if ':' in line:
                                    file_path, _ = line.split(':', 1)
                                    if os.path.exists(file_path):
                                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            code_content = f.read()
                                        
                                        rel_path = os.path.relpath(file_path, temp_dir)
                                        code_files.append({
                                            "file_path": rel_path,
                                            "content": code_content,
                                            "lang": os.path.splitext(file_path)[1][1:]
                                        })
                
                # If no function found or no function specified, get some representative files
                if not code_files:
                    logger.info("Getting representative code files...")
                    extensions = ['.c', '.cpp', '.h', '.py', '.js']
                    
                    for ext in extensions:
                        files = list(Path(temp_dir).rglob(f"*{ext}"))
                        for file_path in files[:2]:  # Get up to 2 files of each type
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                code_content = f.read()
                            
                            rel_path = os.path.relpath(file_path, temp_dir)
                            code_files.append({
                                "file_path": rel_path,
                                "content": code_content,
                                "lang": os.path.splitext(file_path)[1][1:]
                            })
                            
                            if len(code_files) >= 5:  # Limit to at most 5 files
                                break
                
                return {
                    "owner": owner,
                    "repo": repo,
                    "url": repo_url,
                    "code_files": code_files
                }
                
        except Exception as e:
            logger.error(f"Error fetching repository code: {str(e)}")
            return {"error": str(e)}

    def generate_security_advisory(self, vulnerability, repo_code=None):
        """
        Generate a security advisory for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data from Neo4j
            repo_code: Optional repository code for context
            
        Returns:
            Security advisory text
        """
        logger.info(f"Generating security advisory for vulnerability {vulnerability.get('id')}")
        
        # Create a security pattern analysis if we don't have one
        security_analysis = self.analyze_security_pattern(vulnerability)
        
        # Build context from repository code if available
        code_context = ""
        if repo_code and not isinstance(repo_code.get("error", None), str):
            code_files = repo_code.get("code_files", [])
            if code_files:
                code_context = "Code samples from the repository:\n\n"
                for i, file in enumerate(code_files[:2]):  # Only use first two files to keep prompt reasonable
                    file_path = file.get("file_path", "unknown")
                    content = file.get("content", "")
                    # Truncate very large files
                    if len(content) > 1000:
                        content = content[:1000] + "...[truncated]"
                    code_context += f"File: {file_path}\n```\n{content}\n```\n\n"
        
        # Build comprehensive vulnerability context
        vuln_context = f"""
        # Vulnerability Information
        ID: {vulnerability.get('id', 'Unknown')}
        Headline: {vulnerability.get('headline', 'Unknown')}
        Summary: {vulnerability.get('summary', 'Unknown')}
        Details: {vulnerability.get('details', 'Unknown')}
        Severity: {vulnerability.get('severity', 'Unknown')}
        
        # Affected Components
        Affected Functions: {', '.join(vulnerability.get('functions', ['Unknown']))}
        Repositories: {', '.join([r.get('name', 'Unknown') for r in vulnerability.get('repos', [])])}
        
        # CVEs
        {', '.join([cve.get('cve', 'Unknown') for cve in vulnerability.get('cves', [])])}
        
        # Security Analysis
        Vulnerability Class: {security_analysis.get('vulnerability_class', 'Unknown')}
        Root Cause: {security_analysis.get('root_cause', 'Unknown')}
        
        # Code Context
        {code_context}
        """
        
        # Define system prompt for advisory generation
        system_prompt = """You are a security advisory expert. Create a comprehensive security advisory document for the provided vulnerability.
        The advisory should include:
        
        1. Executive Summary (brief overview)
        2. Vulnerability Details
           - Vulnerability type
           - Affected components
           - Attack vectors
           - Potential impact
        3. Technical Analysis
           - Root cause analysis
           - Code patterns leading to the vulnerability
        4. Remediation Recommendations
           - Specific code changes or patterns to implement
           - Alternative approaches
           - Verification steps
        5. Timeline and References
        
        Format the advisory using markdown for readability.
        """
        
        try:
            # Generate advisory using the model
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Please create a security advisory based on this information:\n{vuln_context}"}
            ]
            
            # Tokenize with proper attention handling
            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                padding=True,
                max_length=self.max_sequence_length,
                truncation=True,
                add_special_tokens=True
            ).to(self.model.device)
            
            attention_mask = torch.ones_like(inputs)
            
            # Generate advisory with more creativity
            outputs = self.model.generate(
                inputs,
                attention_mask=attention_mask,
                max_new_tokens=1024,
                do_sample=True,
                temperature=0.8,
                top_p=0.95
            )
            
            advisory = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            logger.info(f"Successfully generated security advisory ({len(advisory)} chars)")
            
            return advisory
            
        except Exception as e:
            logger.error(f"Error generating security advisory: {str(e)}")
            return f"Error generating security advisory: {str(e)}"

    def generate_patch_recommendation(self, vulnerability, code_context):
        """
        Generate recommended code patch patterns for a vulnerability.
        
        Args:
            vulnerability: Vulnerability data from Neo4j
            code_context: Code context from repository
            
        Returns:
            Patch recommendations and code examples
        """
        if not code_context or not code_context.get("code_files"):
            return "Unable to generate patch recommendations: No code context available"
            
        logger.info(f"Generating patch recommendations for vulnerability {vulnerability.get('id')}")
        
        # Get security pattern analysis
        security_analysis = self.analyze_security_pattern(vulnerability)
        
        # Find the most relevant file to patch
        relevant_file = None
        relevant_functions = vulnerability.get('functions', [])
        
        for file in code_context.get("code_files", []):
            content = file.get("content", "")
            # Look for any of the functions in this file
            for func in relevant_functions:
                if func and func in content:
                    relevant_file = file
                    break
            if relevant_file:
                break
                
        # If no match found, use the first file
        if not relevant_file and code_context.get("code_files"):
            relevant_file = code_context["code_files"][0]
        
        if not relevant_file:
            return "Unable to identify relevant code to patch"
            
        # Prepare file context
        file_path = relevant_file.get("file_path", "unknown")
        file_content = relevant_file.get("content", "")
        language = relevant_file.get("lang", "c")
        
        # Truncate very large files for the context
        if len(file_content) > 2000:
            file_content = file_content[:2000] + "...[truncated]"
            
        # Create a custom prompt for the patch recommendation
        system_prompt = f"""You are a secure coding expert specializing in {language} development.
        
        You're analyzing a vulnerability with the following characteristics:
        - Type: {security_analysis.get('vulnerability_class', 'Unknown')}
        - Root cause: {security_analysis.get('root_cause', 'Unknown')}
        
        Based on the code provided, suggest specific patches to fix the vulnerability.
        
        For each suggestion:
        1. Identify the problematic pattern in the code
        2. Show the vulnerable code snippet
        3. Show the fixed code with comments explaining the changes
        4. Explain why the fix addresses the root cause
        
        Focus on practical, minimal changes that fix the security issue without changing functionality.
        """
            
        try:
            # Generate patch recommendations
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"File: {file_path}\n\n```{language}\n{file_content}\n```\n\nPlease suggest secure patches for this code based on the vulnerability description: {vulnerability.get('summary', '')}"}
            ]
            
            # Tokenize with proper attention handling
            inputs = self.tokenizer.apply_chat_template(
                messages,
                return_tensors="pt",
                padding=True,
                max_length=self.max_sequence_length,
                truncation=True,
                add_special_tokens=True
            ).to(self.model.device)
            
            attention_mask = torch.ones_like(inputs)
            
            # Generate advisory
            outputs = self.model.generate(
                inputs,
                attention_mask=attention_mask,
                max_new_tokens=1024,
                do_sample=True,
                temperature=0.7,
                top_p=0.9
            )
            
            recommendations = self.tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            logger.info(f"Successfully generated patch recommendations ({len(recommendations)} chars)")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating patch recommendations: {str(e)}")
            return f"Error generating patch recommendations: {str(e)}"

    def run_vulnerability_assessment(self, num_vulnerabilities=5, include_code=True):
        """
        Run a complete vulnerability assessment process.
        
        Args:
            num_vulnerabilities: Number of vulnerabilities to assess
            include_code: Whether to attempt to fetch repository code
            
        Returns:
            Assessment report with advisories and recommendations
        """
        logger.info(f"Starting vulnerability assessment for {num_vulnerabilities} vulnerabilities")
        start_time = time.time()
        
        # Get top vulnerabilities
        vulnerabilities = self.get_top_vulnerabilities(limit=num_vulnerabilities)
        if not vulnerabilities:
            return {"error": "No vulnerabilities found for assessment"}
            
        assessment_results = []
        
        for i, vuln in enumerate(vulnerabilities):
            logger.info(f"Assessing vulnerability {i+1}/{len(vulnerabilities)}: {vuln.get('id', 'Unknown')}")
            
            result = {
                "vulnerability": vuln,
                "security_analysis": self.analyze_security_pattern(vuln)
            }
            
            # Fetch repository code if available and requested
            repo_code = None
            if include_code and vuln.get("repos"):
                for repo in vuln.get("repos", []):
                    if repo.get("url"):
                        repo_code = self.fetch_repository_code(
                            repo.get("url"),
                            vuln.get("functions")[0] if vuln.get("functions") else None
                        )
                        if repo_code and not repo_code.get("error"):
                            break
                
                result["repository_code"] = repo_code
                
                # Generate patch recommendations if we have code
                if repo_code and not repo_code.get("error"):
                    result["patch_recommendations"] = self.generate_patch_recommendation(vuln, repo_code)
            
            # Generate security advisory
            result["security_advisory"] = self.generate_security_advisory(vuln, repo_code)
            
            assessment_results.append(result)
        
        execution_time = time.time() - start_time
        
        report = {
            "summary": {
                "vulnerabilities_assessed": len(assessment_results),
                "execution_time_seconds": execution_time,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "results": assessment_results
        }
        
        logger.info(f"Vulnerability assessment completed in {execution_time:.2f} seconds")
        return report


def main():
    """Main entry point for the RepairGPT system."""
    repair_system = None
    try:
        logger.info("=== RepairGPT Vulnerability Assessment System ===")
        repair_system = RepairGPT()

        # Run vulnerability assessment for 3 vulnerabilities
        results = repair_system.run_vulnerability_assessment(num_vulnerabilities=3)
        
        # Generate and display summary
        if results and not results.get("error"):
            print("\n=== Vulnerability Assessment Results ===")
            print(f"Vulnerabilities assessed: {results['summary']['vulnerabilities_assessed']}")
            print(f"Execution time: {results['summary']['execution_time_seconds']:.2f} seconds")
            
            for i, result in enumerate(results["results"]):
                vuln = result["vulnerability"]
                print(f"\n--- Vulnerability {i+1}: {vuln.get('id')} ---")
                print(f"Headline: {vuln.get('headline', 'Unknown')}")
                print(f"Severity: {vuln.get('severity', 'Unknown')}")
                print(f"Type: {result['security_analysis'].get('vulnerability_class', 'Unknown')}")
                
                if result.get("repository_code") and not result["repository_code"].get("error"):
                    print(f"Code analyzed: {result['repository_code'].get('url', 'Unknown')}")
                else:
                    print("No repository code analyzed")
                
                print("\nSecurity Advisory Preview:")
                advisory = result.get("security_advisory", "")
                print(advisory[:200] + "..." if len(advisory) > 200 else advisory)
        else:
            print(f"Error: {results.get('error', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Error during execution: {str(e)}", exc_info=True)
    finally:
        if repair_system is not None:
            repair_system.close()
        logger.info("RepairGPT execution completed")


if __name__ == "__main__":
    main()
