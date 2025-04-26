from neo4j import GraphDatabase
import mimetypes
import os
import subprocess
import json

class VulnerabilityScanner:
    def __init__(self, uri, username, password):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        # Blocked file extensions and types
        self.blocked_extensions = ['.css', '.lock', '.md', '.min.js', '.scss', '.txt', '.rst']
        self.max_file_size = 200000  # 200,000 characters

    def close(self):
        self.driver.close()

    def get_repositories(self):
        """Fetch all repositories from the database"""
        with self.driver.session() as session:
            result = session.run("MATCH (r:Repository) RETURN r.url as url")
            return [record["url"] for record in result]

    def get_repository_versions(self, repo_url):
        """Get all versions (revisions) for a specific repository"""
        with self.driver.session() as session:
            query = """
            MATCH (r:Repository {url: $repo_url})-[:HAS_VERSION]->(v:Version)
            RETURN v.version as version, v.id as id
            """
            result = session.run(query, repo_url=repo_url)
            return [{"version": record["version"], "id": record["id"]} for record in result]

    def get_vulnerabilities_for_repo(self, repo_url):
        """Get vulnerabilities associated with a repository"""
        with self.driver.session() as session:
            query = """
            MATCH (v:Vulnerability)-[:FOUND_IN]->(r:Repository {url: $repo_url})
            RETURN v.id as id, v.details as details, v.severity as severity,
                   v.severityScore as score
            """
            result = session.run(query, repo_url=repo_url)
            return [dict(record) for record in result]

    def get_related_cves(self, vulnerability_id):
        """Get related CVEs for a vulnerability"""
        with self.driver.session() as session:
            query = """
            MATCH (v:Vulnerability {id: $vuln_id})-[:RELATED_TO]->(cve:CVE)
            RETURN cve.id as id
            """
            result = session.run(query, vuln_id=vulnerability_id)
            return [record["id"] for record in result]
        
    def should_process_file(self, file_path, content):
        """
        Determine if a file should be processed based on filtering criteria:
        - Not in blocked extensions
        - Not in a path starting with a dot
        - Not larger than max file size
        - Has a text MIME type
        """
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.blocked_extensions:
            return False
        
        # Check if path starts with a dot (hidden files/directories)
        if any(part.startswith('.') for part in file_path.split('/')):
            return False
        
        # Check file size
        if len(content) > self.max_file_size:
            return False
        
        # Check MIME type (ensure it's text)
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and not mime_type.startswith('text/'):
            return False
        
        return True

    def clone_repository(self, repo_url, version):
        """Clone a repository and checkout a specific version"""
        repo_name = repo_url.split('/')[-1]
        temp_dir = f"temp_{repo_name}_{version.replace('/', '_')}"
        
        # Clone repo
        if not os.path.exists(temp_dir):
            subprocess.run(["git", "clone", repo_url, temp_dir], check=True)
        
        # Checkout specific version
        subprocess.run(["git", "-C", temp_dir, "checkout", version], check=True)
        
        return temp_dir

    def get_code_files(self, repo_dir):
        """Get all relevant code files from a repository"""
        code_files = []
        
        for root, _, files in os.walk(repo_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if self.should_process_file(rel_path, content):
                        code_files.append({
                            "path": rel_path,
                            "content": content
                        })
                except (UnicodeDecodeError, IOError):
                    # Skip files that can't be read as text
                    continue
        
        return code_files

    def analyze_with_ollama(self, code_data, vulnerabilities):
        """
        Send code snippets to Ollama for vulnerability analysis
        
        Args:
            code_data: List of dictionaries with file paths and content
            vulnerabilities: List of vulnerabilities associated with the repository
        
        Returns:
            Ollama's assessment of potential vulnerabilities
        """
        # Create the prompt for Ollama
        prompt = self._create_analysis_prompt(code_data, vulnerabilities)
        
        # Call Ollama locally (no API, direct shell command)
        result = subprocess.run(
            ["ollama", "run", "llama3", prompt],
            capture_output=True,
            text=True,
            check=True
        )
        
        return self._parse_ollama_response(result.stdout)

    def _create_analysis_prompt(self, code_data, vulnerabilities):
        """
        Create a structured prompt for Ollama based on code snippets and vulnerabilities
        
        Args:
            code_data: List of dictionaries with file paths and content
            vulnerabilities: List of vulnerabilities associated with the repository
        
        Returns:
            A string prompt for Ollama to analyze the code snippets for potential security issues
        """
        # Create a list of CVE/CWE references
        vulnerability_references = []
        for vuln in vulnerabilities:
            cves = self.get_related_cves(vuln["id"])
            vulnerability_references.append({
                "id": vuln["id"],
                "details": vuln["details"],
                "severity": vuln["severity"],
                "score": vuln["score"],
                "related_cves": cves
            })
        
        # Construct the prompt
        prompt = """
You are VulGPT, an expert in identifying security vulnerabilities in code. 
Analyze the following code snippets for potential security issues.

For each vulnerability you identify, provide:
1. HEADLINE: A concise title for the vulnerability
2. ANALYSIS: A detailed explanation of the vulnerability
3. MOST RELEVANT CVE: The CVE/CWE that most closely matches this vulnerability
4. KEY FUNCTIONS & FILENAMES: The specific functions and files where the vulnerability exists
5. CLASSIFICATION: Categorize as "Very promising" (high-risk), "Slightly promising" (moderate-risk), or "Not promising" (low-risk)

CODE SNIPPETS:
"""
        
        # Add code snippets (limit total size if needed)
        total_chars = 0
        for file in code_data:
            if total_chars + len(file["content"]) > 50000:  # Reasonable limit for LLM context
                prompt += f"\n[Additional files omitted due to size constraints]\n"
                break
                
            prompt += f"\n--- {file['path']} ---\n{file['content']}\n"
            total_chars += len(file["content"])
        
        # Add vulnerability reference information
        prompt += "\nREFERENCE VULNERABILITIES:\n"
        for vuln in vulnerability_references:
            prompt += f"\nID: {vuln['id']}\n"
            prompt += f"DETAILS: {vuln['details']}\n"
            prompt += f"SEVERITY: {vuln['severity'] if vuln['severity'] else 'Unknown'}\n"
            prompt += f"SCORE: {vuln['score'] if vuln['score'] else 'Unknown'}\n"
            if vuln['related_cves']:
                prompt += f"RELATED CVEs: {', '.join(vuln['related_cves'])}\n"
            
        prompt += """
Please analyze the code carefully and return your findings in the specified format.
If no vulnerabilities are found, state this clearly.
"""
        return prompt

    def _parse_ollama_response(self, response):
        """Parse the response from Ollama into a structured format
        
        This is a simplified parser - you may need more robust parsing depending on Ollama's output format
        
        Args:
            response (str): The response from Ollama
        
        Returns:
            list: A list of dictionaries representing the findings, each with keys:
                headline (str): A concise title for the vulnerability
                analysis (str): A detailed explanation of the vulnerability
                cve (str): The CVE/CWE that most closely matches this vulnerability
                key_functions (str): The specific functions and files where the vulnerability exists
                classification (str): Categorize as "Very promising" (high-risk), "Slightly promising" (moderate-risk), or "Not promising" (low-risk)
        """
        findings = []
        current_finding = {}
        current_section = None
        
        for line in response.split('\n'):
            line = line.strip()
            
            if not line:
                continue
                
            if line.startswith("HEADLINE:"):
                # Start a new finding with the headline
                if current_finding and 'headline' in current_finding:
                    findings.append(current_finding)
                    current_finding = {}
                current_finding['headline'] = line[len("HEADLINE:"):].strip()
                current_section = 'headline'
            elif line.startswith("ANALYSIS:"):
                # Set the analysis for the current finding
                current_finding['analysis'] = line[len("ANALYSIS:"):].strip()
                current_section = 'analysis'
            elif line.startswith("MOST RELEVANT CVE:"):
                # Set the CVE for the current finding
                current_finding['cve'] = line[len("MOST RELEVANT CVE:"):].strip()
                current_section = 'cve'
            elif line.startswith("KEY FUNCTIONS & FILENAMES:"):
                # Set the key functions and filenames for the current finding
                current_finding['key_functions'] = line[len("KEY FUNCTIONS & FILENAMES:"):].strip()
                current_section = 'key_functions'
            elif line.startswith("CLASSIFICATION:"):
                # Set the classification for the current finding
                current_finding['classification'] = line[len("CLASSIFICATION:"):].strip()
                current_section = 'classification'
            elif current_section:
                # Append to the current section if continuation
                current_finding[current_section] += " " + line
        
        # Add the last finding if exists
        if current_finding and 'headline' in current_finding:
            findings.append(current_finding)
            
        return findings
    
    def scan_repository(self, repo_url):
        """
        Scan a repository for vulnerabilities:
        1. Get all versions of the repository
        2. For each version, retrieve and filter code
        3. Analyze the code using Ollama
        """
        results = []
        
        print(f"Scanning repository: {repo_url}")
        versions = self.get_repository_versions(repo_url)
        vulnerabilities = self.get_vulnerabilities_for_repo(repo_url)
        
        for version_info in versions:
            version = version_info["version"]
            print(f"  Processing version: {version}")
            
            try:
                # Clone repo and checkout version
                repo_dir = self.clone_repository(repo_url, version)
                
                # Get code files
                code_files = self.get_code_files(repo_dir)
                print(f"    Found {len(code_files)} relevant files")
                
                # Analyze with Ollama
                analysis = self.analyze_with_ollama(code_files, vulnerabilities)
                
                # Store results
                results.append({
                    "repo_url": repo_url,
                    "version": version,
                    "version_id": version_info["id"],
                    "findings": analysis
                })
                
                # Clean up temporary directory
                subprocess.run(["rm", "-rf", repo_dir], check=True)
            except Exception as e:
                print(f"    Error processing version {version}: {e}")
        
        return results

class EvaluationMetrics:
    def __init__(self, ground_truth=None):
        """
        Initialize with optional ground truth data
        Ground truth should be a dict with repo+version as keys and lists of known vulnerabilities as values
        """
        self.ground_truth = ground_truth or {}
        self.results = []
    
    def add_result(self, result):
        """Add a scan result to the evaluation"""
        self.results.append(result)
    
    def calculate_metrics(self):
        """Calculate evaluation metrics"""
        metrics = {
            "total_repos_scanned": len(set(r["repo_url"] for r in self.results)),
            "total_versions_scanned": len(self.results),
            "vulnerability_counts": {
                "very_promising": 0,
                "slightly_promising": 0,
                "not_promising": 0
            },
            "avg_vulnerabilities_per_version": 0,
            "precision": None,
            "recall": None,
            "f1_score": None
        }
        
        # Count vulnerabilities by classification
        total_findings = 0
        for result in self.results:
            for finding in result["findings"]:
                total_findings += 1
                classification = finding["classification"].lower()
                if "very promising" in classification:
                    metrics["vulnerability_counts"]["very_promising"] += 1
                elif "slightly promising" in classification:
                    metrics["vulnerability_counts"]["slightly_promising"] += 1
                elif "not promising" in classification:
                    metrics["vulnerability_counts"]["not_promising"] += 1
        
        # Calculate average vulnerabilities per version
        if metrics["total_versions_scanned"] > 0:
            metrics["avg_vulnerabilities_per_version"] = total_findings / metrics["total_versions_scanned"]
        
        # Calculate precision, recall, F1 (if ground truth available)
        if self.ground_truth:
            true_positives = 0
            false_positives = 0
            false_negatives = 0
            
            for result in self.results:
                key = f"{result['repo_url']}@{result['version']}"
                
                if key in self.ground_truth:
                    # Known vulnerabilities from ground truth
                    known_vulns = set(self.ground_truth[key])
                    
                    # High and medium risk findings from LLM
                    found_vulns = set()
                    for finding in result["findings"]:
                        classification = finding["classification"].lower()
                        if "very promising" in classification or "slightly promising" in classification:
                            # Use CVE ID or headline as identifier
                            vuln_id = finding.get("cve", "").strip() or finding["headline"]
                            found_vulns.add(vuln_id)
                    
                    # Calculate metrics components
                    true_positives += len(known_vulns.intersection(found_vulns))
                    false_positives += len(found_vulns - known_vulns)
                    false_negatives += len(known_vulns - found_vulns)
            
            # Calculate metrics if we have enough data
            if true_positives + false_positives > 0:
                metrics["precision"] = true_positives / (true_positives + false_positives)
            
            if true_positives + false_negatives > 0:
                metrics["recall"] = true_positives / (true_positives + false_negatives)
            
            if metrics["precision"] is not None and metrics["recall"] is not None:
                if metrics["precision"] + metrics["recall"] > 0:
                    metrics["f1_score"] = 2 * (metrics["precision"] * metrics["recall"]) / (metrics["precision"] + metrics["recall"])
        
        return metrics

def main():
    # Neo4j connection details (update with actual values)
    uri = "bolt://localhost:7687"
    username = "neo4j"
    password = "password"
    
    scanner = VulnerabilityScanner(uri, username, password)
    evaluator = EvaluationMetrics()
    
    try:
        # Get all repositories or specify particular ones
        repos = scanner.get_repositories()
        # repos = ["https://github.com/abantecart/abantecart-src"]  # For testing/debugging
        
        all_results = []
        
        for repo in repos:
            results = scanner.scan_repository(repo)
            all_results.extend(results)
            
            # Add results to evaluator
            for result in results:
                evaluator.add_result(result)
            
            # Save incremental results in case of failure
            with open("vulnerability_results.json", "w") as f:
                json.dump(all_results, f, indent=2)
            
            print(f"Completed scan of {repo}")
        
        # Calculate and save metrics
        metrics = evaluator.calculate_metrics()
        with open("evaluation_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)
        
        print("Evaluation metrics:")
        print(json.dumps(metrics, indent=2))
        
        print("All scans completed successfully!")
    finally:
        scanner.close()

if __name__ == "__main__":
    main()