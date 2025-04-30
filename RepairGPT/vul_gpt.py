from neo4j import GraphDatabase
import mimetypes
import os
import subprocess
import json
import requests
import time
from typing import List, Dict, Any, Optional

class VulnerabilityScanner:
    """
    Initialize a VulnerabilityScanner object to interact with the graph database

    :param uri: The URI for the graph database
    :param username: The username for authentication
    :param password: The password for authentication
    :param deepseek_api_key: API key for DeepSeek service
    :param deepseek_api_url: URL for the DeepSeek API endpoint
    :param results_file: Path to the file where results will be saved
    """
    def __init__(self, uri, username, password, deepseek_api_key, 
                 deepseek_api_url="https://api.deepseek.com/v1/chat/completions",
                 results_file="vulnerability_results.json"):
        """
        Initialize a VulnerabilityScanner object to interact with the graph database

        :param uri: The URI for the graph database
        :param username: The username for authentication
        :param password: The password for authentication
        :param deepseek_api_key: API key for DeepSeek service
        :param deepseek_api_url: URL for the DeepSeek API endpoint
        :param results_file: Path to the file where results will be saved
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.deepseek_api_key = deepseek_api_key
        self.deepseek_api_url = deepseek_api_url
        self.results_file = results_file

        # Blocked file extensions and types
        # These files are not analyzed for security issues
        self.blocked_extensions = ['.css', '.lock', '.md', '.min.js', '.scss', '.txt', '.rst']

        # Maximum file size for analysis
        # Files larger than this size are not analyzed
        # This is a reasonable limit to prevent excessive memory usage
        self.max_file_size = 200000  # 200,000 characters
        
        # Load existing results if the file exists
        self.all_results = self._load_existing_results()
        
        # Track progress to avoid reprocessing
        self.processed_versions = self._get_processed_versions()

    def _load_existing_results(self):
        """
        Load existing results from the results file if it exists
        
        Returns:
            list: Previously saved results or an empty list if the file doesn't exist
        """
        try:
            if os.path.exists(self.results_file):
                with open(self.results_file, 'r') as f:
                    return json.load(f)
            return []
        except json.JSONDecodeError:
            print(f"Error loading results from {self.results_file}. Starting with empty results.")
            return []
        except Exception as e:
            print(f"Unexpected error loading results: {e}. Starting with empty results.")
            return []

    def _get_processed_versions(self):
        """
        Extract already processed repo-version combinations from existing results
        
        Returns:
            set: Set of "repo_url:version_id" strings for already processed versions
        """
        processed = set()
        for result in self.all_results:
            if isinstance(result, dict) and 'repo_url' in result and 'version_id' in result:
                key = f"{result['repo_url']}:{result['version_id']}"
                processed.add(key)
        return processed

    def save_results(self, new_results=None):
        """
        Save all results to the specified file with error handling
        
        Args:
            new_results (list, optional): New results to add before saving
        """
        try:
            # Add new results if provided
            if new_results:
                self.all_results.extend(new_results)
            
            # Create a temporary file first to avoid corruption if the process is killed during write
            temp_file = f"{self.results_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.all_results, f, indent=2)
            
            # Rename the temporary file to the target file (atomic operation)
            os.replace(temp_file, self.results_file)
            
            print(f"Successfully saved {len(self.all_results)} results to {self.results_file}")
        except Exception as e:
            print(f"Error saving results to {self.results_file}: {e}")

    def close(self):
        """
        Close the connection to the graph database
        """
        self.driver.close()

    def get_repositories(self):
        """
        Fetch all repositories from the database

        :return: A list of URLs for all repositories in the database
        """
        with self.driver.session() as session:
            result = session.run("MATCH (r:Repository) RETURN r.url as url")
            return [record["url"] for record in result]


    def get_repository_versions(self, repo_url):
        with self.driver.session() as session:
            # Query the database for all versions of the given repository
            query = """
            MATCH (r:Repository {url: $repo_url})-[:HAS_VERSION]->(v:Version)
            RETURN v.version as version, v.id as id
            """
            result = session.run(query, repo_url=repo_url)

            # Return the results as a list of dictionaries
            versions = [{"version": record["version"], "id": record["id"]} for record in result]
            
            # Clean up the version strings to remove 'HEAD ->' prefixes
            for version_info in versions:
                if version_info["version"] and "HEAD -> " in version_info["version"]:
                    # Extract just the branch name after 'HEAD -> '
                    version_info["version"] = version_info["version"].split("HEAD -> ")[1]
            
            return versions
          
    def get_vulnerabilities_for_repo(self, repo_url):
        """
        Get vulnerabilities associated with a repository

        Parameters
        ----------
        repo_url : str
            The URL of the repository to fetch vulnerabilities for

        Returns
        -------
        list
            A list of dictionaries containing the ID, details, severity, and severity score of each vulnerability
        """
        with self.driver.session() as session:
            # Query the database for all vulnerabilities associated with the given repository
            query = """
            MATCH (v:Vulnerability)-[:FOUND_IN]->(r:Repository {url: $repo_url})
            RETURN v.id as id, v.details as details, v.severity as severity,
                   v.severityScore as score
            """
            # Run the query
            result = session.run(query, repo_url=repo_url)

            # Return the results as a list of dictionaries
            return [dict(record) for record in result]

    def get_related_cves(self, vulnerability_id):
        """
        Get related CVEs for a vulnerability

        Parameters
        ----------
        vulnerability_id : str
            The ID of the vulnerability to fetch related CVEs for

        Returns
        -------
        list
            A list of CVE IDs related to the given vulnerability
        """
        with self.driver.session() as session:
            query = """
            MATCH (v:Vulnerability {id: $vuln_id})-[:RELATED_TO]->(cve:CVE)
            RETURN cve.id as id
            """
            result = session.run(query, vuln_id=vulnerability_id)
            # Return the results as a list of CVE IDs
            return [record["id"] for record in result]
        
    def should_process_file(self, file_path, content):
        """
        Determine if a file should be processed based on filtering criteria:

        1. Not in blocked extensions
        2. Not in a path starting with a dot (hidden files/directories)
        3. Not larger than max file size
        4. Has a text MIME type

        Parameters
        ----------
        file_path : str
            The path of the file to check
        content : str
            The content of the file

        Returns
        -------
        bool
            True if the file should be processed, False otherwise
        """
        # 1. Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.blocked_extensions:
            # If the file has a blocked extension, don't process it
            return False
        
        # 2. Check if path starts with a dot (hidden files/directories)
        if any(part.startswith('.') for part in file_path.split('/')):
            # If the path starts with a dot, don't process it
            return False
        
        # 3. Check file size
        if len(content) > self.max_file_size:
            # If the file is too large, don't process it
            return False
        
        # 4. Check MIME type (ensure it's text)
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and not mime_type.startswith('text/'):
            # If the MIME type is not text, don't process it
            return False
        
        # If the file passes all filters, process it
        return True

    def clone_repository(self, repo_url, version):
        """
        Clone a GitHub repository to a temporary directory.

        This method clones a given GitHub repository to a temporary directory
        and checks out the specified version (branch or tag). If the version
        string contains "HEAD -> ", it will be cleaned up to only contain the
        actual branch/tag name.

        Parameters
        ----------
        repo_url : str
            The URL of the GitHub repository to clone.
        version : str
            The version (branch/tag) to check out in the cloned repository.

        Returns
        -------
        str
            The path to the temporary directory containing the cloned repository.
        """
        if version and "HEAD -> " in version:
            version = version.split("HEAD -> ")[1]
        
        repo_name = repo_url.split('/')[-1]
        temp_dir = f"temp_{repo_name}_{version.replace('/', '_')}"
        
        try:
            # Clone repo if it doesn't exist
            if not os.path.exists(temp_dir):
                print(f"Cloning into '{temp_dir}'...")
                subprocess.run(["git", "clone", repo_url, temp_dir], check=True)
            
            # Fetch latest changes
            subprocess.run(["git", "-C", temp_dir, "fetch", "origin"], check=True)
            
            # Try different checkout strategies
            try:
                # Try direct checkout
                subprocess.run(["git", "-C", temp_dir, "checkout", version], check=True)
            except subprocess.CalledProcessError:
                try:
                    # Try checkout with origin prefix
                    subprocess.run(["git", "-C", temp_dir, "checkout", f"origin/{version}"], check=True)
                except subprocess.CalledProcessError:
                    # Try checking if it's already on the correct branch
                    result = subprocess.run(
                        ["git", "-C", temp_dir, "rev-parse", "--abbrev-ref", "HEAD"], 
                        capture_output=True, 
                        text=True,
                        check=True
                    )
                    current_branch = result.stdout.strip()
                    
                    if current_branch == version:
                        # Already on the correct branch, no need to do anything
                        print(f"Already on branch '{version}'")
                    else:
                        # If all checkout attempts fail, print available branches and raise exception
                        print(f"Could not checkout version '{version}'. Available branches:")
                        subprocess.run(["git", "-C", temp_dir, "branch", "-a"], check=False)
                        raise ValueError(f"Could not checkout version '{version}' in any way")
            
            return temp_dir
        except Exception as e:
            print(f"Error in clone_repository: {e}")
            # Clean up the directory if it exists and we encountered an error
            if os.path.exists(temp_dir):
                subprocess.run(["rm", "-rf", temp_dir], check=False)
            raise
        
    def get_code_files(self, repo_dir):
        """
        Get all relevant code files from a repository
        
        Walks the directory tree and checks each file to see if it should be processed.
        If the file should be processed, its path and content are added to the list of code files.
        
        Parameters
        ----------
        repo_dir : str
            The directory of the repository
        
        Returns
        -------
        list
            List of dictionaries with file paths and content
        """
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
                            # Store the relative path so that we can reconstruct the file later
                            "path": rel_path,
                            "content": content
                        })
                except (UnicodeDecodeError, IOError):
                    # Skip files that can't be read as text
                    continue
        
        return code_files

    def analyze_with_deepseek(self, code_data, vulnerabilities):
        """
        Send code snippets to DeepSeek API for vulnerability analysis
        
        Args:
            code_data (list): List of dictionaries with file paths and content
            vulnerabilities (list): List of vulnerabilities associated with the repository
        
        Returns:
            list: List of findings from DeepSeek and the raw API response
        """
        # Create the prompt for DeepSeek
        prompt = self._create_analysis_prompt(code_data, vulnerabilities)
        print(f"    Sending prompt of {len(prompt)} characters to DeepSeek API")
        
        # Prepare the request payload
        payload = {
            "model": "deepseek-chat",  # or the specific model ID you want to use
            "messages": [
                {"role": "system", "content": "You are VulGPT, an expert in identifying security vulnerabilities in code."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,  # Lower temperature for more deterministic responses
            "max_tokens": 4000   # Adjust based on expected response length
        }
        
        # Add headers with API key
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.deepseek_api_key}"
        }
        
        # Add retry logic for API requests
        max_retries = 3
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                # Make the API request
                response = requests.post(
                    self.deepseek_api_url,
                    headers=headers,
                    json=payload,
                    timeout=60  # Add a timeout to prevent hanging
                )
                
                # Check if the request was successful
                response.raise_for_status()
                
                # Parse the response
                result = response.json()
                print(f"    Received response from DeepSeek API")
                
                # Extract the content from the response
                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0]["message"]["content"]
                    print(f"    Response length: {len(content)} characters")
                    
                    # Save raw response for debugging
                    raw_response = content
                    
                    # Parse the content
                    findings = self._parse_deepseek_response(content)
                    print(f"    Extracted {len(findings)} findings from response")
                    
                    # Add raw response to findings
                    if len(findings) == 0:
                        # If no structured findings were found, create a placeholder with the raw response
                        findings = [{
                            "headline": "Raw DeepSeek Response",
                            "analysis": raw_response[:500] + "..." if len(raw_response) > 500 else raw_response,
                            "cve": "N/A",
                            "key_functions": "N/A",
                            "classification": "N/A",
                            "raw_response": raw_response
                        }]
                    else:
                        # Add raw response to each finding
                        for finding in findings:
                            finding["raw_response"] = raw_response
                    
                    return findings
                else:
                    print(f"    Unexpected response format: {result}")
                    if attempt < max_retries - 1:
                        print(f"    Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        # Return the error as a finding
                        return [{
                            "headline": "DeepSeek API Error",
                            "analysis": f"Unexpected response format: {json.dumps(result)[:500]}...",
                            "cve": "N/A",
                            "key_functions": "N/A",
                            "classification": "N/A",
                            "raw_response": json.dumps(result)
                        }]
                    
            except requests.exceptions.RequestException as e:
                print(f"    Error calling DeepSeek API (attempt {attempt+1}/{max_retries}): {e}")
                error_details = ""
                if hasattr(e, 'response') and e.response:
                    print(f"    Status code: {e.response.status_code}")
                    print(f"    Response: {e.response.text}")
                    error_details = f"Status code: {e.response.status_code}, Response: {e.response.text[:300]}..."
                
                if attempt < max_retries - 1:
                    print(f"    Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    # Return the error as a finding
                    return [{
                        "headline": "DeepSeek API Request Error",
                        "analysis": f"Error calling DeepSeek API: {str(e)[:500]}... {error_details}",
                        "cve": "N/A",
                        "key_functions": "N/A",
                        "classification": "N/A",
                        "raw_response": f"Error: {str(e)}, Details: {error_details}"
                    }]

    def _create_analysis_prompt(self, code_data, vulnerabilities):
        """
        Create a structured prompt for DeepSeek based on provided code snippets and vulnerabilities.
        
        Args:
            code_data (list): List of dictionaries containing file paths and content of code snippets.
            vulnerabilities (list): List of vulnerabilities associated with the repository.
        
        Returns:
            str: A formatted string prompt for DeepSeek to analyze the code snippets for potential security issues.
        """
        
        # Create a list of vulnerability references with related CVEs
        vulnerability_references = []
        for vuln in vulnerabilities:
            # Get related CVEs for each vulnerability
            cves = self.get_related_cves(vuln["id"])
            vulnerability_references.append({
                "id": vuln["id"],
                "details": vuln["details"],
                "severity": vuln["severity"],
                "score": vuln["score"],
                "related_cves": cves
            })
        
        # Start constructing the prompt with an introductory message
        prompt = """
You are an expert security analyst specializing in identifying software vulnerabilities. Your task is to analyze code revisions and assess the likelihood of introduced vulnerabilities.

Instructions:

1.  Analyze the provided codebase revision for potential vulnerabilities. Consider common vulnerability types, including but not limited to those listed in the provided CVEs/CWEs. Pay close attention to changes in code logic, data flow, and function calls.
2.  For each potential vulnerability identified, provide the following information in a structured format:

    Headline: A concise and descriptive title for the vulnerability.
    Analysis: A detailed explanation of the vulnerability, including:
        * The specific code changes that introduced or exacerbated the vulnerability.
        * The potential impact or exploit scenario.
        * Why this change is concerning from a security perspective.
    Most Relevant CVE/CWE:** The most relevant Common Vulnerabilities and Exposures (CVE) or Common Weakness Enumeration (CWE) identifier that categorizes the vulnerability type. If a direct match is not available, provide the closest applicable CVE/CWE.
    List of Most Concerned Functions: A list of the function names within the provided code revision that are most directly involved in the vulnerability.
    List of Most Concerned Filenames: A list of the filenames within the provided code revision that are most directly involved in the vulnerability.
    Classification: A classification of the likelihood of this being a real, exploitable vulnerability:
        * "Very Promising": The vulnerability is highly likely to be exploitable and poses a significant security risk. Requires immediate attention.
        * "Slightly Promising": The vulnerability has the potential to be exploitable, but the risk is lower or requires specific conditions. Further investigation is warranted.
        * "Not Promising": The code change is unlikely to introduce a real vulnerability. This requires less urgent attention.

3.  Present your findings in a clear and organized manner. If no vulnerabilities are found, explicitly state "No vulnerabilities found."

4.  Strictly adhere to the output format. Inconsistent formatting will be penalized.

Output Format:

\[
    {
        "vulnerabilities": \[
            {
                "headline": "\[Vulnerability Headline 1]",
                "analysis": "\[Detailed analysis of vulnerability 1]",
                "most_relevant_cve_cwe": "\[CVE/CWE Identifier 1]",
                "most_concerned_functions": \["function1", "function2"\],
                "most_concerned_filenames": \["file1.txt",a "file2.c"\],
                "classification": "\[Very Promising | Slightly Promising | Not Promising]"
            },
            {
                "headline": "\[Vulnerability Headline 2]",
                "analysis": "\[Detailed analysis of vulnerability 2]",
                "most_relevant_cve_cwe": "\[CVE/CWE Identifier 2]",
                 "most_concerned_functions": \["functionA", "functionB", "functionC"\],
                "most_concerned_filenames": \["fileX.py" ],
                "classification": "\[Very Promising | Slightly Promising | Not Promising]"
            },
            // ... more vulnerabilities as needed
        ]
    }
]
CODE SNIPPETS:
"""
        
        # Add code snippets to the prompt, respecting a character limit
        total_chars = 0
        for file in code_data:
            # Check if adding the file would exceed the character limit
            if total_chars + len(file["content"]) > 50000:  # Limit for LLM context
                prompt += f"\n[Additional files omitted due to size constraints]\n"
                break
            
            # Append the file path and content to the prompt
            prompt += f"\n--- {file['path']} ---\n{file['content']}\n"
            total_chars += len(file["content"])
        
        # Add reference information for vulnerabilities
        prompt += "\nREFERENCE VULNERABILITIES:\n"
        for vuln in vulnerability_references:
            prompt += f"\nID: {vuln['id']}\n"
            prompt += f"DETAILS: {vuln['details']}\n"
            prompt += f"SEVERITY: {vuln['severity'] if vuln['severity'] else 'Unknown'}\n"
            prompt += f"SCORE: {vuln['score'] if vuln['score'] else 'Unknown'}\n"
            if vuln['related_cves']:
                prompt += f"RELATED CVEs: {', '.join(vuln['related_cves'])}\n"
        
        # Conclude the prompt with instructions for analysis
        prompt += """
Please analyze the code carefully and return your findings in the specified format.
If no vulnerabilities are found, state this clearly.
"""
        return prompt

    def _parse_deepseek_response(self, response):
        """Parse the response from DeepSeek API into a structured format
        
        Args:
            response (str): The response from DeepSeek API
        
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
        
        # First, try to extract "No vulnerabilities found" statement
        if "No vulnerabilities found" in response:
            print("    DeepSeek reported no vulnerabilities found")
            return []
        
        # Try to parse JSON response first
        try:
            # Find the JSON part in the response (it might be surrounded by other text)
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_text = response[json_start:json_end]
                json_data = json.loads(json_text)
                
                if isinstance(json_data, list) and len(json_data) > 0 and "vulnerabilities" in json_data[0]:
                    vulns = json_data[0]["vulnerabilities"]
                    for vuln in vulns:
                        finding = {
                            "headline": vuln.get("headline", ""),
                            "analysis": vuln.get("analysis", ""),
                            "cve": vuln.get("most_relevant_cve_cwe", ""),
                            "key_functions": ", ".join(vuln.get("most_concerned_functions", [])),
                            "key_filenames": ", ".join(vuln.get("most_concerned_filenames", [])),
                            "classification": vuln.get("classification", "")
                        }
                        findings.append(finding)
                    return findings
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            print(f"    JSON parsing error: {e}. Falling back to text parsing.")
        
        # Iterate through each line of the response
        for line in response.split('\n'):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Parse the line based on the section
            if line.startswith("HEADLINE:") or line.startswith("Headline:"):
                # Start a new finding with the headline
                if current_finding and 'headline' in current_finding:
                    findings.append(current_finding)
                    current_finding = {}
                current_finding['headline'] = line.split(":", 1)[1].strip()
                current_section = 'headline'
            elif line.startswith("ANALYSIS:") or line.startswith("Analysis:"):
                # Set the analysis for the current finding
                current_finding['analysis'] = line.split(":", 1)[1].strip()
                current_section = 'analysis'
            elif line.startswith("MOST RELEVANT CVE:") or line.startswith("Most Relevant CVE:") or line.startswith("MOST RELEVANT CVE/CWE:") or line.startswith("Most Relevant CVE/CWE:"):
                # Set the CVE for the current finding
                current_finding['cve'] = line.split(":", 1)[1].strip()
                current_section = 'cve'
            elif line.startswith("KEY FUNCTIONS & FILENAMES:") or line.startswith("Key Functions & Filenames:") or line.startswith("MOST CONCERNED FUNCTIONS:") or line.startswith("Most Concerned Functions:"):
                # Set the key functions for the current finding
                current_finding['key_functions'] = line.split(":", 1)[1].strip()
                current_section = 'key_functions'
            elif line.startswith("MOST CONCERNED FILENAMES:") or line.startswith("Most Concerned Filenames:"):
                # Set the filenames for the current finding
                current_finding['key_filenames'] = line.split(":", 1)[1].strip()
                current_section = 'key_filenames'
            elif line.startswith("CLASSIFICATION:") or line.startswith("Classification:"):
                # Set the classification for the current finding
                current_finding['classification'] = line.split(":", 1)[1].strip()
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
        Scan a repository for vulnerabilities.
        
        The process involves:
        1. Getting all versions of the repository
        2. For each version, retrieving and filtering code
        3. Analyzing the code using DeepSeek API
        
        Args:
            repo_url (str): The URL of the repository to scan
        
        Returns:
            list: A list of dictionaries, each containing the results of a scan for a particular version of the repository
        """
        results = []
        
        print(f"Scanning repository: {repo_url}")
        versions = self.get_repository_versions(repo_url)
        vulnerabilities = self.get_vulnerabilities_for_repo(repo_url)
        
        # Process each version of the repository
        for version_info in versions:
            version = version_info["version"]
            version_id = version_info["id"]
            
            # Skip already processed versions
            version_key = f"{repo_url}:{version_id}"
            if version_key in self.processed_versions:
                print(f"  Skipping already processed version: {version}")
                continue
                
            print(f"  Processing version: {version}")
            
            try:
                # Clone repo and checkout version
                repo_dir = self.clone_repository(repo_url, version)
                
                # Get code files
                code_files = self.get_code_files(repo_dir)
                print(f"    Found {len(code_files)} relevant files")
                
                # Analyze with DeepSeek API
                analysis = self.analyze_with_deepseek(code_files, vulnerabilities)
                print(f"    Found {len(analysis)} vulnerabilities")
                
                # Create a result for this version
                version_result = {
                    "repo_url": repo_url,
                    "version": version,
                    "version_id": version_id,
                    "findings": analysis
                }
                
                # Add to results list
                results.append(version_result)
                
                # Save intermediate results after each version
                self.save_results([version_result])
                
                # Update processed versions
                self.processed_versions.add(version_key)
                
                # Clean up temporary directory
                subprocess.run(["rm", "-rf", repo_dir], check=True)
                
                print(f"    Successfully processed version {version}")
            except Exception as e:
                print(f"    Error processing version {version}: {e}")
                
                # Create an error finding
                error_finding = {
                    "headline": f"Error Processing {version}",
                    "analysis": f"An error occurred while processing this version: {str(e)}",
                    "cve": "N/A",
                    "key_functions": "N/A",
                    "classification": "Error",
                    "raw_error": str(e)
                }
                
                # Create a result with the error
                error_result = {
                    "repo_url": repo_url,
                    "version": version,
                    "version_id": version_id,
                    "findings": [error_finding]
                }
                
                # Add to results and save
                results.append(error_result)
                self.save_results([error_result])
                
                # Try to clean up if the directory exists
                try:
                    if 'repo_dir' in locals() and os.path.exists(repo_dir):
                        subprocess.run(["rm", "-rf", repo_dir], check=False)
                except:
                    pass 
            
class EvaluationMetrics:
    def __init__(self, ground_truth=None):
        """
        Initialize with optional ground truth data
        
        Ground truth should be a dictionary where the keys are strings of the format "repo+version" and the values are lists of dictionaries with the following keys:
            - headline: a string describing the vulnerability
            - analysis: a string describing the analysis
            - cve: a string containing the CVE number
            - key_functions: a string containing the key functions and filenames
            - classification: a string containing the classification of the vulnerability
        """
        self.ground_truth = ground_truth or {}
        self.results = []
    
    def add_result(self, result):
        """
        Add a scan result to the evaluation
        
        Args:
            result (dict): A dictionary containing the results of a scan for a particular version of the repository
        """
        self.results.append(result)
    
    def calculate_metrics(self):
        """Calculate evaluation metrics
        
        Returns a dictionary with the following keys:
            - total_repos_scanned: The number of unique repositories scanned
            - total_versions_scanned: The total number of versions scanned
            - vulnerability_counts: A dictionary with the number of vulnerabilities found by classification
            - avg_vulnerabilities_per_version: The average number of vulnerabilities found per version
            - precision: The precision of the model (TP / (TP + FP))
            - recall: The recall of the model (TP / (TP + FN))
            - f1_score: The F1 score of the model (2 * (precision * recall) / (precision + recall))
            - raw_response_stats: Statistics about raw responses
        """
        metrics = {
            "total_repos_scanned": len(set(r["repo_url"] for r in self.results)),
            "total_versions_scanned": len(self.results),
            "vulnerability_counts": {
                "very_promising": 0,
                "slightly_promising": 0,
                "not_promising": 0,
                "error": 0,
                "raw_response_only": 0
            },
            "raw_response_stats": {
                "total_responses": 0, 
                "avg_length": 0,
                "min_length": float('inf'),
                "max_length": 0
            },
            "avg_vulnerabilities_per_version": 0,
            "precision": None,
            "recall": None,
            "f1_score": None
        }
        
        # Count vulnerabilities by classification and collect raw response stats
        total_findings = 0
        total_raw_responses = 0
        total_raw_response_length = 0
        min_raw_response_length = float('inf')
        max_raw_response_length = 0
        
        for result in self.results:
            for finding in result["findings"]:
                total_findings += 1
                
                # Track raw responses
                if "raw_response" in finding:
                    total_raw_responses += 1
                    raw_length = len(finding["raw_response"])
                    total_raw_response_length += raw_length
                    min_raw_response_length = min(min_raw_response_length, raw_length)
                    max_raw_response_length = max(max_raw_response_length, raw_length)
                
                # Count by classification
                classification = finding.get("classification", "").lower()
                if "very promising" in classification:
                    metrics["vulnerability_counts"]["very_promising"] += 1
                elif "slightly promising" in classification:
                    metrics["vulnerability_counts"]["slightly_promising"] += 1
                elif "not promising" in classification:
                    metrics["vulnerability_counts"]["not_promising"] += 1
                elif "error" in classification:
                    metrics["vulnerability_counts"]["error"] += 1
                elif finding.get("headline") == "Raw DeepSeek Response":
                    metrics["vulnerability_counts"]["raw_response_only"] += 1
        
        # Calculate average vulnerabilities per version
        if metrics["total_versions_scanned"] > 0:
            metrics["avg_vulnerabilities_per_version"] = total_findings / metrics["total_versions_scanned"]
        
        # Calculate raw response statistics
        if total_raw_responses > 0:
            metrics["raw_response_stats"]["total_responses"] = total_raw_responses
            metrics["raw_response_stats"]["avg_length"] = total_raw_response_length / total_raw_responses
            metrics["raw_response_stats"]["min_length"] = min_raw_response_length if min_raw_response_length != float('inf') else 0
            metrics["raw_response_stats"]["max_length"] = max_raw_response_length
        
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
                        classification = finding.get("classification", "").lower()
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
    """Main entry point for the script
    
    This function connects to Neo4j, creates a VulnerabilityScanner object, and runs it
    on all repositories in the database. The results are saved to a JSON file.
    """
    # Neo4j connection details (update with actual values)
    uri = "bolt://localhost:7687"
    username = "neo4j"
    password = "jaguarai"
    
    # DeepSeek API key (replace with your actual API key)
    deepseek_api_key = "your_deepseek_api_key_here"
    
    # Results file path
    results_file = "vulnerability_results_debug.json"
    
    # Create a debug log file
    log_file = "vulnerability_scanner_debug.log"
    with open(log_file, 'w') as f:
        f.write(f"Starting vulnerability scan at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Create the scanner with specified results file
    scanner = VulnerabilityScanner(uri, username, password, deepseek_api_key, results_file=results_file)
    evaluator = EvaluationMetrics()
    
    try:
        # Get all repositories or specify particular ones
        repos = scanner.get_repositories()
        # For testing/debugging, you might want to limit to a few repositories
        # repos = ["https://github.com/abantecart/abantecart-src"]
        
        # Log the repositories to be scanned
        with open(log_file, 'a') as f:
            f.write(f"Found {len(repos)} repositories to scan\n")
            for repo in repos:
                f.write(f"  {repo}\n")
        
        # Process each repository with error handling
        for repo in repos:
            try:
                print(f"Starting scan of repository: {repo}")
                with open(log_file, 'a') as f:
                    f.write(f"Starting scan of repository: {repo}\n")
                
                results = scanner.scan_repository(repo)
                
                # Add results to evaluator
                for result in results:
                    evaluator.add_result(result)
                
                print(f"Completed scan of {repo}")
                with open(log_file, 'a') as f:
                    f.write(f"Completed scan of {repo}\n")
                    
            except Exception as e:
                print(f"Error scanning repository {repo}: {e}")
                with open(log_file, 'a') as f:
                    f.write(f"Error scanning repository {repo}: {e}\n")
                # Continue with next repository even if one fails
                continue
        
        # Calculate and save metrics
        metrics = evaluator.calculate_metrics()
        with open("evaluation_metrics_debug.json", "w") as f:
            # Save the evaluation metrics to a JSON file
            json.dump(metrics, f, indent=2)
        
        print("Evaluation metrics:")
        print(json.dumps(metrics, indent=2))
        with open(log_file, 'a') as f:
            f.write("Evaluation metrics:\n")
            f.write(json.dumps(metrics, indent=2) + "\n")
        
        print("All scans completed successfully!")
        with open(log_file, 'a') as f:
            f.write(f"All scans completed at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
    except Exception as e:
        print(f"Unexpected error in main function: {e}")
        with open(log_file, 'a') as f:
            f.write(f"Unexpected error in main function: {e}\n")
    finally:
        # Always close the scanner to properly shut down database connections
        scanner.close()


if __name__ == "__main__":
    main()
