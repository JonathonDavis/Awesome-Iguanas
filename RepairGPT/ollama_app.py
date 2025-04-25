import json
import random
import requests
import time
import argparse
import os
import datetime
import re
import logging
from collections import Counter
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

@dataclass
class VulnerabilityInfo:
    id: str
    summary: str
    details: Optional[str]
    published: Optional[str]
    modified: Optional[str]
    affected_packages: List[Dict]
    references: List[Dict]
    
@dataclass
class SecurityInsight:
    vulnerability_id: str
    severity: str
    affected_ecosystems: List[str]
    vulnerability_type: str
    impact_analysis: str
    remediation_steps: str
    exploitation_likelihood: str
    recommendation: str

class SecurityAnalyzer:
    def __init__(self, api_key=None, ollama_base_url="http://localhost:11434"):
        """Initialize the security analyzer with optional API keys."""
        self.api_key = api_key
        self.ollama_base_url = ollama_base_url
        
    def load_vulnerability_data(self, file_path: str) -> List[Dict[str, Any]]:
        """Load vulnerability data from a JSON file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return data
        except Exception as e:
            print(f"Error loading vulnerability data: {e}")
            return []
    
    def analyze_with_ollama(self, prompt: str, model: str = "llama3") -> str:
        """Generate analysis text using Ollama local model."""
        try:
            url = f"{self.ollama_base_url}/api/generate"
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False
            }
            
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "No response generated")
            else:
                return f"Error: Received status code {response.status_code} from Ollama API"
        except Exception as e:
            return f"Error calling Ollama API: {e}"
    
    def query_nist_nvd(self, cve_id: str) -> Dict[str, Any]:
        """Query the NIST NVD API for CVE details."""
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
            url = f"{base_url}{cve_id}"
            
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error querying NVD for {cve_id}: {response.status_code}")
                return {}
                
        except Exception as e:
            print(f"Exception querying NVD: {e}")
            return {}
    
    def get_package_info_from_package_index(self, package_name: str, ecosystem: str = "pypi") -> Dict[str, Any]:
        """Get package information from the appropriate package index."""
        try:
            if ecosystem.lower() == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()
            elif ecosystem.lower() == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()
            elif ecosystem.lower() == "rubygems":
                url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()
                    
            return {}
        except Exception as e:
            print(f"Error fetching package info for {package_name}: {e}")
            return {}
    
    def generate_package_analysis_prompt(self, package_name: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Create a prompt for analyzing a package and its vulnerabilities."""
        prompt = f"""You are a cybersecurity expert specializing in vulnerability analysis. 
        
        Please provide a detailed analysis of the package named '{package_name}' which has the following vulnerabilities:
        
        """
        
        for vuln in vulnerabilities:
            prompt += f"- {vuln.get('id', 'Unknown ID')}: {vuln.get('summary', 'No summary available')}\n"
            if vuln.get("details"):
                prompt += f"  Details: {vuln.get('details')}\n"
        
        prompt += """
        Please structure your analysis with the following sections:
        1. Package Overview (what the package does, its popularity, use cases)
        2. Vulnerability Assessment (analyze each vulnerability)
        3. Impact Analysis (how these vulnerabilities could affect systems)
        4. Remediation Steps (specific actions to mitigate these vulnerabilities)
        5. Lessons Learned (what developers can learn from these vulnerabilities)
        
        Focus on technical details and provide practical advice.
        """
        
        return prompt
    
    def generate_cve_analysis_prompt(self, cve_id: str, cve_data: Dict[str, Any]) -> str:
        """Create a prompt for analyzing a specific CVE."""
        description = "No description available"
        if cve_data and "result" in cve_data and "CVE_Items" in cve_data["result"]:
            if cve_data["result"]["CVE_Items"]:
                cve_item = cve_data["result"]["CVE_Items"][0]
                if "cve" in cve_item and "description" in cve_item["cve"]:
                    desc_data = cve_item["cve"]["description"]["description_data"]
                    if desc_data and len(desc_data) > 0:
                        description = desc_data[0].get("value", "No description available")
        
        prompt = f"""You are a cybersecurity expert specializing in vulnerability analysis.
        
        Please provide a detailed analysis of the following CVE:
        
        CVE ID: {cve_id}
        Description: {description}
        
        Please structure your analysis with the following sections:
        1. Vulnerability Overview
        2. Technical Details
        3. Exploitation Methods
        4. Potential Impact
        5. Mitigation Strategies
        
        Focus on technical details, real-world implications, and provide practical advice for security professionals.
        """
        
        return prompt
    
    def analyze_repositories(self, repositories: List[Dict[str, Any]], sample_count: int = 5) -> Dict[str, Any]:
        """Analyze repositories and generate detailed analyses for samples of packages and CVEs."""
        results = {
            "repository_analyses": [],
            "package_analyses": [],
            "cve_analyses": []
        }
        
        for repo in repositories:
            repo_url = repo.get("repository_url", "Unknown")
            vuln_count = repo.get("vulnerability_count", 0)
            
            # Add basic repository info
            repo_analysis = {
                "repository_url": repo_url,
                "vulnerability_count": vuln_count,
                "affected_packages_count": len(repo.get("affected_packages", [])),
                "cve_count": len(repo.get("cve_ids", []))
            }
            results["repository_analyses"].append(repo_analysis)
            
            # Sample packages and CVEs for detailed analysis
            packages_to_analyze = self.sample_items(repo.get("affected_packages", []), sample_count)
            cves_to_analyze = self.sample_items(repo.get("cve_ids", []), sample_count)
            
            # Analyze sampled packages
            for package in packages_to_analyze:
                # Get any vulnerabilities related to this package
                package_vulns = self.find_package_vulnerabilities(package, repo)
                
                # Generate and run analysis
                prompt = self.generate_package_analysis_prompt(package, package_vulns)
                analysis = self.analyze_with_ollama(prompt)
                
                results["package_analyses"].append({
                    "package_name": package,
                    "repository": repo_url,
                    "vulnerabilities": package_vulns,
                    "analysis": analysis
                })
                
                # Add delay to avoid overloading the API
                time.sleep(1)
            
            # Analyze sampled CVEs
            for cve_id in cves_to_analyze:
                # Get CVE details from NVD
                cve_data = self.query_nist_nvd(cve_id)
                
                # Generate and run analysis
                prompt = self.generate_cve_analysis_prompt(cve_id, cve_data)
                analysis = self.analyze_with_ollama(prompt)
                
                results["cve_analyses"].append({
                    "cve_id": cve_id,
                    "repository": repo_url,
                    "analysis": analysis
                })
                
                # Add delay to avoid overloading the API
                time.sleep(1)
        
        return results

    def find_package_vulnerabilities(self, package_name: str, repo: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find vulnerabilities for a specific package in the repository data."""
        # For this example, we'll create simple dummy vulnerability data
        # In a real implementation, you would extract this from the repository data or query a vulnerability database
        
        # Create 1-3 random vulnerabilities for the package
        vuln_count = random.randint(1, 3)
        vulnerabilities = []
        
        for i in range(vuln_count):
            if repo.get("cve_ids") and len(repo.get("cve_ids", [])) > 0:
                # Use a real CVE ID if available
                cve_id = random.choice(repo.get("cve_ids"))
            else:
                cve_id = f"CVE-202{random.randint(0, 4)}-{random.randint(10000, 99999)}"
                
            vulnerabilities.append({
                "id": cve_id,
                "summary": f"Vulnerability affecting {package_name}",
                "details": f"This is a simulated vulnerability for demonstration purposes affecting {package_name}."
            })
            
        return vulnerabilities
    
    def sample_items(self, items: List[str], count: int) -> List[str]:
        """Sample a specified number of items from a list."""
        if not items:
            return []
            
        sample_count = min(count, len(items))
        return random.sample(items, sample_count)
    
    def save_results_to_file(self, results: Dict[str, Any], output_file: str) -> None:
        """Save analysis results to a JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def generate_markdown_report(self, results: Dict[str, Any], output_file: str) -> None:
        """Generate a markdown report from the analysis results."""
        try:
            with open(output_file, 'w') as f:
                f.write("# Security Vulnerability Analysis Report\n\n")
                
                # Repository summary
                f.write("## Repository Overview\n\n")
                for repo in results.get("repository_analyses", []):
                    f.write(f"### {repo.get('repository_url', 'Unknown Repository')}\n\n")
                    f.write(f"- Total vulnerabilities: {repo.get('vulnerability_count', 0)}\n")
                    f.write(f"- Affected packages: {repo.get('affected_packages_count', 0)}\n")
                    f.write(f"- CVEs: {repo.get('cve_count', 0)}\n\n")
                
                # Package analyses
                f.write("## Package Vulnerability Analyses\n\n")
                for pkg_analysis in results.get("package_analyses", []):
                    f.write(f"### {pkg_analysis.get('package_name', 'Unknown Package')}\n\n")
                    f.write(f"Repository: {pkg_analysis.get('repository', 'Unknown')}\n\n")
                    
                    f.write("#### Vulnerabilities\n\n")
                    for vuln in pkg_analysis.get("vulnerabilities", []):
                        f.write(f"- **{vuln.get('id', 'Unknown')}**: {vuln.get('summary', 'No summary')}\n")
                    
                    f.write("\n#### Analysis\n\n")
                    f.write(f"{pkg_analysis.get('analysis', 'No analysis available')}\n\n")
                    f.write("---\n\n")
                
                # CVE analyses
                f.write("## CVE Analyses\n\n")
                for cve_analysis in results.get("cve_analyses", []):
                    f.write(f"### {cve_analysis.get('cve_id', 'Unknown CVE')}\n\n")
                    f.write(f"Repository: {cve_analysis.get('repository', 'Unknown')}\n\n")
                    
                    f.write("#### Analysis\n\n")
                    f.write(f"{cve_analysis.get('analysis', 'No analysis available')}\n\n")
                    f.write("---\n\n")
                
            print(f"Markdown report saved to {output_file}")
        except Exception as e:
            print(f"Error generating markdown report: {e}")

class Neo4jSecurityAnalyzer:
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "jaguarai",
        log_level: str = "INFO"
    ):
        """Initialize the security analyzer with connection parameters."""
        # Setup logging
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {log_level}")
            
        logging.basicConfig(
            level=numeric_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize Neo4j connection
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            self.driver.verify_connectivity()
            self.logger.info("Successfully connected to Neo4j database")
        except (ServiceUnavailable, AuthError) as e:
            self.logger.error(f"Failed to connect to Neo4j: {str(e)}")
            raise
        
    def close(self) -> None:
        """Safely close the Neo4j connection."""
        if hasattr(self, 'driver'):
            self.driver.close()
            self.logger.info("Neo4j connection closed")

    def query_neo4j(self, query: str, params: Dict = None) -> List[Dict]:
        """Execute a Cypher query against Neo4j."""
        try:
            with self.driver.session() as session:
                result = session.run(query, params or {})
                return result.data()
        except Exception as e:
            self.logger.error(f"Neo4j query error: {str(e)}")
            raise

    def get_database_schema(self) -> Dict:
        """Retrieve the database schema structure."""
        self.logger.info("Retrieving database schema...")
        
        # Get node labels
        labels_query = "CALL db.labels()"
        labels = self.query_neo4j(labels_query)
        
        schema = {
            "node_labels": [label["label"] for label in labels],
            "relationships": [],
            "properties": {}
        }
        
        # Get relationship types
        rel_query = "CALL db.relationshipTypes()"
        relationships = self.query_neo4j(rel_query)
        schema["relationship_types"] = [rel["relationshipType"] for rel in relationships]
        
        # Get properties for each node label
        for label in schema["node_labels"]:
            # Use string formatting as label names are safe from db.labels()
            prop_query = f"MATCH (n:{label}) WITH n LIMIT 1 RETURN keys(n) as properties"
            props = self.query_neo4j(prop_query)
            if props and "properties" in props[0]:
                schema["properties"][label] = props[0]["properties"]
        
        # Get common relationship patterns
        pattern_query = """
        MATCH (a)-[r]->(b)
        RETURN labels(a)[0] as source_label,
               type(r) as relationship,
               labels(b)[0] as target_label,
               count(*) as frequency
        ORDER BY frequency DESC
        LIMIT 20
        """
        
        patterns = self.query_neo4j(pattern_query)
        schema["relationships"] = patterns
        
        return schema

    def get_vulnerability_details(self, vuln_id: str = None, limit: int = 10) -> List[Dict]:
        """Get details about vulnerabilities from Neo4j."""
        if vuln_id:
            query = """
            MATCH (vuln:Vulnerability {id: $vuln_id})
            OPTIONAL MATCH (cve:CVE)-[]->(vuln)
            OPTIONAL MATCH (vuln)-[]->(pkg:Package)
            OPTIONAL MATCH (ref:Reference)-[]->(cve)
            RETURN vuln.id as id, 
                   vuln.summary as summary,
                   vuln.details as details,
                   vuln.published as published,
                   vuln.modified as modified,
                   vuln.affected as affected_json,
                   collect(DISTINCT cve.id) as cve_ids,
                   collect(DISTINCT {name: pkg.name, ecosystem: pkg.ecosystem}) as affected_packages,
                   collect(DISTINCT {url: ref.url, type: ref.type}) as references
            """
            params = {"vuln_id": vuln_id}
        else:
            query = """
            MATCH (vuln:Vulnerability)
            OPTIONAL MATCH (cve:CVE)-[]->(vuln)
            OPTIONAL MATCH (vuln)-[]->(pkg:Package)
            OPTIONAL MATCH (ref:Reference)-[]->(cve)
            RETURN vuln.id as id, 
                   vuln.summary as summary,
                   vuln.details as details,
                   vuln.published as published,
                   vuln.modified as modified,
                   vuln.affected as affected_json,
                   collect(DISTINCT cve.id) as cve_ids,
                   collect(DISTINCT {name: pkg.name, ecosystem: pkg.ecosystem}) as affected_packages,
                   collect(DISTINCT {url: ref.url, type: ref.type}) as references
            LIMIT $limit
            """
            params = {"limit": limit}
        
        return self.query_neo4j(query, params)

    def get_cve_details(self, cve_id: str = None, limit: int = 10) -> List[Dict]:
        """Get details about CVEs from Neo4j."""
        if cve_id:
            query = """
            MATCH (cve:CVE {id: $cve_id})
            OPTIONAL MATCH (cve)-[]->(vuln:Vulnerability)
            OPTIONAL MATCH (vuln)-[]->(pkg:Package)
            OPTIONAL MATCH (ref:Reference)-[]->(cve)
            OPTIONAL MATCH (repo:Repository)<-[]-(pkg)
            RETURN cve.id as id, 
                   collect(DISTINCT {
                     id: vuln.id, 
                     summary: vuln.summary, 
                     details: vuln.details, 
                     published: vuln.published, 
                     modified: vuln.modified
                   }) as vulnerabilities, 
                   collect(DISTINCT {
                     name: pkg.name, 
                     ecosystem: pkg.ecosystem
                   }) as affected_packages,
                   collect(DISTINCT {
                     url: ref.url, 
                     type: ref.type
                   }) as references,
                   collect(DISTINCT {
                     url: repo.url
                   }) as repositories
            """
            params = {"cve_id": cve_id}
        else:
            query = """
            MATCH (cve:CVE)
            OPTIONAL MATCH (cve)-[]->(vuln:Vulnerability)
            OPTIONAL MATCH (vuln)-[]->(pkg:Package)
            OPTIONAL MATCH (ref:Reference)-[]->(cve)
            OPTIONAL MATCH (repo:Repository)<-[]-(pkg)
            RETURN cve.id as id, 
                   collect(DISTINCT {
                     id: vuln.id, 
                     summary: vuln.summary, 
                     details: vuln.details, 
                     published: vuln.published, 
                     modified: vuln.modified
                   }) as vulnerabilities, 
                   collect(DISTINCT {
                     name: pkg.name, 
                     ecosystem: pkg.ecosystem
                   }) as affected_packages,
                   collect(DISTINCT {
                     url: ref.url, 
                     type: ref.type
                   }) as references,
                   collect(DISTINCT {
                     url: repo.url
                   }) as repositories
            LIMIT $limit
            """
            params = {"limit": limit}
        
        return self.query_neo4j(query, params)

    def get_package_vulnerabilities(self, package_name: str = None, ecosystem: str = None, limit: int = 10) -> List[Dict]:
        """Get vulnerabilities associated with packages."""
        if package_name and ecosystem:
            query = """
            MATCH (pkg:Package {name: $package_name, ecosystem: $ecosystem})
            OPTIONAL MATCH (vuln:Vulnerability)-[]->(pkg)
            OPTIONAL MATCH (cve:CVE)-[]->(vuln)
            OPTIONAL MATCH (ver:Version)<-[]-(pkg)
            OPTIONAL MATCH (repo:Repository)<-[]-(pkg)
            RETURN pkg.name as package_name,
                   pkg.ecosystem as ecosystem,
                   collect(DISTINCT {
                     id: vuln.id, 
                     summary: vuln.summary, 
                     details: vuln.details
                   }) as vulnerabilities,
                   collect(DISTINCT cve.id) as cves,
                   collect(DISTINCT {
                     version: ver.version, 
                     size: ver.size, 
                     primary_language: ver.primary_language
                   }) as versions,
                   collect(DISTINCT repo.url) as repositories
            """
            params = {"package_name": package_name, "ecosystem": ecosystem}
        elif package_name:
            query = """
            MATCH (pkg:Package {name: $package_name})
            OPTIONAL MATCH (vuln:Vulnerability)-[]->(pkg)
            OPTIONAL MATCH (cve:CVE)-[]->(vuln)
            OPTIONAL MATCH (ver:Version)<-[]-(pkg)
            OPTIONAL MATCH (repo:Repository)<-[]-(pkg)
            RETURN pkg.name as package_name,
                   pkg.ecosystem as ecosystem,
                   collect(DISTINCT {
                     id: vuln.id, 
                     summary: vuln.summary, 
                     details: vuln.details
                   }) as vulnerabilities,
                   collect(DISTINCT cve.id) as cves,
                   collect(DISTINCT {
                     version: ver.version, 
                     size: ver.size, 
                     primary_language: ver.primary_language
                   }) as versions,
                   collect(DISTINCT repo.url) as repositories
            """
            params = {"package_name": package_name}
        else:
            query = """
            MATCH (pkg:Package)
            OPTIONAL MATCH (vuln:Vulnerability)-[]->(pkg)
            OPTIONAL MATCH (cve:CVE)-[]->(vuln)
            OPTIONAL MATCH (ver:Version)<-[]-(pkg)
            OPTIONAL MATCH (repo:Repository)<-[]-(pkg)
            RETURN pkg.name as package_name,
                   pkg.ecosystem as ecosystem,
                   collect(DISTINCT {
                     id: vuln.id, 
                     summary: vuln.summary, 
                     details: vuln.details
                   }) as vulnerabilities,
                   collect(DISTINCT cve.id) as cves,
                   collect(DISTINCT {
                     version: ver.version, 
                     size: ver.size, 
                     primary_language: ver.primary_language
                   }) as versions,
                   collect(DISTINCT repo.url) as repositories
            LIMIT $limit
            """
            params = {"limit": limit}
        
        return self.query_neo4j(query, params)

    def get_ecosystem_vulnerabilities(self, ecosystem: str, limit: int = 10) -> List[Dict]:
        """Get vulnerabilities associated with a particular ecosystem."""
        query = """
        MATCH (pkg:Package {ecosystem: $ecosystem})
        OPTIONAL MATCH (vuln:Vulnerability)-[]->(pkg)
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        RETURN pkg.name as package_name,
               pkg.ecosystem as ecosystem,
               collect(DISTINCT {
                 id: vuln.id, 
                 summary: vuln.summary, 
                 details: vuln.details
               }) as vulnerabilities,
               collect(DISTINCT cve.id) as cves
        LIMIT $limit
        """
        params = {"ecosystem": ecosystem, "limit": limit}
        
        return self.query_neo4j(query, params)

    def get_repositories_with_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """Get repositories with associated vulnerabilities."""
        self.logger.info(f"Executing get_repositories_with_vulnerabilities with limit={limit}")
        
        # Using the exact relationship structure from the database
        query = """
        MATCH (repo:Repository)
        MATCH (vuln:Vulnerability)-[:FOUND_IN]->(repo)
        WITH repo, count(DISTINCT vuln) as vuln_count
        ORDER BY vuln_count DESC
        LIMIT $limit
        
        MATCH (v:Vulnerability)-[:FOUND_IN]->(repo)
        OPTIONAL MATCH (pkg:Package)-[:AFFECTED_BY]->(v)
        OPTIONAL MATCH (cve:CVE)-[:IDENTIFIED_AS]->(v)
        
        RETURN repo.url as repository_url,
               vuln_count as vulnerability_count,
               collect(DISTINCT pkg.name) as affected_packages,
               collect(DISTINCT cve.id) as cve_ids
        """
        
        try:
            return self.query_neo4j(query, {"limit": limit})
        except Exception as e:
            self.logger.error(f"Error executing repo query: {str(e)}")
            
            # Simpler fallback query if the main one fails
            fallback_query = """
            MATCH (repo:Repository)
            OPTIONAL MATCH (vuln:Vulnerability)-[:FOUND_IN]->(repo)
            WITH repo, count(DISTINCT vuln) as vuln_count
            ORDER BY vuln_count DESC
            LIMIT $limit
            RETURN repo.url as repository_url,
                vuln_count as vulnerability_count,
                [] as affected_packages,
                [] as cve_ids
            """
            
            try:
                return self.query_neo4j(fallback_query, {"limit": limit})
            except Exception as e2:
                self.logger.error(f"Error executing fallback repo query: {str(e2)}")
                
                # Last resort - just return repositories
                last_resort_query = """
                MATCH (repo:Repository)
                RETURN repo.url as repository_url, 
                    0 as vulnerability_count,
                    [] as affected_packages,
                    [] as cve_ids
                LIMIT $limit
                """
                return self.query_neo4j(last_resort_query, {"limit": limit})

    def count_nodes_by_label(self) -> Dict[str, int]:
        """Count nodes by label in the database."""
        results = {}
        labels = [label["label"] for label in self.query_neo4j("CALL db.labels()")]
        for label in labels:
            # Instead of parameter substitution for the label, use string formatting
            # This is safe since the labels come from db.labels()
            query = f"""
            MATCH (n:{label})
            RETURN count(n) as count
            """
            
            count_result = self.query_neo4j(query)
            if count_result:
                results[label] = count_result[0]["count"]
            else:
                results[label] = 0
                    
        return results

    # Analysis methods

    def _determine_vulnerability_type(self, summary: str, details: str = None) -> str:
        """Determine vulnerability type based on text analysis."""
        # Combine summary and details, handling None values
        summary = summary or ""
        details = details or ""
        text = (summary + " " + details).lower()  # Convert to lowercase for case-insensitive matching
        
        vulnerability_types = {
            "buffer overflow": ["buffer overflow", "stack overflow", "heap overflow", "buffer over-read"],
            "sql injection": ["sql injection", "sqli", "database injection"],
            "cross-site scripting": ["xss", "cross-site scripting", "script injection"],
            "cross-site request forgery": ["csrf", "cross-site request forgery"],
            "path traversal": ["path traversal", "directory traversal", "../", "..\\"],
            "command injection": ["command injection", "command execution", "code execution", "rce", "remote code execution"],
            "denial of service": ["denial of service", "dos", "crash", "resource exhaustion"],
            "information disclosure": ["information disclosure", "information leak", "data leak", "sensitive data"],
            "authentication bypass": ["auth bypass", "authentication bypass", "privilege escalation"],
            "memory corruption": ["memory corruption", "use-after-free", "double free"],
            "improper input validation": ["input validation", "improper validation", "improper sanitization"]
        }
        
        # Check for each vulnerability type
        for vuln_type, patterns in vulnerability_types.items():
            for pattern in patterns:
                if pattern in text:
                    return vuln_type.title()
                    
        return "Unknown"
        
    def _determine_severity(self, summary: str, details: str = None, packages: List[Dict] = None) -> str:
        """
        Determine vulnerability severity based on text analysis of the summary and details.
        
        This method checks for explicit severity mentions in the text, and then uses heuristics to determine the severity.
        """
        # Combine summary and details, handling None values
        text = (summary or "") + " " + (details or "")
        
        # Check for explicit severity mentions
        if "critical" in text or "severe" in text:
            # If the text explicitly mentions "critical" or "severe", it's CRITICAL
            return "CRITICAL"
        elif "high" in text or "important" in text:
            # If the text explicitly mentions "high" or "important", it's HIGH
            return "HIGH"
        elif "medium" in text or "moderate" in text:
            # If the text explicitly mentions "medium" or "moderate", it's MEDIUM
            return "MEDIUM"
        elif "low" in text:
            # If the text explicitly mentions "low", it's LOW
            return "LOW"
            
        # Check for high severity indicators in the text
        high_severity_indicators = [
            # Remote code execution is always HIGH
            "remote code execution", "rce", "arbitrary code execution",
            # Command execution is always HIGH
            "command execution", "privilege escalation", "authentication bypass",
            # SQL injection is always HIGH
            "sql injection", "arbitrary file read", "arbitrary file write"
        ]
        
        for indicator in high_severity_indicators:
            if indicator in text:
                # If any of the high severity indicators are present, it's HIGH
                return "HIGH"
        
        # Use a simple heuristic based on the number of affected packages
        if packages and len(packages) > 5:
            # If more than 5 packages are affected, it's HIGH
            return "HIGH"
        elif packages and len(packages) > 2:
            # If more than 2 packages are affected, it's MEDIUM
            return "MEDIUM"
        # Default to medium if uncertain
        return "MEDIUM"

    def _generate_remediation_steps(self, vuln_type: str, packages: List[Dict] = None) -> str:
        """Generate remediation steps based on vulnerability type."""
        general_advice = "Update to the latest patched version of the affected software components."
        
        if not packages:
            return general_advice
            
        remediation = general_advice + " Specifically:\n"
        
        for pkg in packages:
            pkg_name = pkg.get("name", "unknown")
            eco = pkg.get("ecosystem", "unknown")
            remediation += f"- Update {pkg_name} ({eco}) to the latest secure version\n"
            
        type_specific_advice = {
            "Buffer Overflow": "Implement proper bounds checking and input validation.",
            "SQL Injection": "Use parameterized queries and input validation.",
            "Cross-Site Scripting": "Implement proper output encoding and content security policies.",
            "Path Traversal": "Validate and sanitize file paths, use path canonicalization.",
            "Command Injection": "Avoid passing user input to command interpreters, use allow-lists.",
            "Denial Of Service": "Implement rate limiting and resource consumption controls.",
            "Information Disclosure": "Audit information leakage vectors and implement proper access controls.",
            "Authentication Bypass": "Review authentication mechanisms and implement multi-factor authentication where possible.",
            "Memory Corruption": "Update to versions with memory safety improvements or consider memory-safe alternatives."
        }
        
        if vuln_type in type_specific_advice:
            remediation += "\nAdditional recommendation: " + type_specific_advice[vuln_type]
            
        return remediation

    def _extract_affected_ecosystems(self, packages: List[Dict]) -> List[str]:
        """Extract unique affected ecosystems from package list."""
        self.logger.debug(f"_extract_affected_ecosystems called with packages={packages}")
        
        if packages is None:
            self.logger.warning("packages parameter is None, returning empty list")
            return []
            
        if not isinstance(packages, list):
            self.logger.warning(f"packages parameter is not a list (type: {type(packages)}), returning empty list")
            return []
            
        ecosystems = set()
        for pkg in packages:
            if not isinstance(pkg, dict):
                self.logger.warning(f"Package is not a dict (type: {type(pkg)}), skipping")
                continue
                
            eco = pkg.get("ecosystem")
            if eco:
                ecosystems.add(eco)
        return list(ecosystems)
    
    def _determine_exploitation_likelihood(self, vuln_type: str, references: List[Dict] = None) -> str:
        """
        Determine exploitation likelihood based on vulnerability type and references.
        """
        self.logger.debug(f"_determine_exploitation_likelihood called with vuln_type={vuln_type}")
        
        # High-risk vulnerability types
        high_risk_types = ["Remote Code Execution", "SQL Injection", "Authentication Bypass", 
                        "Command Injection", "Cross-Site Scripting"]
        
        # Medium-risk vulnerability types
        medium_risk_types = ["Information Disclosure", "Path Traversal", "Cross-Site Request Forgery",
                        "Denial Of Service"]
        
        # Check if there are any exploit references
        has_exploit = False
        if references:
            self.logger.debug(f"Checking {len(references)} references")
            for i, ref in enumerate(references):
                self.logger.debug(f"Reference {i}: {ref}")
                # Handle potential None values using or operator
                url = "" if ref.get("url") is None else str(ref.get("url")).lower()
                ref_type = "" if ref.get("type") is None else str(ref.get("type")).lower()
                if "exploit" in url or "exploit" in ref_type or "poc" in url or "proof of concept" in url:
                    has_exploit = True
                    break
        else:
            self.logger.debug("No references to check")
        
        if vuln_type in high_risk_types or has_exploit:
            return "HIGH"
        elif vuln_type in medium_risk_types:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_impact_analysis(self, vuln_type: str, summary: str, packages: List[Dict] = None) -> str:
        """Generate impact analysis based on vulnerability type and affected packages."""
        impact = f"This {vuln_type} vulnerability could potentially "
        
        # Map vulnerability types to their potential impact
        type_impacts = {
            "Buffer Overflow": "lead to arbitrary code execution, application crashes, or memory corruption.",
            "SQL Injection": "allow attackers to read, modify, or delete database content, potentially accessing sensitive information or bypassing authentication.",
            "Cross-Site Scripting": "enable attackers to execute malicious scripts in users' browsers, potentially leading to session hijacking, credential theft, or defacement.",
            "Cross-Site Request Forgery": "trick users into performing unwanted actions while authenticated, potentially leading to account compromise or unauthorized data modification.",
            "Path Traversal": "allow attackers to access files outside intended directories, potentially exposing sensitive configuration or system files.",
            "Command Injection": "enable execution of arbitrary system commands with the privileges of the application, potentially leading to complete system compromise.",
            "Denial Of Service": "allow attackers to disrupt service availability by exhausting system resources or causing application crashes.",
            "Information Disclosure": "expose sensitive information such as internal system details, user data, or authentication credentials.",
            "Authentication Bypass": "allow unauthorized access to protected functionality or data, potentially leading to privilege escalation.",
            "Memory Corruption": "cause application instability, crashes, or potentially lead to arbitrary code execution.",
            "Improper Input Validation": "lead to various attacks including injection attacks, bypassing security controls, or application logic errors."
        }
        
        if vuln_type in type_impacts:
            impact += type_impacts[vuln_type]
        else:
            impact += "compromise affected systems in various ways depending on the specific context of deployment."
        
        # Add ecosystem/package specific impact
        if packages and len(packages) > 0:
            ecosystems = self._extract_affected_ecosystems(packages)
            package_count = len(packages)
            
            impact += f"\n\nThe vulnerability affects {package_count} package(s) across {len(ecosystems)} ecosystem(s)"
            if ecosystems:
                impact += f" ({', '.join(ecosystems)})"
            impact += "."
            
            # Add more specific impact based on summary
            if summary:
                impact += f"\n\nAccording to the vulnerability summary: \"{summary}\""
        
        return impact

    def _generate_recommendation(self, severity: str, vuln_type: str, remediation_steps: str) -> str:
        """Generate a security recommendation based on severity and type."""
        if severity == "CRITICAL":
            return f"URGENT: Immediately patch this {vuln_type} vulnerability. {remediation_steps} Consider temporarily isolating affected systems if immediate patching is not possible."
        elif severity == "HIGH":
            return f"HIGH PRIORITY: This {vuln_type} vulnerability should be addressed as soon as possible. {remediation_steps}"
        elif severity == "MEDIUM":
            return f"MEDIUM PRIORITY: Schedule remediation of this {vuln_type} vulnerability within your normal patch cycle. {remediation_steps}"
        else:
            return f"LOW PRIORITY: Address this {vuln_type} vulnerability as resources permit. {remediation_steps}"

    def analyze_vulnerability(self, vuln_id: str) -> SecurityInsight:
        """Analyze a specific vulnerability using local analysis."""
        vuln_data = self.get_vulnerability_details(vuln_id)
        if not vuln_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in database")
        
        vuln_info = vuln_data[0]
        
        # Extract basic vulnerability information
        vuln_summary = vuln_info.get("summary", "")
        vuln_details = vuln_info.get("details", "")
        affected_packages = vuln_info.get("affected_packages", [])
        references = vuln_info.get("references", [])
        
        # Perform analysis
        vuln_type = self._determine_vulnerability_type(vuln_summary, vuln_details)
        severity = self._determine_severity(vuln_summary, vuln_details, affected_packages)
        affected_ecosystems = self._extract_affected_ecosystems(affected_packages)
        exploitation_likelihood = self._determine_exploitation_likelihood(vuln_type, references)
        impact_analysis = self._generate_impact_analysis(vuln_type, vuln_summary, affected_packages)
        remediation_steps = self._generate_remediation_steps(vuln_type, affected_packages)
        recommendation = self._generate_recommendation(severity, vuln_type, remediation_steps)
        
        # Create and return a structured insight object
        return SecurityInsight(
            vulnerability_id=vuln_id,
            severity=severity,
            affected_ecosystems=affected_ecosystems,
            vulnerability_type=vuln_type,
            impact_analysis=impact_analysis,
            remediation_steps=remediation_steps,
            exploitation_likelihood=exploitation_likelihood,
            recommendation=recommendation
        )

    def analyze_cve(self, cve_id: str) -> Dict[str, Any]:
        """Analyze a specific CVE using local analysis."""
        cve_data = self.get_cve_details(cve_id)
        if not cve_data:
            raise ValueError(f"CVE {cve_id} not found in database")

        cve_info = cve_data[0]
        vulnerabilities = cve_info.get("vulnerabilities", [])

        # Initialize with empty list if None
        affected_packages = cve_info.get("affected_packages") or []
        references = cve_info.get("references") or []

        # Extract text from vulnerabilities for analysis
        detail_texts = [v.get("details", "") for v in vulnerabilities if v.get("details")]

        try:
            summary_texts = [v.get("summary", "") for v in vulnerabilities if v.get("summary")]
        except Exception as e:
            self.logger.error(f"Error during analysis (summary): {e}")
            summary_texts = []  # Ensure summary_texts is always defined
        try:
            combined_summary = " ".join(summary_texts)
        except Exception as e:
            self.logger.error(f"Error during analysis (combine summary): {e}")
            combined_summary = "" # Ensure combined_summary is always defined
        combined_details = " ".join(detail_texts)

        # Defensive programming - check for None values in all relevant variables
        analysis_results = {}
        try:
            self.logger.debug("Determining vulnerability type")
            vuln_type = self._determine_vulnerability_type(combined_summary, combined_details)
            self.logger.debug(f"Vulnerability type: {vuln_type}")
            analysis_results["vulnerability_type"] = vuln_type

            self.logger.debug("Determining severity")
            severity = self._determine_severity(combined_summary, combined_details, affected_packages)
            self.logger.debug(f"Severity: {severity}")
            analysis_results["severity"] = severity
            
            self.logger.debug("Extracting affected ecosystems")
            affected_ecosystems = self._extract_affected_ecosystems(affected_packages)
            self.logger.debug(f"Affected ecosystems: {affected_ecosystems}")
            analysis_results["affected_ecosystems"] = affected_ecosystems

            self.logger.debug("Determining exploitation likelihood")
            exploitation_likelihood = self._determine_exploitation_likelihood(vuln_type, references)
            self.logger.debug(f"Exploitation likelihood: {exploitation_likelihood}")
            analysis_results["exploitation_likelihood"] = exploitation_likelihood

            return analysis_results
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            raise

    def analyze_ecosystem_security(self, ecosystem: str) -> Dict:
        """Analyze security posture of a particular ecosystem."""
        eco_data = self.get_ecosystem_vulnerabilities(ecosystem, limit=25)
        
        if not eco_data:
            return {
                "ecosystem_name": ecosystem,
                "overall_security_rating": "UNKNOWN",
                "common_vulnerability_patterns": [],
                "highest_risk_packages": [],
                "systemic_security_issues": [],
                "recommended_security_improvements": [],
                "security_trend_analysis": f"No vulnerability data found for ecosystem {ecosystem}."
            }
        
        # Collect all vulnerabilities
        all_vulns = []
        packages_with_vulns = {}
        
        for item in eco_data:
            pkg_name = item.get("package_name")
            vulns = item.get("vulnerabilities", [])
            
            # Count vulnerabilities per package
            if pkg_name and vulns:
                if pkg_name not in packages_with_vulns:
                    packages_with_vulns[pkg_name] = 0
                packages_with_vulns[pkg_name] += len(vulns)
            
            all_vulns.extend(vulns)
        
        # Analyze vulnerability types
        vuln_types = {}
        for vuln in all_vulns:
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            vuln_type = self._determine_vulnerability_type(summary, details)
            
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        # Get highest risk packages
        highest_risk_packages = []
        for pkg, count in sorted(packages_with_vulns.items(), key=lambda x: x[1], reverse=True)[:5]:
            highest_risk_packages.append(f"{pkg} ({count} vulnerabilities)")
        
        # Determine common vulnerability patterns
        common_vulnerability_patterns = []
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            if count > 1:
                common_vulnerability_patterns.append(f"{vuln_type} ({count} instances)")
        
        # Generate systemic security issues
        systemic_security_issues = []
        total_vulns = len(all_vulns)
        total_packages = len(eco_data)
        
        if total_vulns / max(1, total_packages) > 2:
            systemic_security_issues.append(f"High vulnerability density ({total_vulns} vulnerabilities across {total_packages} packages)")
        
        for vuln_type, count in vuln_types.items():
            if count / max(1, total_vulns) > 0.3:  # If over 30% of vulnerabilities are of this type
                systemic_security_issues.append(f"High prevalence of {vuln_type} vulnerabilities")
        
        # Generate recommended improvements
        recommended_security_improvements = [
            f"Prioritize updates for high-risk packages: {', '.join(highest_risk_packages[:3])}" if highest_risk_packages else "Conduct regular security audits of dependent packages",
            f"Implement security scanning for {ecosystem} dependencies in CI/CD pipelines",
            "Establish regular vulnerability monitoring for critical dependencies"
        ]
        
        # Add type-specific recommendations
        for vuln_type, count in vuln_types.items():
            if count > 1:
                if vuln_type == "Cross-Site Scripting":
                    recommended_security_improvements.append("Implement Content Security Policy (CSP) headers for web applications")
                elif vuln_type == "SQL Injection":
                    recommended_security_improvements.append("Use parameterized queries and ORM libraries with automatic escaping")
                elif vuln_type == "Buffer Overflow":
                    recommended_security_improvements.append("Consider memory-safe language alternatives for critical components")
                elif vuln_type == "Command Injection":
                    recommended_security_improvements.append("Implement strict input validation and command argument sanitization")
        
        # Determine overall security rating
        vulns_per_package = total_vulns / max(1, total_packages)
        if vulns_per_package > 3:
            overall_rating = "POOR"
        elif vulns_per_package > 1.5:
            overall_rating = "CONCERNING"
        elif vulns_per_package > 0.5:
            overall_rating = "MODERATE"
        else:
            overall_rating = "GOOD"
            
        # Generate security trend analysis
        security_trend_analysis = f"Analysis of {ecosystem} ecosystem reveals {total_vulns} vulnerabilities across {total_packages} packages. "
        security_trend_analysis += f"The most prevalent vulnerability type is {list(vuln_types.keys())[0] if vuln_types else 'Unknown'}. "
        security_trend_analysis += f"Overall security posture is rated as {overall_rating}."
        
        return {
            "ecosystem_name": ecosystem,
            "overall_security_rating": overall_rating,
            "common_vulnerability_patterns": common_vulnerability_patterns,
            "highest_risk_packages": highest_risk_packages,
            "systemic_security_issues": systemic_security_issues,
            "recommended_security_improvements": recommended_security_improvements,
            "security_trend_analysis": security_trend_analysis
        }

    def get_vulnerability_statistics(self) -> Dict:
        """Get overall vulnerability statistics from the database."""
        stats = {}
        
        # Count total vulnerabilities
        vuln_count_query = "MATCH (v:Vulnerability) RETURN count(v) as count"
        vuln_count = self.query_neo4j(vuln_count_query)[0]["count"]
        stats["total_vulnerabilities"] = vuln_count
        
        # Count total CVEs
        cve_count_query = "MATCH (c:CVE) RETURN count(c) as count"
        cve_count = self.query_neo4j(cve_count_query)[0]["count"]
        stats["total_cves"] = cve_count
        
        # Count affected packages
        pkg_count_query = "MATCH (p:Package) RETURN count(p) as count"
        pkg_count = self.query_neo4j(pkg_count_query)[0]["count"]
        stats["total_packages"] = pkg_count
        
        # Count vulnerabilities by ecosystem
        ecosystem_query = """
        MATCH (p:Package)<-[]-(v:Vulnerability)
        RETURN p.ecosystem as ecosystem, count(DISTINCT v) as vuln_count
        ORDER BY vuln_count DESC
        """
        ecosystem_stats = self.query_neo4j(ecosystem_query)
        stats["vulnerabilities_by_ecosystem"] = {
            item["ecosystem"]: item["vuln_count"] for item in ecosystem_stats if item["ecosystem"]
        }
        
        # Get recent vulnerabilities (published in the last 90 days)
        recent_query = """
        MATCH (v:Vulnerability)
        WHERE v.published IS NOT NULL AND datetime(v.published) > datetime() - duration('P90D')
        RETURN count(v) as count
        """
        recent_count = self.query_neo4j(recent_query)
        stats["recent_vulnerabilities"] = recent_count[0]["count"] if recent_count else 0
        
        # Get most common vulnerability types by keyword analysis
        all_vulns_query = """
        MATCH (v:Vulnerability)
        RETURN v.id as id, v.summary as summary, v.details as details
        LIMIT 1000
        """
        all_vulns = self.query_neo4j(all_vulns_query)
        
        # Extract vulnerability types
        vuln_types = []
        for vuln in all_vulns:
            summary = vuln.get("summary", "")
            details = vuln.get("details", "")
            vuln_type = self._determine_vulnerability_type(summary, details)
            vuln_types.append(vuln_type)
        
        # Count frequency of each type
        type_counter = Counter(vuln_types)
        stats["vulnerability_types"] = {k: v for k, v in type_counter.most_common(10)}
        
        return stats

    def find_related_vulnerabilities(self, vuln_id: str) -> List[Dict]:
        """Find vulnerabilities related to a specific vulnerability."""
        query = """
        MATCH (v1:Vulnerability {id: $vuln_id})
        MATCH (v1)-[]->(p:Package)<-[]-(v2:Vulnerability)
        WHERE v1 <> v2
        RETURN DISTINCT v2.id as id, v2.summary as summary, p.name as package_name, p.ecosystem as ecosystem
        LIMIT 10
        """
        params = {"vuln_id": vuln_id}
        
        related_vulns = self.query_neo4j(query, params)
        return related_vulns

    def generate_security_report(self, target: str, target_type: str) -> Dict:
        """Generate a comprehensive security report for a package, ecosystem, or vulnerability."""
        report = {
            "report_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "target_type": target_type,
            "summary": "",
            "details": {},
            "recommendations": []
        }
        
        if target_type == "vulnerability":
            try:
                insight = self.analyze_vulnerability(target)
                report["summary"] = f"Analysis of vulnerability {target} ({insight.vulnerability_type})"
                report["details"] = {
                    "severity": insight.severity,
                    "affected_ecosystems": insight.affected_ecosystems,
                    "vulnerability_type": insight.vulnerability_type,
                    "impact_analysis": insight.impact_analysis,
                    "exploitation_likelihood": insight.exploitation_likelihood
                }
                report["recommendations"] = [
                    insight.remediation_steps,
                    insight.recommendation
                ]
                
                # Add related vulnerabilities
                related = self.find_related_vulnerabilities(target)
                if related:
                    report["related_vulnerabilities"] = related
                    
            except ValueError as e:
                report["summary"] = f"Error: {str(e)}"
                
        elif target_type == "cve":
            try:
                analysis = self.analyze_cve(target)
                
                # Create impact analysis based on vulnerability type and affected ecosystems
                impact_analysis = "The potential impact of this vulnerability depends on the affected systems and deployment context."
                if "vulnerability_type" in analysis and analysis["vulnerability_type"] != "Unknown":
                    impact_analysis = f"This {analysis['vulnerability_type']} vulnerability could potentially affect systems using the impacted packages."
                
                # Generate remediation steps based on affected ecosystems
                remediation_steps = "Update to the latest patched version of the affected software components."
                if "affected_ecosystems" in analysis and analysis["affected_ecosystems"]:
                    ecosystems = ", ".join(analysis["affected_ecosystems"])
                    remediation_steps += f" Pay special attention to packages in the {ecosystems} ecosystem(s)."
                
                report["summary"] = f"Analysis of CVE {target}"
                if "vulnerability_type" in analysis and analysis["vulnerability_type"] != "Unknown":
                    report["summary"] += f" ({analysis['vulnerability_type']})"
                    
                report["details"] = {
                    "severity": analysis.get("severity", "UNKNOWN"),
                    "vulnerability_type": analysis.get("vulnerability_type", "Unknown"),
                    "affected_ecosystems": analysis.get("affected_ecosystems", []),
                    "exploitation_likelihood": analysis.get("exploitation_likelihood", "UNKNOWN"),
                    "impact_analysis": impact_analysis
                }
                
                report["recommendations"] = [
                    remediation_steps,
                    "Implement security scanning for affected package dependencies in CI/CD pipelines",
                    "Establish regular vulnerability monitoring for critical dependencies"
                ]
                
            except ValueError as e:
                report["summary"] = f"Error: {str(e)}"
                
        elif target_type == "package":
            # Assume target format is "name@ecosystem"
            if "@" in target:
                name, ecosystem = target.split("@", 1)
                vulns = self.get_package_vulnerabilities(name, ecosystem)
            else:
                vulns = self.get_package_vulnerabilities(target)
                
            if vulns:
                package_info = vulns[0]
                package_name = package_info.get("package_name", target)
                ecosystem = package_info.get("ecosystem", "unknown")
                vulnerabilities = package_info.get("vulnerabilities", [])
                
                report["summary"] = f"Security analysis of package {package_name} ({ecosystem})"
                report["details"] = {
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "vulnerability_count": len(vulnerabilities),
                    "repositories": package_info.get("repositories", []),
                    "versions": package_info.get("versions", [])
                }
                
                if vulnerabilities:
                    vulnerability_summaries = []
                    for v in vulnerabilities:
                        if "id" in v and "summary" in v:
                            vulnerability_summaries.append({
                                "id": v["id"],
                                "summary": v["summary"]
                            })
                    report["details"]["vulnerabilities"] = vulnerability_summaries
                    
                    # Generate recommendations based on vulnerabilities
                    report["recommendations"] = [
                        "Update to the latest version of the package which contains security fixes",
                        "Implement security scanning in your dependency management workflow",
                        "Consider alternative packages if this package has many unresolved vulnerabilities"
                    ]
                else:
                    report["recommendations"] = [
                        "No known vulnerabilities found, but continue to monitor for new security advisories",
                        "Implement automated dependency security scanning as a precaution"
                    ]
            else:
                report["summary"] = f"No data found for package {target}"
                
        elif target_type == "ecosystem":
            analysis = self.analyze_ecosystem_security(target)
            report["summary"] = f"Security analysis of {target} ecosystem"
            report["details"] = {
                "ecosystem_name": analysis["ecosystem_name"],
                "overall_security_rating": analysis["overall_security_rating"],
                "common_vulnerability_patterns": analysis["common_vulnerability_patterns"],
                "highest_risk_packages": analysis["highest_risk_packages"],
                "systemic_security_issues": analysis["systemic_security_issues"],
                "security_trend_analysis": analysis["security_trend_analysis"]
            }
            report["recommendations"] = analysis["recommended_security_improvements"]
            
        else:
            report["summary"] = f"Unknown target type: {target_type}"
            
        return report

class CombinedSecurityAnalyzer:
    """
    Combined security analyzer that uses both the Neo4j and Ollama-based analyzers.
    """
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "jaguarai",
        ollama_base_url: str = "http://localhost:11434",
        api_key: str = None,
        log_level: str = "INFO"
    ):
        # Initialize both analyzers
        self.neo4j_analyzer = Neo4jSecurityAnalyzer(
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            log_level=log_level
        )
        
        self.ollama_analyzer = SecurityAnalyzer(
            api_key=api_key, 
            ollama_base_url=ollama_base_url
        )
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def close(self):
        """Close database connections."""
        self.neo4j_analyzer.close()
    
    def analyze_repositories_from_file(self, file_path: str, sample_count: int = 3, model: str = "llama3") -> Dict[str, Any]:
        """
        Analyze repositories from a JSON file, enriching data from Neo4j where possible.
        
        Args:
            file_path: Path to the JSON file containing repository data
            sample_count: Number of packages and CVEs to sample from each repository
            model: Ollama model to use for analysis
        
        Returns:
            Dictionary containing analysis results
        """
        # Load repository data from file
        repositories = self.ollama_analyzer.load_vulnerability_data(file_path)
        
        if not repositories:
            self.logger.error("No repository data loaded from file")
            return {"error": "No repository data loaded"}
        
        results = {
            "repository_analyses": [],
            "package_analyses": [],
            "cve_analyses": []
        }
        
        for repo in repositories:
            repo_url = repo.get("repository_url", "Unknown")
            self.logger.info(f"Analyzing repository: {repo_url}")
            
            # Add basic repository info
            repo_analysis = {
                "repository_url": repo_url,
                "vulnerability_count": repo.get("vulnerability_count", 0),
                "affected_packages_count": len(repo.get("affected_packages", [])),
                "cve_count": len(repo.get("cve_ids", []))
            }
            results["repository_analyses"].append(repo_analysis)
            
            # Sample packages and CVEs
            packages_to_analyze = self.ollama_analyzer.sample_items(repo.get("affected_packages", []), sample_count)
            cves_to_analyze = self.ollama_analyzer.sample_items(repo.get("cve_ids", []), sample_count)
            
            # Analyze sampled packages using Neo4j data when available
            for package in packages_to_analyze:
                self.logger.info(f"Analyzing package: {package}")
                
                # Try to get package info from Neo4j
                neo4j_pkg_data = []
                try:
                    neo4j_pkg_data = self.neo4j_analyzer.get_package_vulnerabilities(package)
                except Exception as e:
                    self.logger.warning(f"Error getting Neo4j data for package {package}: {str(e)}")
                
                # If we have Neo4j data, use it to enhance the analysis
                if neo4j_pkg_data:
                    vulnerabilities = []
                    for pkg_info in neo4j_pkg_data:
                        vuln_data = pkg_info.get("vulnerabilities", [])
                        vulnerabilities.extend(vuln_data)
                else:
                    # Fall back to simulated vulnerability data
                    vulnerabilities = self.ollama_analyzer.find_package_vulnerabilities(package, repo)
                
                # Generate and run analysis
                prompt = self.ollama_analyzer.generate_package_analysis_prompt(package, vulnerabilities)
                analysis = self.ollama_analyzer.analyze_with_ollama(prompt, model)
                
                results["package_analyses"].append({
                        "package_name": package,
                        "repository": repo_url,
                        "vulnerabilities": vulnerabilities,
                        "analysis": analysis
                    })
                
                # Add delay to avoid overloading the API
                time.sleep(1)
            
            # Analyze sampled CVEs using Neo4j data when available
            for cve_id in cves_to_analyze:
                self.logger.info(f"Analyzing CVE: {cve_id}")
                
                # Try to get CVE info from Neo4j
                neo4j_cve_data = {}
                try:
                    neo4j_cve_results = self.neo4j_analyzer.get_cve_details(cve_id)
                    if neo4j_cve_results:
                        neo4j_cve_data = neo4j_cve_results[0]
                except Exception as e:
                    self.logger.warning(f"Error getting Neo4j data for CVE {cve_id}: {str(e)}")
                
                # If we have Neo4j data, use it to enhance the analysis
                if neo4j_cve_data:
                    # Try to use Neo4j's analysis method
                    try:
                        neo4j_analysis = self.neo4j_analyzer.analyze_cve(cve_id)
                        vuln_type = neo4j_analysis.get("vulnerability_type", "Unknown")
                        severity = neo4j_analysis.get("severity", "UNKNOWN")
                        exploitation_likelihood = neo4j_analysis.get("exploitation_likelihood", "UNKNOWN")
                    except Exception as e:
                        self.logger.warning(f"Error analyzing CVE {cve_id} with Neo4j: {str(e)}")
                        # Fall back to NVD data
                        nvd_data = self.ollama_analyzer.query_nist_nvd(cve_id)
                else:
                    # Get data from NVD
                    nvd_data = self.ollama_analyzer.query_nist_nvd(cve_id)
                
                # Generate and run analysis with Ollama
                prompt = self.ollama_analyzer.generate_cve_analysis_prompt(cve_id, nvd_data if 'nvd_data' in locals() else {})
                analysis = self.ollama_analyzer.analyze_with_ollama(prompt, model)
                
                cve_result = {
                    "cve_id": cve_id,
                    "repository": repo_url,
                    "analysis": analysis
                }
                
                # Add Neo4j data if available
                if 'neo4j_analysis' in locals():
                    cve_result["neo4j_analysis"] = {
                        "vulnerability_type": vuln_type,
                        "severity": severity,
                        "exploitation_likelihood": exploitation_likelihood
                    }
                
                results["cve_analyses"].append(cve_result)
                
                # Add delay to avoid overloading the API
                time.sleep(1)
        
        return results
    
    def save_results_to_file(self, results: Dict[str, Any], output_file: str) -> None:
        """Save analysis results to a JSON file."""
        self.ollama_analyzer.save_results_to_file(results, output_file)
    
    def generate_markdown_report(self, results: Dict[str, Any], output_file: str) -> None:
        """Generate a markdown report from the analysis results."""
        self.ollama_analyzer.generate_markdown_report(results, output_file)

def main():
    parser = argparse.ArgumentParser(description="Combined Security Vulnerability Analysis Tool")
    
    # Basic arguments
    parser.add_argument("--input", required=True, help="Input JSON file with vulnerability data")
    parser.add_argument("--output", default="security_analysis_results.json", help="Output JSON file for results")
    parser.add_argument("--report", default="security_analysis_report.md", help="Output markdown report file")
    parser.add_argument("--samples", type=int, default=3, help="Number of packages and CVEs to sample for analysis")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging level")
    
    # Neo4j connection arguments
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j connection URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="jaguarai", help="Neo4j password")
    
    # Ollama arguments
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Base URL for Ollama API")
    parser.add_argument("--model", default="llama3", help="Ollama model to use for analysis")
    
    # API Keys
    parser.add_argument("--nvd-api-key", help="API key for NVD API (optional)")
    
    # Neo4j direct commands
    parser.add_argument("--neo4j-command", choices=[
        "schema", "stats", "vuln", "cve", "package", "ecosystem", "repo", "report"
    ], help="Direct Neo4j command to execute")
    parser.add_argument("--neo4j-target", help="Target ID for the command (vuln ID, CVE ID, package name, etc.)")
    parser.add_argument("--neo4j-limit", type=int, default=10, help="Limit for result count")
    
    args = parser.parse_args()
    
    # Setup logging
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=numeric_level)
    
    logger = logging.getLogger(__name__)
    
    # Initialize the combined analyzer
    analyzer = CombinedSecurityAnalyzer(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        ollama_base_url=args.ollama_url,
        api_key=args.nvd_api_key,
        log_level=args.log_level
    )
    
    try:
        # Check if a direct Neo4j command was specified
        if args.neo4j_command:
            logger.info(f"Executing Neo4j command: {args.neo4j_command}")
            
            result = None
            if args.neo4j_command == "schema":
                result = analyzer.neo4j_analyzer.get_database_schema()
                
            elif args.neo4j_command == "stats":
                result = analyzer.neo4j_analyzer.get_vulnerability_statistics()
                
            elif args.neo4j_command == "vuln":
                if args.neo4j_target:
                    result = analyzer.neo4j_analyzer.get_vulnerability_details(args.neo4j_target)
                else:
                    result = analyzer.neo4j_analyzer.get_vulnerability_details(limit=args.neo4j_limit)
                    
            elif args.neo4j_command == "cve":
                if args.neo4j_target:
                    result = analyzer.neo4j_analyzer.get_cve_details(args.neo4j_target)
                else:
                    result = analyzer.neo4j_analyzer.get_cve_details(limit=args.neo4j_limit)
                    
            elif args.neo4j_command == "package":
                if args.neo4j_target:
                    if "@" in args.neo4j_target:
                        name, ecosystem = args.neo4j_target.split("@", 1)
                        result = analyzer.neo4j_analyzer.get_package_vulnerabilities(name, ecosystem)
                    else:
                        result = analyzer.neo4j_analyzer.get_package_vulnerabilities(args.neo4j_target)
                else:
                    result = analyzer.neo4j_analyzer.get_package_vulnerabilities(limit=args.neo4j_limit)
                    
            elif args.neo4j_command == "ecosystem":
                if not args.neo4j_target:
                    logger.error("Error: --neo4j-target ecosystem_name is required for ecosystem command")
                    return 1
                result = analyzer.neo4j_analyzer.get_ecosystem_vulnerabilities(args.neo4j_target, args.neo4j_limit)
                
            elif args.neo4j_command == "repo":
                result = analyzer.neo4j_analyzer.get_repositories_with_vulnerabilities(args.neo4j_limit)
                
            elif args.neo4j_command == "report":
                if not args.neo4j_target or ":" not in args.neo4j_target:
                    logger.error("Error: --neo4j-target must be in format type:id (e.g., vulnerability:CVE-2021-44228)")
                    return 1
                    
                target_type, target_id = args.neo4j_target.split(":", 1)
                if target_type not in ["vulnerability", "cve", "package", "ecosystem"]:
                    logger.error(f"Error: Unknown target type {target_type}")
                    return 1
                    
                result = analyzer.neo4j_analyzer.generate_security_report(target_id, target_type)
            
            # Output results
            if result:
                result_json = json.dumps(result, indent=2, default=str)
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(result_json)
                    logger.info(f"Results written to {args.output}")
                else:
                    print(result_json)
            else:
                logger.warning("No results returned")
        else:
            # Run the combined analyzer on the input file
            logger.info(f"Analyzing repositories from {args.input} with {args.samples} samples each...")
            results = analyzer.analyze_repositories_from_file(
                args.input, 
                sample_count=args.samples,
                model=args.model
            )
            
            # Save results
            analyzer.save_results_to_file(results, args.output)
            analyzer.generate_markdown_report(results, args.report)
            
            logger.info("Analysis complete.")
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
    finally:
        analyzer.close()
    
    return 0

if __name__ == "__main__":
    exit(main())
