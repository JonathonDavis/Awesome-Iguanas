import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json
import time
import argparse
import datetime
import re
from collections import Counter
import requests

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

class Neo4jSecurityAnalyzer:
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "jaguarai",
        deepseek_api_key: str = None,
        deepseek_api_url: str = "https://api.deepseek.com/v1/chat/completions",
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
            
        # DeepSeek API configuration
        self.deepseek_api_key = deepseek_api_key
        self.deepseek_api_url = deepseek_api_url
        
        # Check if DeepSeek API key is provided
        if not self.deepseek_api_key:
            self.logger.warning("DeepSeek API key not provided. Falling back to local basic analysis methods.")
        
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
        query = """
        MATCH (repo:Repository)<-[]-(pkg:Package)<-[]-(vuln:Vulnerability)
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        RETURN repo.url as repository_url,
               count(DISTINCT vuln) as vulnerability_count,
               collect(DISTINCT pkg.name) as affected_packages,
               collect(DISTINCT cve.id) as cve_ids
        ORDER BY vulnerability_count DESC
        LIMIT $limit
        """
        params = {"limit": limit}
        
        return self.query_neo4j(query, params)

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

    # DeepSeek API integration
    def call_deepseek_api(self, prompt: str) -> str:
        """Call DeepSeek API for analysis."""
        if not self.deepseek_api_key:
            self.logger.warning("DeepSeek API key not provided, using basic analysis")
            return None
            
        try:
            headers = {
                "Authorization": f"Bearer {self.deepseek_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": "deepseek-coder",  # or appropriate model name
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1  # Lower temperature for more deterministic responses
            }
            
            response = requests.post(
                self.deepseek_api_url,
                headers=headers,
                json=payload
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Extract the response content based on DeepSeek's API response structure
            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"]
            else:
                self.logger.error(f"Unexpected DeepSeek API response format: {result}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"DeepSeek API error: {str(e)}")
            return None

    # Fallback local analysis methods if DeepSeek API is not available
    def _determine_vulnerability_type(self, summary: str, details: str = None) -> str:
        """Determine vulnerability type based on text analysis."""
        text = (summary or "") + " " + (details or "")
        text = text.lower()
        
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
        
        for vuln_type, patterns in vulnerability_types.items():
            for pattern in patterns:
                if pattern in text:
                    return vuln_type.title()
                    
        return "Unknown"

    def _determine_severity(self, summary: str, details: str = None, packages: List[Dict] = None) -> str:
        """Determine vulnerability severity based on text analysis."""
        text = (summary or "") + " " + (details or "")
        text = text.lower()
        
        # Check for explicit severity mentions
        if "critical" in text or "severe" in text:
            return "CRITICAL"
        elif "high" in text or "important" in text:
            return "HIGH"
        elif "medium" in text or "moderate" in text:
            return "MEDIUM"
        elif "low" in text:
            return "LOW"
            
        # Check for high severity indicators
        high_severity_indicators = [
            "remote code execution", "rce", "arbitrary code execution",
            "command execution", "privilege escalation", "authentication bypass",
            "sql injection", "arbitrary file read", "arbitrary file write"
        ]
        
        for indicator in high_severity_indicators:
            if indicator in text:
                return "HIGH"
                
        # Check package count as a heuristic
        if packages and len(packages) > 5:
            return "HIGH"
        elif packages and len(packages) > 2:
            return "MEDIUM"
            
        return "MEDIUM"  # Default to medium if uncertain

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
        ecosystems = set()
        for pkg in packages:
            eco = pkg.get("ecosystem")
            if eco:
                ecosystems.add(eco)
        return list(ecosystems)

    def _determine_exploitation_likelihood(self, vuln_type: str, references: List[Dict] = None) -> str:
        """Determine exploitation likelihood based on vulnerability type and references."""
        # Higher risk vulnerability types
        high_risk_types = ["Remote Code Execution", "SQL Injection", "Authentication Bypass", 
                         "Command Injection", "Cross-Site Scripting"]
        
        # Medium risk vulnerability types
        medium_risk_types = ["Information Disclosure", "Path Traversal", "Cross-Site Request Forgery",
                           "Denial Of Service"]
        
        # Look for exploit references
        has_exploit = False
        if references:
            for ref in references:
                url = ref.get("url", "").lower()
                ref_type = ref.get("type", "").lower()
                if "exploit" in url or "exploit" in ref_type or "poc" in url or "proof of concept" in url:
                    has_exploit = True
                    break
        
        if vuln_type in high_risk_types or has_exploit:
            return "HIGH"
        elif vuln_type in medium_risk_types:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_impact_analysis(self, vuln_type: str, summary: str, packages: List[Dict] = None) -> str:
        """Generate impact analysis based on vulnerability type and affected packages."""
        impact = f"This {vuln_type.lower()} vulnerability could potentially "
        
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
            return f"URGENT: Immediately patch this {vuln_type.lower()} vulnerability. {remediation_steps} Consider temporarily isolating affected systems if immediate patching is not possible."
        elif severity == "HIGH":
            return f"HIGH PRIORITY: This {vuln_type.lower()} vulnerability should be addressed as soon as possible. {remediation_steps}"
        elif severity == "MEDIUM":
            return f"MEDIUM PRIORITY: Schedule remediation of this {vuln_type.lower()} vulnerability within your normal patch cycle. {remediation_steps}"
        else:
            return f"LOW PRIORITY: Address this {vuln_type.lower()} vulnerability as resources permit. {remediation_steps}"

    def analyze_vulnerability_with_deepseek(self, vuln_info: Dict) -> SecurityInsight:
        """Analyze vulnerability using DeepSeek API."""
        vuln_id = vuln_info.get("id", "unknown")
        summary = vuln_info.get("summary", "")
        details = vuln_info.get("details", "")
        affected_packages = vuln_info.get("affected_packages", [])
        references = vuln_info.get("references", [])
        
        # Format input for DeepSeek API
        prompt = f"""
        Analyze the following security vulnerability:
        
        ID: {vuln_id}
        Summary: {summary}
        Details: {details}
        
        Affected packages: {json.dumps(affected_packages, indent=2)}
        
        References: {json.dumps(references, indent=2)}
        
        Please provide a structured analysis with the following information:
        1. Vulnerability Type: Classify the vulnerability (e.g., SQL Injection, XSS, Buffer Overflow)
        2. Severity: Classify as LOW, MEDIUM, HIGH, or CRITICAL
        3. Affected Ecosystems: List the affected software ecosystems
        4. Impact Analysis: Describe the potential impact of this vulnerability
        5. Exploitation Likelihood: Rate as LOW, MEDIUM, or HIGH
        6. Remediation Steps: Provide specific remediation guidance
        7. Recommendation: Provide a prioritized recommendation
        
        Format your response as a JSON object with these fields.
        """
        
        # Call DeepSeek API
        result = self.call_deepseek_api(prompt)
        
        # Parse the result
        if result:
            try:
                # Try to extract JSON from the response
                result_text = result.strip()
                # Look for JSON-like content in the response
                json_start = result_text.find('{')
                json_end = result_text.rfind('}')
                
                if json_start >= 0 and json_end > json_start:
                    json_str = result_text[json_start:json_end+1]
                    analysis = json.loads(json_str)
                    
                    # Create and return SecurityInsight object
                    return SecurityInsight(
                        vulnerability_id=vuln_id,
                        severity=analysis.get("Severity", "MEDIUM"),
                        affected_ecosystems=analysis.get("Affected Ecosystems", []),
                        vulnerability_type=analysis.get("Vulnerability Type", "Unknown"),
                        impact_analysis=analysis.get("Impact Analysis", ""),
                        remediation_steps=analysis.get("Remediation Steps", ""),
                        exploitation_likelihood=analysis.get("Exploitation Likelihood", "MEDIUM"),
                        recommendation=analysis.get("Recommendation", "")
                    )
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.error(f"Failed to parse DeepSeek response: {str(e)}")
        
        # Fall back to local analysis
        self.logger.info("Falling back to local analysis")
        return self._analyze_vulnerability_locally(vuln_info)

    def _analyze_vulnerability_locally(self, vuln_info: Dict) -> SecurityInsight:
        """Analyze vulnerability using local methods when DeepSeek is unavailable."""
        vuln_id = vuln_info.get("id", "unknown")
        summary = vuln_info.get("summary", "")
        details = vuln_info.get("details", "")
        affected_packages = vuln_info.get("affected_packages", [])
        references = vuln_info.get("references", [])
        
        # Perform analysis using local methods
        vuln_type = self._determine_vulnerability_type(summary, details)
        severity = self._determine_severity(summary, details, affected_packages)
        affected_ecosystems = self._extract_affected_ecosystems(affected_packages)
        exploitation_likelihood = self._determine_exploitation_likelihood(vuln_type, references)
        impact_analysis = self._generate_impact_analysis(vuln_type, summary, affected_packages)
        remediation_steps = self._generate_remediation_steps(vuln_type, affected_packages)
        recommendation = self._generate_recommendation(severity, vuln_type, remediation_steps)
        
        # Create and return structured insight
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

    def analyze_vulnerability(self, vuln_id: str) -> SecurityInsight:
        """Analyze a specific vulnerability."""
        vuln_data = self.get_vulnerability_details(vuln_id)
        if not vuln_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in database")
        
        vuln_info = vuln_data[0]
        
        # Try to use DeepSeek API first, fall back to local analysis if needed
        if self.deepseek_api_key:
            return self.analyze_vulnerability_with_deepseek(vuln_info)
        else:
            return self._analyze_vulnerability_locally(vuln_info)

    def analyze_cve_with_deepseek(self, cve_info: Dict) -> Dict:
        """Analyze CVE using DeepSeek API."""
        cve_id = cve_info.get("id", "unknown")
        vulnerabilities = cve_info.get("vulnerabilities", [])
        affected_packages = cve_info.get("affected_packages", [])
        references = cve_info.get("references", [])
        
        # Extract text for analysis
        summaries = [v.get("summary", "") for v in vulnerabilities if v.get("summary")]
        details = [v.get("details", "") for v in vulnerabilities if v.get("details")]
        
        # Format input for DeepSeek API
        prompt = f"""
        Analyze the following CVE:
        
        ID: {cve_id}
        
        Vulnerability Summaries:
        {json.dumps(summaries, indent=2)}
        
        Technical Details:
        {json.dumps(details, indent=2)}
        
        Affected Packages:
        {json.dumps(affected_packages, indent=2)}
        
        References:
        {json.dumps(references, indent=2)}
        
        Please provide a structured analysis with the following information:
        1. Vulnerability Type: Classify the vulnerability (e.g., SQL Injection, XSS, Buffer Overflow)
        2. Severity: Classify as LOW, MEDIUM, HIGH, or CRITICAL
        3. Affected Ecosystems: List the affected software ecosystems
        4. Impact Analysis: Describe the potential impact of this vulnerability
        5. Exploitation Likelihood: Rate as LOW, MEDIUM, or HIGH
        6. Remediation Steps: Provide specific remediation guidance
        7. Recommendation: Provide a prioritized recommendation
        
        Format your response as a JSON object with these fields.
        """
        
        # Call DeepSeek API
        result = self.call_deepseek_api(prompt)
        
        # Parse the result
        if result:
            try:
                # Try to extract JSON from the response
                result_text = result.strip()
                # Look for JSON-like content in the response
                json_start = result_text.find('{')
                json_end = result_text.rfind('}')
                
                if json_start >= 0 and json_end > json_start:
                    json_str = result_text[json_start:json_end+1]
                    analysis = json.loads(json_str)
                    
                    # Return structured analysis
                    return {
                        "cve_id": cve_id,
                        "severity": analysis.get("Severity", "MEDIUM"),
                        "affected_ecosystems": analysis.get("Affected Ecosystems", []),
                        "vulnerability_type": analysis.get("Vulnerability Type", "Unknown"),
                        "impact_analysis": analysis.get("Impact Analysis", ""),
                        "remediation_steps": analysis.get("Remediation Steps", ""),
                        "exploitation_likelihood": analysis.get("Exploitation Likelihood", "MEDIUM"),
                        "recommendation": analysis.get("Recommendation", "")
                    }
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.error(f"Failed to parse DeepSeek response: {str(e)}")
        
        # Fall back to local analysis
        self.logger.info("Falling back to local analysis for CVE")
        return self._analyze_cve_locally(cve_info)

    def _analyze_cve_locally(self, cve_info: Dict) -> Dict:
        """Analyze CVE using local methods when DeepSeek is unavailable."""
        cve_id = cve_info.get("id", "unknown")
        vulnerabilities = cve_info.get("vulnerabilities", [])
        affected_packages = cve_info.get("affected_packages", [])
        references = cve_info.get("references", [])
        
        # Extract text for analysis
        combined_summary = " ".join([v.get("summary", "") for v in vulnerabilities if v.get("summary")])
        combined_details = " ".join([v.get("details", "") for v in vulnerabilities if v.get("details")])
        
        # Perform analysis using local methods
        vuln_type = self._determine_vulnerability_type(combined_summary, combined_details)
        severity = self._determine_severity(combined_summary, combined_details, affected_packages)
        affected_ecosystems = self._extract_affected_ecosystems(affected_packages)
        exploitation_likelihood = self._determine_exploitation_likelihood(vuln_type, references)
        impact_analysis = self._generate_impact_analysis(vuln_type, combined_summary, affected_packages)
        remediation_steps = self._generate_remediation_steps(vuln_type, affected_packages)
        recommendation = self._generate_recommendation(severity, vuln_type, remediation_steps)
        
        # Return structured analysis
        return {
            "cve_id": cve_id,
            "severity": severity,
            "affected_ecosystems": affected_ecosystems,
            "vulnerability_type": vuln_type,
            "impact_analysis": impact_analysis,
            "remediation_steps": remediation_steps,
            "exploitation_likelihood": exploitation_likelihood,
            "recommendation": recommendation
        }

    def analyze_cve(self, cve_id: str) -> Dict:
        """Analyze a specific CVE."""
        cve_data = self.get_cve_details(cve_id)
        if not cve_data:
            raise ValueError(f"CVE {cve_id} not found in database")
        
        cve_info = cve_data[0]
        
        # Try to use DeepSeek API first, fall back to local analysis if needed
        if self.deepseek_api_key:
            return self.analyze_cve_with_deepseek(cve_info)
        else:
            return self._analyze_cve_locally(cve_info)

    def generate_ecosystem_security_report(self, ecosystem: str, limit: int = 20) -> Dict:
        """Generate a security report for a specific ecosystem."""
        self.logger.info(f"Generating security report for {ecosystem} ecosystem")
        
        # Get vulnerabilities for the ecosystem
        vulnerabilities = self.get_ecosystem_vulnerabilities(ecosystem, limit)
        
        if not vulnerabilities:
            return {
                "ecosystem": ecosystem,
                "vulnerability_count": 0,
                "report_date": datetime.datetime.now().isoformat(),
                "summary": f"No vulnerabilities found for {ecosystem} ecosystem",
                "recommendations": [],
                "vulnerabilities": []
            }
            
        # Count vulnerabilities by package
        package_vuln_counts = Counter()
        vuln_details = []
        
        for pkg_data in vulnerabilities:
            pkg_name = pkg_data.get("package_name", "unknown")
            vulns = pkg_data.get("vulnerabilities", [])
            
            if vulns:
                package_vuln_counts[pkg_name] = len(vulns)
                
                # Collect vulnerability details
                for vuln in vulns:
                    vuln_id = vuln.get("id", "unknown")
                    vuln_summary = vuln.get("summary", "No summary available")
                    
                    vuln_details.append({
                        "id": vuln_id,
                        "package": pkg_name,
                        "summary": vuln_summary
                    })
        
        # Most vulnerable packages
        most_vulnerable = package_vuln_counts.most_common(5)
        
        # Generate recommendations
        recommendations = [
            f"Update {pkg} package which has {count} known vulnerabilities"
            for pkg, count in most_vulnerable
        ]
        
        # Create report
        return {
            "ecosystem": ecosystem,
            "vulnerability_count": sum(package_vuln_counts.values()),
            "report_date": datetime.datetime.now().isoformat(),
            "summary": f"Found {sum(package_vuln_counts.values())} vulnerabilities across {len(package_vuln_counts)} packages in the {ecosystem} ecosystem",
            "most_vulnerable_packages": most_vulnerable,
            "recommendations": recommendations,
            "vulnerabilities": vuln_details
        }

    def generate_repository_security_report(self, repository_url: str) -> Dict:
        """Generate a security report for a specific repository."""
        self.logger.info(f"Generating security report for repository: {repository_url}")
        
        # Query for repository and its vulnerabilities
        query = """
        MATCH (repo:Repository {url: $repo_url})
        OPTIONAL MATCH (repo)<-[]-(pkg:Package)<-[]-(vuln:Vulnerability)
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        RETURN repo.url as repository_url,
               collect(DISTINCT {
                 name: pkg.name,
                 ecosystem: pkg.ecosystem
               }) as packages,
               collect(DISTINCT {
                 id: vuln.id,
                 summary: vuln.summary,
                 package_name: pkg.name
               }) as vulnerabilities,
               collect(DISTINCT cve.id) as cve_ids
        """
        params = {"repo_url": repository_url}
        
        results = self.query_neo4j(query, params)
        
        if not results or not results[0]["repository_url"]:
            self.logger.warning(f"Repository {repository_url} not found")
            return {
                "repository_url": repository_url,
                "error": "Repository not found in database"
            }
            
        repo_data = results[0]
        vulnerabilities = repo_data.get("vulnerabilities", [])
        packages = repo_data.get("packages", [])
        cve_ids = repo_data.get("cve_ids", [])
        
        # Filter out null entries from lists
        vulnerabilities = [v for v in vulnerabilities if v["id"] is not None]
        packages = [p for p in packages if p["name"] is not None]
        cve_ids = [c for c in cve_ids if c is not None]
        
        # Count vulnerabilities by package
        package_vuln_counts = Counter()
        for vuln in vulnerabilities:
            pkg_name = vuln.get("package_name", "unknown")
            package_vuln_counts[pkg_name] += 1
            
        # Get ecosystem distribution
        ecosystem_counts = Counter([p.get("ecosystem", "unknown") for p in packages])
        
        # Create report
        report = {
            "repository_url": repository_url,
            "total_vulnerabilities": len(vulnerabilities),
            "total_affected_packages": len(package_vuln_counts),
            "total_cves": len(cve_ids),
            "report_date": datetime.datetime.now().isoformat(),
            "ecosystems": dict(ecosystem_counts),
            "vulnerable_packages": dict(package_vuln_counts),
            "vulnerabilities": vulnerabilities,
            "cve_ids": cve_ids
        }
        
        # Generate recommendations
        recommendations = []
        
        if vulnerabilities:
            recommendations.append(f"Address {len(vulnerabilities)} known vulnerabilities affecting {len(package_vuln_counts)} packages in this repository")
            
            # Recommend updates for most vulnerable packages
            for pkg, count in package_vuln_counts.most_common(3):
                recommendations.append(f"Prioritize updating {pkg} which has {count} vulnerabilities")
                
        else:
            recommendations.append("No known vulnerabilities found. Maintain regular security updates and scans.")
            
        report["recommendations"] = recommendations
        
        return report

    def find_similar_vulnerabilities(self, vuln_id: str, limit: int = 5) -> List[Dict]:
        """Find vulnerabilities similar to the specified one."""
        # Get details of the target vulnerability
        vuln_data = self.get_vulnerability_details(vuln_id)
        if not vuln_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in database")
            
        target_vuln = vuln_data[0]
        target_summary = target_vuln.get("summary", "")
        target_affected = target_vuln.get("affected_packages", [])
        
        # Extract keywords from summary
        keywords = re.findall(r'\b\w+\b', target_summary.lower())
        keywords = [k for k in keywords if len(k) > 3]  # Filter out short words
        
        if not keywords:
            self.logger.warning(f"No significant keywords found in vulnerability {vuln_id}")
            return []
            
        # Query for vulnerabilities with similar summaries
        keyword_conditions = " OR ".join([f"vuln.summary CONTAINS toLower('{k}')" for k in keywords[:5]])
        
        query = f"""
        MATCH (vuln:Vulnerability)
        WHERE vuln.id <> $vuln_id AND ({keyword_conditions})
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        OPTIONAL MATCH (vuln)-[]->(pkg:Package)
        RETURN vuln.id as id,
               vuln.summary as summary,
               vuln.details as details,
               collect(DISTINCT cve.id) as cve_ids,
               collect(DISTINCT {{
                 name: pkg.name,
                 ecosystem: pkg.ecosystem
               }}) as affected_packages,
               count(pkg) as affected_count
        ORDER BY affected_count DESC
        LIMIT $limit
        """
        
        params = {"vuln_id": vuln_id, "limit": limit}
        
        similar_vulns = self.query_neo4j(query, params)
        
        # Calculate similarity score
        for vuln in similar_vulns:
            score = 0
            
            # Summary text similarity
            vuln_summary = vuln.get("summary", "").lower()
            matching_keywords = sum(1 for k in keywords if k in vuln_summary)
            score += matching_keywords / max(1, len(keywords)) * 50
            
            # Package overlap
            vuln_packages = vuln.get("affected_packages", [])
            target_pkg_names = {p.get("name") for p in target_affected if p.get("name")}
            vuln_pkg_names = {p.get("name") for p in vuln_packages if p.get("name")}
            
            if target_pkg_names and vuln_pkg_names:
                overlap = len(target_pkg_names.intersection(vuln_pkg_names))
                overlap_score = overlap / max(1, len(target_pkg_names.union(vuln_pkg_names))) * 50
                score += overlap_score
                
            vuln["similarity_score"] = round(score, 2)
            
        # Sort by similarity score
        similar_vulns.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
        
        return similar_vulns

    def find_vulnerabilities_by_text(self, search_text: str, limit: int = 10) -> List[Dict]:
        """Search for vulnerabilities matching the provided text."""
        # Clean search text
        search_text = search_text.strip().lower()
        
        if not search_text:
            return []
            
        # Extract keywords
        keywords = re.findall(r'\b\w+\b', search_text)
        keywords = [k for k in keywords if len(k) > 3]  # Filter out short words
        
        if not keywords:
            return []
            
        # Construct query with keyword conditions
        keyword_conditions = " OR ".join([f"toLower(vuln.summary) CONTAINS '{k}' OR toLower(vuln.details) CONTAINS '{k}'" for k in keywords[:5]])
        
        query = f"""
        MATCH (vuln:Vulnerability)
        WHERE {keyword_conditions}
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        OPTIONAL MATCH (vuln)-[]->(pkg:Package)
        RETURN vuln.id as id,
               vuln.summary as summary,
               collect(DISTINCT cve.id) as cve_ids,
               collect(DISTINCT {{
                 name: pkg.name,
                 ecosystem: pkg.ecosystem
               }}) as affected_packages,
               count(DISTINCT pkg) as package_count
        ORDER BY package_count DESC
        LIMIT $limit
        """
        
        params = {"limit": limit}
        
        results = self.query_neo4j(query, params)
        
        # Calculate relevance score
        for vuln in results:
            score = 0
            summary = vuln.get("summary", "").lower()
            
            # Text matching score
            matching_keywords = sum(1 for k in keywords if k in summary)
            score += matching_keywords / max(1, len(keywords)) * 100
            
            # Boost score for exact phrase match
            if search_text in summary:
                score += 50
                
            # Package count factor
            package_count = vuln.get("package_count", 0)
            score += min(package_count * 5, 50)  # Cap at 50 points
            
            vuln["relevance_score"] = round(score, 2)
            
        # Sort by relevance score
        results.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)
        
        return results

    def get_summary_statistics(self) -> Dict:
        """Get summary statistics about the vulnerability database."""
        stats = {}
        
        # Count nodes by type
        node_counts = self.count_nodes_by_label()
        stats["node_counts"] = node_counts
        
        # Get ecosystem counts
        ecosystem_query = """
        MATCH (pkg:Package)
        RETURN pkg.ecosystem as ecosystem, count(*) as count
        ORDER BY count DESC
        """
        ecosystem_counts = self.query_neo4j(ecosystem_query)
        stats["ecosystem_counts"] = {ec["ecosystem"]: ec["count"] for ec in ecosystem_counts if ec["ecosystem"]}
        
        # Get vulnerability counts by year
        year_query = """
        MATCH (vuln:Vulnerability)
        WHERE vuln.published IS NOT NULL
        WITH substring(vuln.published, 0, 4) as year, count(*) as count
        WHERE year <> ""
        RETURN year, count
        ORDER BY year
        """
        year_counts = self.query_neo4j(year_query)
        stats["vulnerability_by_year"] = {yc["year"]: yc["count"] for yc in year_counts if yc["year"]}
        
        # Get most vulnerable packages
        pkg_query = """
        MATCH (pkg:Package)<-[]-(vuln:Vulnerability)
        RETURN pkg.name as package_name, pkg.ecosystem as ecosystem, count(vuln) as vuln_count
        ORDER BY vuln_count DESC
        LIMIT 10
        """
        vulnerable_packages = self.query_neo4j(pkg_query)
        stats["most_vulnerable_packages"] = vulnerable_packages
        
        # Repository statistics
        repo_query = """
        MATCH (repo:Repository)
        OPTIONAL MATCH (repo)<-[]-(pkg:Package)<-[]-(vuln:Vulnerability)
        RETURN count(DISTINCT repo) as total_repos,
               count(DISTINCT vuln) as total_vulns,
               count(DISTINCT pkg) as total_packages
        """
        repo_stats = self.query_neo4j(repo_query)
        if repo_stats:
            stats["repository_statistics"] = repo_stats[0]
        
        return stats
    
    def run_cli(self):
        """Run the CLI interface for the security analyzer."""
        parser = argparse.ArgumentParser(description="Neo4j Security Vulnerability Analyzer")
        
        # Create subparsers for different commands
        subparsers = parser.add_subparsers(dest="command", help="Commands")
        
        # Vulnerability command
        vuln_parser = subparsers.add_parser("vulnerability", help="Get vulnerability information")
        vuln_parser.add_argument("--id", type=str, help="Vulnerability ID to analyze")
        vuln_parser.add_argument("--limit", type=int, default=10, help="Limit results (when not using ID)")
        
        # CVE command
        cve_parser = subparsers.add_parser("cve", help="Get CVE information")
        cve_parser.add_argument("--id", type=str, help="CVE ID to analyze")
        cve_parser.add_argument("--limit", type=int, default=10, help="Limit results (when not using ID)")
        
        # Package command
        pkg_parser = subparsers.add_parser("package", help="Get package vulnerability information")
        pkg_parser.add_argument("--name", type=str, help="Package name")
        pkg_parser.add_argument("--ecosystem", type=str, help="Package ecosystem")
        pkg_parser.add_argument("--limit", type=int, default=10, help="Limit results")
        
        # Ecosystem command
        eco_parser = subparsers.add_parser("ecosystem", help="Get ecosystem vulnerability information")
        eco_parser.add_argument("--name", type=str, required=True, help="Ecosystem name")
        eco_parser.add_argument("--report", action="store_true", help="Generate full report")
        eco_parser.add_argument("--limit", type=int, default=10, help="Limit results")
        
        # Repository command
        repo_parser = subparsers.add_parser("repository", help="Get repository vulnerability information")
        repo_parser.add_argument("--url", type=str, help="Repository URL")
        repo_parser.add_argument("--limit", type=int, default=10, help="Limit results (when not using URL)")
        
        # Schema command
        schema_parser = subparsers.add_parser("schema", help="Get database schema information")
        
        # Stats command
        stats_parser = subparsers.add_parser("stats", help="Get database statistics")
        
        # Search command
        search_parser = subparsers.add_parser("search", help="Search vulnerabilities")
        search_parser.add_argument("--text", type=str, required=True, help="Search text")
        search_parser.add_argument("--limit", type=int, default=10, help="Limit results")
        
        # Similar command
        similar_parser = subparsers.add_parser("similar", help="Find similar vulnerabilities")
        similar_parser.add_argument("--id", type=str, required=True, help="Vulnerability ID")
        similar_parser.add_argument("--limit", type=int, default=5, help="Limit results")
        
        # Parse arguments
        args = parser.parse_args()
        
        # Execute command
        try:
            if args.command == "vulnerability":
                if args.id:
                    # Get and analyze specific vulnerability
                    vuln_data = self.get_vulnerability_details(args.id)
                    if not vuln_data:
                        print(f"Vulnerability {args.id} not found")
                        return
                        
                    print(f"Vulnerability Details for {args.id}:")
                    print(json.dumps(vuln_data[0], indent=2))
                    
                    # Analyze vulnerability
                    print("\nVulnerability Analysis:")
                    analysis = self.analyze_vulnerability(args.id)
                    print(json.dumps(analysis.__dict__, indent=2))
                else:
                    # List vulnerabilities
                    vulns = self.get_vulnerability_details(limit=args.limit)
                    print(f"Listing {len(vulns)} vulnerabilities:")
                    for v in vulns:
                        print(f"- {v['id']}: {v['summary'][:80]}...")
                        
            elif args.command == "cve":
                if args.id:
                    # Get and analyze specific CVE
                    cve_data = self.get_cve_details(args.id)
                    if not cve_data:
                        print(f"CVE {args.id} not found")
                        return
                        
                    print(f"CVE Details for {args.id}:")
                    print(json.dumps(cve_data[0], indent=2))
                    
                    # Analyze CVE
                    print("\nCVE Analysis:")
                    analysis = self.analyze_cve(args.id)
                    print(json.dumps(analysis, indent=2))
                else:
                    # List CVEs
                    cves = self.get_cve_details(limit=args.limit)
                    print(f"Listing {len(cves)} CVEs:")
                    for c in cves:
                        print(f"- {c['id']}")
                        
            elif args.command == "package":
                packages = self.get_package_vulnerabilities(
                    package_name=args.name,
                    ecosystem=args.ecosystem,
                    limit=args.limit
                )
                
                print(f"Found {len(packages)} packages:")
                for p in packages:
                    print(f"- {p['package_name']} ({p['ecosystem']}): {len(p['vulnerabilities'])} vulnerabilities")
                    
            elif args.command == "ecosystem":
                if args.report:
                    report = self.generate_ecosystem_security_report(args.name, args.limit)
                    print(f"Ecosystem Security Report for {args.name}:")
                    print(json.dumps(report, indent=2))
                else:
                    vulns = self.get_ecosystem_vulnerabilities(args.name, args.limit)
                    print(f"Found {len(vulns)} packages with vulnerabilities in {args.name} ecosystem")
                    for v in vulns:
                        print(f"- {v['package_name']}: {len(v['vulnerabilities'])} vulnerabilities")
                        
            elif args.command == "repository":
                if args.url:
                    report = self.generate_repository_security_report(args.url)
                    print(f"Repository Security Report for {args.url}:")
                    print(json.dumps(report, indent=2))
                else:
                    repos = self.get_repositories_with_vulnerabilities(args.limit)
                    print(f"Found {len(repos)} repositories with vulnerabilities:")
                    for r in repos:
                        print(f"- {r['repository_url']}: {r['vulnerability_count']} vulnerabilities")
                        
            elif args.command == "schema":
                schema = self.get_database_schema()
                print("Database Schema:")
                print(json.dumps(schema, indent=2))
                
            elif args.command == "stats":
                stats = self.get_summary_statistics()
                print("Database Statistics:")
                print(json.dumps(stats, indent=2))
                
            elif args.command == "search":
                results = self.find_vulnerabilities_by_text(args.text, args.limit)
                print(f"Found {len(results)} vulnerabilities matching '{args.text}':")
                for r in results:
                    print(f"- {r['id']} (Score: {r['relevance_score']}): {r['summary'][:80]}...")
                    
            elif args.command == "similar":
                similar = self.find_similar_vulnerabilities(args.id, args.limit)
                print(f"Found {len(similar)} vulnerabilities similar to {args.id}:")
                for s in similar:
                    print(f"- {s['id']} (Similarity: {s['similarity_score']}): {s['summary'][:80]}...")
                    
            else:
                parser.print_help()
                
        except Exception as e:
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            # Close Neo4j connection
            self.close()

if __name__ == "__main__":
    analyzer = Neo4jSecurityAnalyzer()
    analyzer.run_cli()
