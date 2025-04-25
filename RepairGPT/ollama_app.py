import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json
import time
import argparse
import datetime
import re
from collections import Counter

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

    def get_repositories_with_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """
        Get repositories with vulnerabilities, sorted by the number of vulnerabilities.

        :param limit: The maximum number of repositories to return
        :return: A list of dictionaries containing the repository URL, number of vulnerabilities, affected packages, and CVE IDs
        """
        
        query = f"""
        MATCH (repo:Repository)
        MATCH (vuln:Vulnerability)-[:FOUND_IN]->(repo)
        WITH repo, count(DISTINCT vuln) as vuln_count
        ORDER BY vuln_count DESC
        LIMIT {limit}
        
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

    # New local analysis methods replacing Ollama API

    def _determine_vulnerability_type(self, summary: str, details: str = None) -> str:
        """Determine vulnerability type based on text analysis."""
        # Combine summary and details, handling None values
        summary = summary or ""
        details = details or ""
        text = (summary + " " + details).lower()  # Convert to lowercase for case-insensitive matching
        
        # Remove debug print statement
        # print(text)
        
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

        Args:
            summary (str): The summary of the vulnerability.
            details (str, optional): Additional details about the vulnerability.
            packages (List[Dict], optional): List of affected packages, if any.

        Returns:
            str: The determined severity in uppercase, one of CRITICAL, HIGH, MEDIUM, or LOW.
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
            # Remote code execution (RCE) is always HIGH severity
            "remote code execution", "rce", "arbitrary code execution",
            # Command execution and privilege escalation are HIGH severity
            "command execution", "privilege escalation", "authentication bypass",
            # SQL injection is always HIGH severity
            "sql injection", "arbitrary file read", "arbitrary file write"
        ]
        
        for indicator in high_severity_indicators:
            if indicator in text:
                # If any of the high severity indicators are found, it's HIGH
                return "HIGH"
        
        # Use a simple heuristic based on the number of affected packages
        # More than 5 affected packages is considered HIGH severity
        # More than 2 affected packages is considered MEDIUM severity
        if packages and len(packages) > 5:
            # If more than 5 packages are affected, it's HIGH
            return "HIGH"
        elif packages and len(packages) > 2:
            # If more than 2 packages are affected, it's MEDIUM
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

        The exploitation likelihood is determined by checking the vulnerability type
        against a list of high-risk vulnerability types, as well as checking if there
        are any exploit references. If either condition is true, the exploitation
        likelihood is HIGH. If the vulnerability type is not high-risk, but there
        are exploit references, the exploitation likelihood is MEDIUM. Otherwise,
        the exploitation likelihood is LOW.

        Args:
            vuln_type (str): The type of vulnerability
            references (List[Dict], optional): A list of dictionaries containing
                references to the vulnerability. Defaults to None.

        Returns:
            str: The exploitation likelihood (HIGH, MEDIUM, or LOW)
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
                # Fix: Handle potential None values using or operator
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
        """Generate impact analysis based on vulnerability type and affected packages.

        The impact analysis is generated based on the vulnerability type and the number
        and types of affected packages. The analysis is structured as follows:
        - A general description of the potential impact of the vulnerability
        - A description of the specific impact of the vulnerability on the affected packages
        - A list of affected packages and ecosystems

        Args:
            vuln_type (str): The type of vulnerability
            summary (str): A summary of the vulnerability
            packages (List[Dict], optional): A list of dictionaries containing information about the affected packages. Defaults to None.

        Returns:
            str: The impact analysis
        """
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
        
        
    from typing import Dict, List, Any

    def analyze_cve(self, cve_id: str) -> Dict[str, Any]:
            """Analyze a specific CVE using local analysis."""

            cve_data = self.get_cve_details(cve_id)
            if not cve_data:
                raise ValueError(f"CVE {cve_id} not found in database")

            cve_info = cve_data[0]

            vulnerabilities = cve_info.get("vulnerabilities", [])

            # Fix: Initialize with empty list if None
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
        
        # Add type-specific
        # Add type-specific recommendations based on prevalent vulnerability types
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
        print("break?")
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

def main():
    """Main function to run the Neo4j Security Analyzer."""
    parser = argparse.ArgumentParser(description="Neo4j Security Vulnerability Analyzer")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j connection URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="jaguarai", help="Neo4j password")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--command", required=True, choices=[
        "schema", "stats", "vuln", "cve", "package", "ecosystem", "repo", "report"
    ], help="Command to execute")
    parser.add_argument("--target", help="Target ID for the command (vuln ID, CVE ID, package name, etc.)")
    parser.add_argument("--limit", type=int, default=10, help="Limit for result count")
    parser.add_argument("--output", help="Output file path for JSON results")
    
    args = parser.parse_args()
    
    analyzer = Neo4jSecurityAnalyzer(
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=args.neo4j_password,
        log_level=args.log_level
    )
    
    try:
        result = None
        
        if args.command == "schema":
            result = analyzer.get_database_schema()
            
        elif args.command == "stats":
            result = analyzer.get_vulnerability_statistics()
            
        elif args.command == "vuln":
            if args.target:
                result = analyzer.get_vulnerability_details(args.target)
            else:
                result = analyzer.get_vulnerability_details(limit=args.limit)
                
        elif args.command == "cve":
            if args.target:
                result = analyzer.get_cve_details(args.target)
            else:
                result = analyzer.get_cve_details(limit=args.limit)
                
        elif args.command == "package":
            if "@" in args.target:
                name, ecosystem = args.target.split("@", 1)
                result = analyzer.get_package_vulnerabilities(name, ecosystem)
            elif args.target:
                result = analyzer.get_package_vulnerabilities(args.target)
            else:
                result = analyzer.get_package_vulnerabilities(limit=args.limit)
                
        elif args.command == "ecosystem":
            if not args.target:
                print("Error: --target ecosystem_name is required for ecosystem command")
                return 1
            result = analyzer.get_ecosystem_vulnerabilities(args.target, args.limit)
            
        elif args.command == "repo":
            result = analyzer.get_repositories_with_vulnerabilities(args.limit)
            
        elif args.command == "report":
            if not args.target or ":" not in args.target:
                print("Error: --target must be in format type:id (e.g., vulnerability:CVE-2021-44228)")
                return 1
                
            target_type, target_id = args.target.split(":", 1)
            if target_type not in ["vulnerability", "cve", "package", "ecosystem"]:
                print(f"Error: Unknown target type {target_type}")
                return 1
                
            result = analyzer.generate_security_report(target_id, target_type)
        
        # Output results
        if result:
            result_json = json.dumps(result, indent=2, default=str)
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(result_json)
                print(f"Results written to {args.output}")
            else:
                print(result_json)
        else:
            print("No results returned")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    finally:
        analyzer.close()
    
    return 0


if __name__ == "__main__":
    exit(main())
