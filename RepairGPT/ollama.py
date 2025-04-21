import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json
import time
import argparse

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError
import requests

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

class OllamaNeo4jSecurityAnalyzer:
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "jaguarai",
        ollama_url: str = "http://localhost:11434",
        model: str = "llama3",
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
        
        # Ollama configuration
        # Ensure the URL points to the generate endpoint
        if not ollama_url.endswith('/api/generate'):
             self.ollama_url = f"{ollama_url.rstrip('/')}/api/generate"
        else:
            self.ollama_url = ollama_url
            
        self.model = model
        self.logger.info(f"Configured to use Ollama model: {model}")
        

    def _test_ollama_connection(self) -> None:
        """Test the connection to Ollama service."""
        # Use the base URL for the health check, not the /api/generate endpoint
        base_ollama_url = self.ollama_url.replace('/api/generate', '')
        if not base_ollama_url: # handle case where ollama_url was just /api/generate
             base_ollama_url = self.ollama_url.replace('api/generate', '') # try removing just api/generate

        try:
            response = requests.get(base_ollama_url)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            # A successful response to the base URL usually indicates the service is running.
            self.logger.info("Successfully connected to Ollama service")
        except requests.exceptions.RequestException as e:
             raise ConnectionError(f"Failed to connect to Ollama service at {base_ollama_url}: {str(e)}")

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

    def analyze_with_ollama(self, prompt: str, system_prompt: str = None) -> Dict:
        """Send data to Ollama for analysis."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        if system_prompt:
            payload["system"] = system_prompt
            
        try:
            self.logger.info(f"Sending prompt to Ollama (length: {len(prompt)})")
            response = requests.post(self.ollama_url, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ollama request error: {str(e)}")
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

    def _extract_json_from_response(self, text: str) -> Dict:
        """Extract JSON from Ollama's response text."""
        try:
            # Try to parse the entire text as JSON first
            return json.loads(text)
        except json.JSONDecodeError:
            # Look for a JSON block in the response
            try:
                json_start = text.find('{')
                json_end = text.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_str = text[json_start:json_end]
                    return json.loads(json_str)
                else:
                    # Return raw analysis if no JSON block found
                    return {"raw_analysis": text}
            except json.JSONDecodeError:
                # Return raw analysis if JSON block parsing fails
                return {"raw_analysis": text}

    def analyze_vulnerability(self, vuln_id: str) -> SecurityInsight:
        """Analyze a specific vulnerability using Ollama."""
        vuln_data = self.get_vulnerability_details(vuln_id)
        if not vuln_data:
            raise ValueError(f"Vulnerability {vuln_id} not found in database")
        
        vuln_info = vuln_data[0]
        
        # Format data for Ollama
        system_prompt = """
        You are a security vulnerability analyst specializing in CVE analysis and threat intelligence.
        Provide detailed security insights about the vulnerability information provided.
        Format your output strictly as valid JSON with the following keys:
        - severity (string: LOW, MEDIUM, HIGH, or CRITICAL)
        - vulnerability_type (string: brief categorization like "Buffer Overflow", "SQL Injection", etc.)
        - affected_ecosystems (array of strings)
        - impact_analysis (string: comprehensive analysis of potential impacts)
        - remediation_steps (string: specific steps for remediation)
        - exploitation_likelihood (string: LOW, MEDIUM, or HIGH with rationale)
        - recommendation (string: security recommendation)
        
        Be technical, precise, and focused on actionable security insights.
        """
        
        # Use json.dumps for complex data structures within the prompt to ensure correct formatting
        prompt = f"""
        Please analyze the following vulnerability information and provide detailed security insights:
        
        Vulnerability ID: {vuln_info.get('id')}
        Summary: {vuln_info.get('summary')}
        Details: {vuln_info.get('details')}
        Publication Date: {vuln_info.get('published')}
        Last Modified: {vuln_info.get('modified')}
        
        Affected Components:
        {json.dumps(vuln_info.get('affected_packages', []), indent=2)}
        
        Associated CVEs:
        {json.dumps(vuln_info.get('cve_ids', []), indent=2)}
        
        References:
        {json.dumps(vuln_info.get('references', []), indent=2)}
        
        Additional JSON Data:
        {vuln_info.get('affected_json', '{}')}
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        analysis = self._extract_json_from_response(response_text)
        
        # Create a structured insight object
        return SecurityInsight(
            vulnerability_id=vuln_id,
            severity=analysis.get("severity", "Unknown"),
            affected_ecosystems=analysis.get("affected_ecosystems", []),
            vulnerability_type=analysis.get("vulnerability_type", "Unknown"),
            impact_analysis=analysis.get("impact_analysis", "No analysis available"),
            remediation_steps=analysis.get("remediation_steps", "No remediation steps available"),
            exploitation_likelihood=analysis.get("exploitation_likelihood", "Unknown"),
            recommendation=analysis.get("recommendation", "No recommendation available")
        )

    def analyze_cve(self, cve_id: str) -> Dict:
        """Analyze a specific CVE using Ollama."""
        cve_data = self.get_cve_details(cve_id)
        if not cve_data:
            raise ValueError(f"CVE {cve_id} not found in database")
            
        # Format data for Ollama
        system_prompt = """
        You are a security vulnerability analyst specializing in CVE analysis and threat intelligence.
        Based on the CVE information provided, generate a detailed security analysis in JSON format.
        Include technical details, severity assessment, vulnerability type classification, and remediation options.
        Format your output strictly as valid JSON.
        """
        
        # Use json.dumps for the data sent to Ollama
        prompt = f"""
        Analyze the following CVE information and provide detailed security insights:
        
        CVE ID: {cve_id}
        
        Vulnerability Details: {json.dumps(cve_data, indent=2)}
        
        Please provide your analysis in JSON format with the following structure:
        {{
          "severity": "LOW|MEDIUM|HIGH|CRITICAL",
          "vulnerability_type": "...",
          "potential_impact": "...",
          "affected_systems": [...],
          "exploitation_vectors": [...],
          "recommended_mitigations": [...],
          "technical_analysis": "..."
        }}
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)

    def analyze_ecosystem_security(self, ecosystem: str) -> Dict:
        """Analyze security posture of a particular ecosystem."""
        eco_data = self.get_ecosystem_vulnerabilities(ecosystem, limit=25)
        
        system_prompt = """
        You are a security ecosystem analyst. Provide a comprehensive security analysis of the ecosystem
        based on its vulnerability profile. Focus on identifying patterns, common vulnerability types,
        and systemic security issues. Format output as valid JSON.
        """
        
        # Use json.dumps for the data sent to Ollama
        prompt = f"""
        Analyze the security posture of the '{ecosystem}' ecosystem based on this vulnerability data:
        
        {json.dumps(eco_data, indent=2)}
        
        Generate a comprehensive security assessment in JSON format with the following structure:
        {{
          "ecosystem_name": "{ecosystem}",
          "overall_security_rating": "GOOD|FAIR|POOR",
          "common_vulnerability_patterns": [], // array of strings or objects
          "highest_risk_packages": [], // array of strings or objects
          "systemic_security_issues": [], // array of strings or objects
          "recommended_security_improvements": [], // array of strings or objects
          "security_trend_analysis": "..." // string
        }}
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)
        
    def analyze_repository_security(self, repository_url: str) -> Dict:
        """Analyze the security profile of a specific repository."""
        # Query for repository info
        query = """
        MATCH (repo:Repository {url: $url})
        OPTIONAL MATCH (repo)<-[]-(pkg:Package)<-[]-(vuln:Vulnerability)
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        OPTIONAL MATCH (pkg)-[]-(ver:Version)
        RETURN repo.url as repository_url,
               collect(DISTINCT {
                 name: pkg.name, 
                 ecosystem: pkg.ecosystem
               }) as packages,
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
               }) as versions
        """
        
        repo_data = self.query_neo4j(query, {"url": repository_url})
        
        if not repo_data or not repo_data[0].get("repository_url"):
            raise ValueError(f"Repository {repository_url} not found in database")
        
        system_prompt = """
        You are a repository security auditor. Analyze the security profile of the repository
        based on its associated vulnerabilities, packages, and versions. Provide actionable
        security recommendations. Format output as valid JSON.
        """
        
        # Use json.dumps for the data sent to Ollama
        prompt = f"""
        Analyze the security posture of repository: {repository_url}
        
        Repository data: {json.dumps(repo_data, indent=2)}
        
        Generate a comprehensive security assessment in JSON format with the following structure:
        {{
          "repository_url": "{repository_url}",
          "security_rating": "GOOD|FAIR|POOR",
          "critical_vulnerabilities": [], // array of vulnerability summaries or IDs
          "vulnerable_dependencies": [], // array of package names and versions
          "security_improvement_recommendations": [], // array of strings
          "dependency_update_priorities": [], // array of package names and suggested versions
          "security_architecture_recommendations": "..." // string
        }}
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)
    
    def analyze_vulnerability_trends(self, limit: int = 100) -> Dict:
        """Analyze vulnerability trends in the database."""
        # Get recent vulnerabilities
        query = """
        MATCH (vuln:Vulnerability)
        OPTIONAL MATCH (cve:CVE)-[]->(vuln)
        OPTIONAL MATCH (vuln)-[]->(pkg:Package)
        RETURN vuln.id as id, 
               vuln.summary as summary,
               vuln.published as published, 
               collect(DISTINCT cve.id) as cve_ids,
               collect(DISTINCT pkg.ecosystem) as ecosystems
        ORDER BY vuln.published DESC
        LIMIT $limit
        """
        
        vuln_data = self.query_neo4j(query, {"limit": limit})
        
        system_prompt = """
        You are a security trend analyst specializing in vulnerability intelligence.
        Based on the vulnerability data provided, identify important security trends, patterns,
        and emerging threats. Format your analysis as valid JSON.
        """
        
        # Use json.dumps for the data sent to Ollama
        prompt = f"""
        Analyze the following vulnerability dataset ({len(vuln_data)} records) and identify important trends:
        
        {json.dumps(vuln_data[:25], indent=2)}
        
        {json.dumps(vuln_data[25:], indent=2) if len(vuln_data) > 25 else ""}
        
        Generate a comprehensive trend analysis in JSON format with the following structure:
        {{
          "most_affected_ecosystems": [], // array of strings
          "common_vulnerability_patterns": [], // array of strings or objects
          "trending_vulnerability_types": [], // array of strings
          "emerging_threats": [], // array of strings
          "security_focus_recommendations": [], // array of strings
          "temporal_trends": "..." // string analysis over time
        }}
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)

    def generate_comprehensive_security_report(self) -> Dict:
        """Generate a comprehensive security report across the database."""
        # Gather data for report
        database_stats = self.count_nodes_by_label()
        top_vulns = self.get_vulnerability_details(limit=10)
        top_repos = self.get_repositories_with_vulnerabilities(limit=10)
        schema = self.get_database_schema()
        
        # Prepare simplified vulnerability data for the report prompt
        simplified_top_vulns = [{
            "id": v.get("id"),
            "summary": v.get("summary"),
            "cves": v.get("cve_ids"),
            "package_count": len(v.get("affected_packages", []))
        } for v in top_vulns]

        report_data = {
            "database_statistics": database_stats,
            "schema_overview": schema,
            "top_vulnerabilities": simplified_top_vulns,
            "vulnerable_repositories": top_repos
        }
        
        system_prompt = """
        You are a chief security officer providing an executive summary of security vulnerabilities.
        Based on the comprehensive security data provided, generate a detailed security assessment
        report with clear, actionable insights. Format your report as valid JSON with organized sections.
        """
        
        # Use json.dumps for the data sent to Ollama
        prompt = f"""
        Generate a comprehensive security assessment report based on this database overview:
        
        {json.dumps(report_data, indent=2)}
        
        Generate a comprehensive executive security report in JSON format that includes:
        - executive_summary (string)
        - critical_vulnerability_assessment (string)
        - ecosystem_security_analysis (string)
        - prioritized_remediation_recommendations (array of strings)
        - long_term_security_strategy (string)
        - key_metrics_and_indicators (object with relevant counts/stats)
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)


def main():
    parser = argparse.ArgumentParser(description='Ollama Neo4j Security Analyzer')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='jaguarai', help='Neo4j password')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama API base URL (e.g., http://localhost:11434)')
    parser.add_argument('--model', default='llama3', help='Ollama model name')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    parser.add_argument('--action', choices=['overview', 'cve', 'vulnerability', 'ecosystem', 'repository', 'trends', 'report'], 
                        default='overview', help='Analysis action to perform')
    parser.add_argument('--id', help='ID for specific CVE or vulnerability analysis')
    parser.add_argument('--ecosystem', help='Ecosystem name for ecosystem analysis')
    parser.add_argument('--repository-url', help='Repository URL for repository analysis')
    parser.add_argument('--output', help='Output file for JSON results')
    
    args = parser.parse_args()
    
    analyzer = None
    try:
        # Initialize the analyzer
        analyzer = OllamaNeo4jSecurityAnalyzer(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password,
            ollama_url=args.ollama_url, # Pass base URL, init handles /api/generate
            model=args.model,
            log_level=args.log_level
        )
        
        # Test Ollama connection early
        analyzer._test_ollama_connection()
        
        print("=== Neo4j Security Analyzer with Ollama ===\n")
        
        # Execute requested action
        result = None
        
        if args.action == 'overview':
            print("Generating database overview...")
            db_stats = analyzer.count_nodes_by_label()
            print(f"\nDatabase Statistics:")
            for label, count in db_stats.items():
                print(f"- {label}: {count}")
                
            schema = analyzer.get_database_schema()
            print(f"\nDatabase Schema:")
            print(f"- Node labels: {', '.join(schema['node_labels'])}")
            print(f"- Relationship types: {', '.join(schema['relationship_types'])}")
            # Optionally print properties and relationships
            # print(f"- Properties: {json.dumps(schema['properties'], indent=2)}")
            # print(f"- Relationships: {json.dumps(schema['relationships'], indent=2)}")
            
            result = {
                "statistics": db_stats,
                "schema": schema
            }
            
        elif args.action == 'cve':
            if not args.id:
                print("Error: --id parameter required for CVE analysis")
                return
                
            print(f"Analyzing CVE: {args.id}...")
            result = analyzer.analyze_cve(args.id)
            print(f"\nCVE Analysis Results (for {args.id}):")
            # Safely print potentially missing keys
            print(f"- Severity: {result.get('severity', 'Unknown')}")
            print(f"- Vulnerability Type: {result.get('vulnerability_type', 'Unknown')}")
            print(f"- Potential Impact: {result.get('potential_impact', 'Unknown')}")
            # Use json.dumps for list/object results from LLM to avoid type errors
            print(f"- Affected Systems: {json.dumps(result.get('affected_systems', []), indent=2)}")
            print(f"- Exploitation Vectors: {json.dumps(result.get('exploitation_vectors', []), indent=2)}")
            print(f"- Recommended Mitigations: {json.dumps(result.get('recommended_mitigations', []), indent=2)}")
            print(f"- Technical Analysis: {result.get('technical_analysis', 'No analysis available')}")
            
        elif args.action == 'vulnerability':
            if not args.id:
                print("Error: --id parameter required for vulnerability analysis")
                return
                
            print(f"Analyzing Vulnerability: {args.id}...")
            # This function already returns a structured SecurityInsight object
            result_obj = analyzer.analyze_vulnerability(args.id) 
            print(f"\nVulnerability Analysis Results (for {args.id}):")
            print(f"- Severity: {result_obj.severity}")
            print(f"- Vulnerability Type: {result_obj.vulnerability_type}")
            # Use json.dumps for lists in dataclass
            print(f"- Affected Ecosystems: {json.dumps(result_obj.affected_ecosystems, indent=2)}")
            print(f"- Exploitation Likelihood: {result_obj.exploitation_likelihood}")
            print(f"- Impact Analysis: {result_obj.impact_analysis}")
            print(f"- Remediation Steps: {result_obj.remediation_steps}")
            print(f"- Recommendation: {result_obj.recommendation}")
            
            # Convert dataclass to dict for potential JSON output file
            result = result_obj.__dict__

        elif args.action == 'ecosystem':
            if not args.ecosystem:
                print("Error: --ecosystem parameter required for ecosystem analysis")
                return

            print(f"Analyzing ecosystem: {args.ecosystem}...")
            result = analyzer.analyze_ecosystem_security(args.ecosystem)
            print(f"\nEcosystem Security Analysis:")
            # Safely print potentially missing keys
            print(f"- Overall Security Rating: {result.get('overall_security_rating', 'Unknown')}")
            # Use json.dumps for list/object results from LLM to avoid type errors
            print(f"- Common Vulnerability Patterns: {json.dumps(result.get('common_vulnerability_patterns', []), indent=2)}")
            print(f"- Highest Risk Packages: {json.dumps(result.get('highest_risk_packages', []), indent=2)}")
            print(f"- Systemic Security Issues: {json.dumps(result.get('systemic_security_issues', []), indent=2)}")
            print(f"- Recommended Security Improvements: {json.dumps(result.get('recommended_security_improvements', []), indent=2)}")
            print(f"- Security Trend Analysis: {result.get('security_trend_analysis', 'No analysis available')}")

        elif args.action == 'repository':
             if not args.repository_url:
                 print("Error: --repository-url parameter required for repository analysis")
                 return

             print(f"Analyzing repository: {args.repository_url}...")
             result = analyzer.analyze_repository_security(args.repository_url)
             print(f"\nRepository Security Analysis (for {args.repository_url}):")
             # Safely print potentially missing keys
             print(f"- Security Rating: {result.get('security_rating', 'Unknown')}")
             # Use json.dumps for list/object results from LLM to avoid type errors
             print(f"- Critical Vulnerabilities: {json.dumps(result.get('critical_vulnerabilities', []), indent=2)}")
             print(f"- Vulnerable Dependencies: {json.dumps(result.get('vulnerable_dependencies', []), indent=2)}")
             print(f"- Security Improvement Recommendations: {json.dumps(result.get('security_improvement_recommendations', []), indent=2)}")
             print(f"- Dependency Update Priorities: {json.dumps(result.get('dependency_update_priorities', []), indent=2)}")
             print(f"- Security Architecture Recommendations: {result.get('security_architecture_recommendations', 'No analysis available')}")
             
        elif args.action == 'trends':
            print("Analyzing vulnerability trends...")
            result = analyzer.analyze_vulnerability_trends()
            print(f"\nVulnerability Trend Analysis:")
            # Safely print potentially missing keys
            print(f"- Most Affected Ecosystems: {json.dumps(result.get('most_affected_ecosystems', []), indent=2)}")
            print(f"- Common Vulnerability Patterns: {json.dumps(result.get('common_vulnerability_patterns', []), indent=2)}")
            print(f"- Trending Vulnerability Types: {json.dumps(result.get('trending_vulnerability_types', []), indent=2)}")
            print(f"- Emerging Threats: {json.dumps(result.get('emerging_threats', []), indent=2)}")
            print(f"- Security Focus Recommendations: {json.dumps(result.get('security_focus_recommendations', []), indent=2)}")
            print(f"- Temporal Trends: {result.get('temporal_trends', 'No analysis available')}")

        elif args.action == 'report':
            print("Generating comprehensive security report...")
            result = analyzer.generate_comprehensive_security_report()
            print(f"\nComprehensive Security Report:")
            # Safely print potentially missing keys
            print(f"- Executive Summary: {result.get('executive_summary', 'No summary available')}")
            print(f"- Critical Vulnerability Assessment: {result.get('critical_vulnerability_assessment', 'No assessment available')}")
            print(f"- Ecosystem Security Analysis: {result.get('ecosystem_security_analysis', 'No analysis available')}")
            # Use json.dumps for list/object results from LLM to avoid type errors
            print(f"- Prioritized Remediation Recommendations: {json.dumps(result.get('prioritized_remediation_recommendations', []), indent=2)}")
            print(f"- Long-Term Security Strategy: {result.get('long_term_security_strategy', 'No strategy available')}")
            print(f"- Key Metrics and Indicators: {json.dumps(result.get('key_metrics_and_indicators', {}), indent=2)}")

        # Write result to output file if specified
        if args.output and result is not None:
            try:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nAnalysis results written to {args.output}")
            except IOError as e:
                print(f"Error writing to output file {args.output}: {str(e)}")

    except (ServiceUnavailable, AuthError, ConnectionError, ValueError, requests.exceptions.RequestException) as e:
        logging.error(f"An error occurred during execution: {str(e)}")
        print(f"\nAn error occurred: {str(e)}")
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print(f"\nAn unexpected error occurred: {str(e)}")
    finally:
        # Ensure the Neo4j connection is closed
        if analyzer:
            analyzer.close()

if __name__ == "__main__":
    main()
