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
        self.ollama_url = ollama_url
        self.model = model
        self.logger.info(f"Configured to use Ollama model: {model}")
        
        # Verify Ollama connection
        try:
            self._test_ollama_connection()
            self.logger.info("Successfully verified connection to Ollama")
        except Exception as e:
            self.logger.error(f"Failed to connect to Ollama service: {str(e)}")
            raise

    def _test_ollama_connection(self) -> None:
        """Test the connection to Ollama service."""
        payload = {
            "model": self.model,
            "prompt": "Respond with 'Connection successful' if you receive this message.",
            "stream": False
        }
        print('test')
        response = requests.post(self.ollama_url, json=payload)
        
        if response.status_code != 200:
            raise ConnectionError(f"Failed to connect to Ollama: HTTP {response.status_code}")
        
        result = response.json()
        if "error" in result:
            raise ConnectionError(f"Ollama error: {result['error']}")

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
        query = """
        CALL db.labels() YIELD label
        MATCH (n) WHERE n:$label
        RETURN $label as label, count(n) as count
        """
        
        results = {}
        labels = [label["label"] for label in self.query_neo4j("CALL db.labels()")]
        
        for label in labels:
            count_result = self.query_neo4j(query, {"label": label})
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
                    return {"raw_analysis": text}
            except json.JSONDecodeError:
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
        
        prompt = f"""
        Analyze the security posture of the '{ecosystem}' ecosystem based on this vulnerability data:
        
        {json.dumps(eco_data, indent=2)}
        
        Generate a comprehensive security assessment in JSON format with the following structure:
        {{
          "ecosystem_name": "{ecosystem}",
          "overall_security_rating": "GOOD|FAIR|POOR",
          "common_vulnerability_patterns": [...],
          "highest_risk_packages": [...],
          "systemic_security_issues": [...],
          "recommended_security_improvements": [...],
          "security_trend_analysis": "..."
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
        
        prompt = f"""
        Analyze the security posture of repository: {repository_url}
        
        Repository data: {json.dumps(repo_data, indent=2)}
        
        Generate a comprehensive security assessment in JSON format with the following structure:
        {{
          "repository_url": "{repository_url}",
          "security_rating": "GOOD|FAIR|POOR",
          "critical_vulnerabilities": [...],
          "vulnerable_dependencies": [...],
          "security_improvement_recommendations": [...],
          "dependency_update_priorities": [...],
          "security_architecture_recommendations": "..."
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
        
        prompt = f"""
        Analyze the following vulnerability dataset ({len(vuln_data)} records) and identify important trends:
        
        {json.dumps(vuln_data[:25], indent=2)}
        
        [... additional {len(vuln_data) - 25} records omitted for brevity ...]
        
        Generate a comprehensive trend analysis in JSON format with the following structure:
        {{
          "most_affected_ecosystems": [...],
          "common_vulnerability_patterns": [...],
          "trending_vulnerability_types": [...],
          "emerging_threats": [...],
          "security_focus_recommendations": [...],
          "temporal_trends": "..."
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
        
        report_data = {
            "database_statistics": database_stats,
            "schema_overview": schema,
            "top_vulnerabilities": top_vulns,
            "vulnerable_repositories": top_repos
        }
        
        system_prompt = """
        You are a chief security officer providing an executive summary of security vulnerabilities.
        Based on the comprehensive security data provided, generate a detailed security assessment
        report with clear, actionable insights. Format your report as valid JSON with organized sections.
        """
        
        prompt = f"""
        Generate a comprehensive security assessment report based on this database overview:
        
        Database Statistics:
        {json.dumps(database_stats, indent=2)}
        
        Top Vulnerabilities:
        {json.dumps([{
            "id": v.get("id"),
            "summary": v.get("summary"),
            "cves": v.get("cve_ids"),
            "package_count": len(v.get("affected_packages", []))
        } for v in top_vulns], indent=2)}
        
        Vulnerable Repositories:
        {json.dumps(top_repos, indent=2)}
        
        Generate a comprehensive executive security report in JSON format that includes:
        - Executive summary
        - Critical vulnerability assessment
        - Ecosystem security analysis
        - Prioritized remediation recommendations
        - Long-term security strategy
        - Key metrics and indicators
        """
        
        analysis_result = self.analyze_with_ollama(prompt, system_prompt)
        response_text = analysis_result.get("response", "{}")
        
        return self._extract_json_from_response(response_text)


def main():
    parser = argparse.ArgumentParser(description='Ollama Neo4j Security Analyzer')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='jaguarai', help='Neo4j password')
    parser.add_argument('--ollama-url', default='http://localhost:11434/api/generate', help='Ollama API URL')
    parser.add_argument('--model', default='llama3', help='Ollama model name')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    parser.add_argument('--action', choices=['overview', 'cve', 'vulnerability', 'ecosystem', 'trends', 'report'], 
                        default='overview', help='Analysis action to perform')
    parser.add_argument('--id', help='ID for specific CVE or vulnerability analysis')
    parser.add_argument('--ecosystem', help='Ecosystem name for ecosystem analysis')
    parser.add_argument('--output', help='Output file for JSON results')
    
    args = parser.parse_args()
    
    analyzer = None
    try:
        # Initialize the analyzer
        analyzer = OllamaNeo4jSecurityAnalyzer(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password,
            ollama_url=args.ollama_url,
            model=args.model,
            log_level=args.log_level
        )
        
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
            print(f"\nCVE Analysis Results:")
            print(f"- Severity: {result.get('severity', 'Unknown')}")
            print(f"- Vulnerability Type: {result.get('vulnerability_type', 'Unknown')}")
            print(f"- Potential Impact: {result.get('potential_impact', 'Unknown')}")
            
        elif args.action == 'vulnerability':
            if not args.id:
                print("Error: --id parameter required for vulnerability analysis")
                return
                
            print(f"Analyzing vulnerability: {args.id}...")
            result = analyzer.analyze_vulnerability(args.id)
            print(f"\nVulnerability Analysis Results:")
            print(f"- Severity: {result.severity}")
            print(f"- Vulnerability Type: {result.vulnerability_type}")
            print(f"- Exploitation Likelihood: {result.exploitation_likelihood}")
            print(f"- Affected Ecosystems: {', '.join(result.affected_ecosystems)}")
            
        elif args.action == 'ecosystem':
            if not args.ecosystem:
                print("Error: --ecosystem parameter required for ecosystem analysis")
                return
                
            print(f"Analyzing ecosystem: {args.ecosystem}...")
            result = analyzer.analyze_ecosystem_security(args.ecosystem)
            print(f"\nEcosystem Security Analysis:")
            print(f"- Overall Security Rating: {result.get('overall_security_rating', 'Unknown')}")
            print(f"- Common Vulnerability Patterns: {', '.join(result.get('common_vulnerability_patterns', []))}")
            print(f"- Highest Risk Packages: {', '.join(result.get('highest_risk_packages', []))}")
            
        elif args.action == 'trends':
            print("Analyzing vulnerability trends...")
            result = analyzer.analyze_vulnerability_trends()
            print(f"\nVulnerability Trend Analysis:")
            print(f"- Most Affected Ecosystems: {', '.join(result.get('most_affected_ecosystems', []))}")
            print(f"- Trending Vulnerability Types: {', '.join(result.get('trending_vulnerability_types', []))}")
            print(f"- Emerging Threats: {', '.join(result.get('emerging_threats', []))}")
            
        elif args.action == 'report':
            print("Generating comprehensive security report...")
            result = analyzer.generate_comprehensive_security_report()
            print(f"\nComprehensive Security Report Generated")
            print(f"- Executive Summary: {result.get('executive_summary', 'Not available')[:100]}...")
            print(f"- Critical Vulnerabilities Count: {len(result.get('critical_vulnerabilities', []))}")
            
        # Save results to file if output is specified
        if result and args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\nResults saved to {args.output}")
            except Exception as e:
                print(f"Error saving results to file: {str(e)}")
                
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        # Clean up resources
        if analyzer:
            analyzer.close()
            
    print("\nAnalysis complete.")

if __name__ == "__main__":
    main()
