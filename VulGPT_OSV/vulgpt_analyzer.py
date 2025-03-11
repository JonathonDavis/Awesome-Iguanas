#!/usr/bin/env python3
"""
Simple VulGPT Analyzer
Provides analysis and search functionality for vulnerability data in Neo4j
"""

import sys
import json
import time
from neo4j import GraphDatabase

def print_status(message):
    """Print status message with timestamp"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")

class VulGPTAnalyzer:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="jaguarai"):
        """Initialize the analyzer with Neo4j connection parameters"""
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            print_status("Connected to Neo4j database")
        except Exception as e:
            print_status(f"Error connecting to Neo4j: {e}")
            sys.exit(1)

    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def search_vulnerabilities(self, query=None, severity=None, ecosystem=None, package=None, limit=10):
        """Search for vulnerabilities based on various criteria"""
        with self.driver.session() as session:
            # Build the Cypher query
            cypher_query = "MATCH (v:Vulnerability)"
            where_clauses = []
            params = {"limit": limit}

            # Add package filter if specified
            if package:
                cypher_query += " MATCH (v)-[:AFFECTS]->(p:Package)"
                where_clauses.append("p.name CONTAINS $package")
                params["package"] = package

                # Add ecosystem filter if specified with package
                if ecosystem:
                    where_clauses.append("p.ecosystem = $ecosystem")
                    params["ecosystem"] = ecosystem
            # Add ecosystem filter without package
            elif ecosystem:
                cypher_query += " MATCH (v)-[:AFFECTS]->(p:Package)"
                where_clauses.append("p.ecosystem = $ecosystem")
                params["ecosystem"] = ecosystem

            # Add text search if specified
            if query:
                where_clauses.append("(v.summary CONTAINS $query OR v.details CONTAINS $query)")
                params["query"] = query

            # Add severity filter if specified
            if severity:
                where_clauses.append("v.severity = $severity")
                params["severity"] = severity

            # Add WHERE clause if any filters were applied
            if where_clauses:
                cypher_query += " WHERE " + " AND ".join(where_clauses)

            # Complete the query
            cypher_query += " RETURN v.id as id, v.summary as summary, v.severity as severity LIMIT $limit"

            # Execute the query
            result = session.run(cypher_query, **params)
            return [dict(record) for record in result]

    def get_vulnerability_details(self, vuln_id):
        """Get detailed information about a specific vulnerability"""
        with self.driver.session() as session:
            # Get basic vulnerability info
            result = session.run("""
                MATCH (v:Vulnerability {id: $id})
                RETURN v.id as id, v.summary as summary, v.details as details,
                       v.severity as severity
            """, id=vuln_id)

            record = result.single()
            if not record:
                return None

            vulnerability = dict(record)

            # Get affected packages
            result = session.run("""
                MATCH (v:Vulnerability {id: $id})-[r:AFFECTS]->(p:Package)
                RETURN p.name as name, p.ecosystem as ecosystem
            """, id=vuln_id)

            vulnerability["affected_packages"] = [dict(record) for record in result]

            return vulnerability

    def analyze_package(self, package_name, ecosystem=None):
        """Analyze vulnerabilities affecting a specific package"""
        with self.driver.session() as session:
            # Build the query based on whether ecosystem is provided
            if ecosystem:
                result = session.run("""
                    MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package {name: $name, ecosystem: $ecosystem})
                    RETURN v.id as id, v.summary as summary, v.severity as severity
                """, name=package_name, ecosystem=ecosystem)
            else:
                result = session.run("""
                    MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)
                    WHERE p.name CONTAINS $name
                    RETURN v.id as id, v.summary as summary, v.severity as severity,
                           p.ecosystem as ecosystem
                """, name=package_name)

            vulnerabilities = [dict(record) for record in result]

            # Count vulnerabilities by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "UNKNOWN")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                "package_name": package_name,
                "ecosystem": ecosystem,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerabilities": vulnerabilities
            }

    def get_dashboard_data(self):
        """Get data for a simple dashboard"""
        with self.driver.session() as session:
            # Total counts
            result = session.run("""
                MATCH (v:Vulnerability) RETURN count(v) as vulnerabilities
            """)
            total_vulnerabilities = result.single()["vulnerabilities"]

            result = session.run("""
                MATCH (p:Package) RETURN count(p) as packages
            """)
            total_packages = result.single()["packages"]

            # Severity distribution
            result = session.run("""
                MATCH (v:Vulnerability)
                RETURN v.severity as severity, count(v) as count
                ORDER BY count DESC
            """)
            severity_distribution = {record["severity"]: record["count"] for record in result}

            # Top ecosystems
            result = session.run("""
                MATCH (p:Package)
                RETURN p.ecosystem as ecosystem, count(p) as count
                ORDER BY count DESC
                LIMIT 5
            """)
            top_ecosystems = {record["ecosystem"]: record["count"] for record in result}

            # Top affected packages
            result = session.run("""
                MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)
                WITH p.name as name, p.ecosystem as ecosystem, count(v) as vuln_count
                ORDER BY vuln_count DESC
                LIMIT 10
                RETURN name, ecosystem, vuln_count
            """)
            top_affected_packages = [{"name": r["name"], "ecosystem": r["ecosystem"], "vuln_count": r["vuln_count"]}
                                 for r in result]

            # Recent vulnerabilities
            result = session.run("""
                MATCH (v:Vulnerability)
                RETURN v.id as id, v.summary as summary, v.severity as severity
                ORDER BY v.created_at DESC
                LIMIT 5
            """)
            recent_vulnerabilities = [dict(record) for record in result]

            return {
                "total_vulnerabilities": total_vulnerabilities,
                "total_packages": total_packages,
                "severity_distribution": severity_distribution,
                "top_ecosystems": top_ecosystems,
                "top_affected_packages": top_affected_packages,
                "recent_vulnerabilities": recent_vulnerabilities
            }

def main():
    """Main function to run the VulGPT analyzer"""
    import argparse

    parser = argparse.ArgumentParser(description="VulGPT Vulnerability Analyzer")
    parser.add_argument("--search", help="Search term in vulnerability summary and details")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                       help="Filter by severity level")
    parser.add_argument("--ecosystem", help="Filter by ecosystem")
    parser.add_argument("--package", help="Filter by package name")
    parser.add_argument("--id", help="Get details for a specific vulnerability ID")
    parser.add_argument("--analyze-package", help="Analyze vulnerabilities for a specific package")
    parser.add_argument("--dashboard", action="store_true", help="Show dashboard data")
    parser.add_argument("--limit", type=int, default=10, help="Maximum number of results")

    args = parser.parse_args()

    analyzer = VulGPTAnalyzer()
    try:
        if args.id:
            # Get details for a specific vulnerability
            details = analyzer.get_vulnerability_details(args.id)
            if details:
                print("\n==== Vulnerability Details ====")
                print(f"ID: {details['id']}")
                print(f"Severity: {details.get('severity', 'Unknown')}")
                print(f"Summary: {details.get('summary', 'No summary available')}")

                if details.get('details'):
                    print("\nDetails:")
                    print(details['details'])

                if details.get('affected_packages'):
                    print("\nAffected Packages:")
                    for pkg in details['affected_packages']:
                        print(f"  - {pkg.get('name')} ({pkg.get('ecosystem')})")
            else:
                print(f"No vulnerability found with ID: {args.id}")

        elif args.analyze_package:
            # Analyze a package
            analysis = analyzer.analyze_package(args.analyze_package, args.ecosystem)

            print("\n==== Package Vulnerability Analysis ====")
            print(f"Package: {analysis['package_name']}")
            if analysis['ecosystem']:
                print(f"Ecosystem: {analysis['ecosystem']}")

            print(f"Total Vulnerabilities: {analysis['total_vulnerabilities']}")

            if analysis['severity_counts']:
                print("\nSeverity Distribution:")
                for severity, count in analysis['severity_counts'].items():
                    print(f"  {severity}: {count}")

            if analysis['vulnerabilities']:
                print("\nVulnerabilities:")
                for i, vuln in enumerate(analysis['vulnerabilities'], 1):
                    print(f"\n{i}. {vuln.get('id')}")
                    print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                    print(f"   Summary: {vuln.get('summary', 'No summary available')}")

        elif args.search or args.severity or args.ecosystem or args.package:
            # Search for vulnerabilities
            results = analyzer.search_vulnerabilities(
                query=args.search,
                severity=args.severity,
                ecosystem=args.ecosystem,
                package=args.package,
                limit=args.limit
            )

            print(f"\n==== Search Results ({len(results)} found) ====")
            for i, vuln in enumerate(results, 1):
                print(f"\n{i}. {vuln['id']}")
                print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                print(f"   Summary: {vuln.get('summary', 'No summary available')}")

        elif args.dashboard or not any([args.search, args.severity, args.ecosystem, args.package, args.id, args.analyze_package]):
            # Show dashboard
            dashboard = analyzer.get_dashboard_data()

            print("\n==== VulGPT Dashboard ====")
            print(f"Total Vulnerabilities: {dashboard['total_vulnerabilities']}")
            print(f"Total Affected Packages: {dashboard['total_packages']}")

            print("\nSeverity Distribution:")
            for severity, count in dashboard['severity_distribution'].items():
                percentage = (count / dashboard['total_vulnerabilities']) * 100 if dashboard['total_vulnerabilities'] > 0 else 0
                print(f"  {severity}: {count} ({percentage:.1f}%)")

            print("\nTop Ecosystems:")
            for ecosystem, count in dashboard['top_ecosystems'].items():
                print(f"  - {ecosystem}: {count} packages")

            print("\nMost Affected Packages:")
            for pkg in dashboard['top_affected_packages']:
                print(f"  - {pkg['name']} ({pkg['ecosystem']}): {pkg['vuln_count']} vulnerabilities")

            print("\nRecent Vulnerabilities:")
            for vuln in dashboard['recent_vulnerabilities']:
                summary = vuln.get('summary', 'No summary')
                if len(summary) > 80:
                    summary = summary[:77] + "..."
                print(f"  - {vuln['id']} ({vuln.get('severity', 'Unknown')}): {summary}")

    except KeyboardInterrupt:
        print_status("Operation interrupted by user")
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()