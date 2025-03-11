#!/usr/bin/env python3
"""
Simple OSV Vulnerability Collector
Collects vulnerability data from OSV API and stores it in Neo4j
"""

import requests
import json
import time
import sys
from neo4j import GraphDatabase
import datetime

def print_status(message):
    """Print status message with timestamp"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")

class OSVCollector:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="jaguarai"):
        """Initialize the OSV collector with Neo4j connection parameters"""
        # Updated API URL to use the latest version
        self.osv_api_url = "https://api.osv.dev/v1"
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            print_status("Connected to Neo4j database")
            self.setup_database()
        except Exception as e:
            print_status(f"Error connecting to Neo4j: {e}")
            sys.exit(1)

    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def setup_database(self):
        """Set up the Neo4j database with constraints and indexes"""
        with self.driver.session() as session:
            # Create constraints and indexes
            session.run("CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
            session.run("CREATE INDEX vulnerability_package IF NOT EXISTS FOR (p:Package) ON (p.name)")
            print_status("Database setup complete")

    def get_vulnerabilities_by_batch(self, batch_size=100):
        """Query the OSV API to get a batch of vulnerabilities"""
        try:
            # Get vulnerabilities for a specific popular ecosystem since general query doesn't work
            ecosystems = ["PyPI", "npm", "Maven", "Go", "Debian"]
            chosen_ecosystem = ecosystems[0]  # Start with PyPI

            url = f"{self.osv_api_url}/query"
            data = {
                "package": {
                    "name": "",
                    "ecosystem": chosen_ecosystem
                }
            }

            response = requests.post(url, json=data)
            response.raise_for_status()
            result = response.json()

            return result.get("vulns", []), result.get("next_page_token")
        except requests.exceptions.RequestException as e:
            print_status(f"Error fetching vulnerabilities: {e}")
            return [], None

    def get_vulnerability_details(self, vuln_id):
        """Get detailed information about a specific vulnerability"""
        try:
            url = f"{self.osv_api_url}/vulns/{vuln_id}"
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print_status(f"Error fetching vulnerability {vuln_id}: {e}")
            return None

    def store_vulnerability(self, vulnerability):
        """Store a vulnerability in Neo4j"""
        with self.driver.session() as session:
            try:
                # Create the vulnerability node
                vuln_id = vulnerability.get("id")

                # Basic details
                summary = vulnerability.get("summary", "")
                details = vulnerability.get("details", "")
                severity = self._extract_severity(vulnerability)

                # Create vulnerability node
                session.run("""
                    MERGE (v:Vulnerability {id: $id})
                    ON CREATE SET v.summary = $summary,
                                 v.details = $details,
                                 v.severity = $severity,
                                 v.created_at = datetime()
                    ON MATCH SET v.summary = $summary,
                               v.details = $details,
                               v.severity = $severity,
                               v.updated_at = datetime()
                """, id=vuln_id, summary=summary, details=details, severity=severity)

                # Create affected packages and relationships
                self._store_affected_packages(vuln_id, vulnerability.get("affected", []))

                print_status(f"Stored vulnerability: {vuln_id}")

            except Exception as e:
                print_status(f"Error storing vulnerability {vulnerability.get('id')}: {e}")

    def _extract_severity(self, vulnerability):
        """Extract severity from the vulnerability"""
        # Check if CVSS score exists
        for severity in vulnerability.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                score = severity.get("score")
                if score:
                    try:
                        # Try to extract the base score from the CVSS string if it's in that format
                        if isinstance(score, str) and score.startswith('CVSS:'):
                            # For CVSS strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            # Use a default high severity since we can't easily parse it
                            return "HIGH"
                        else:
                            # If it's a numeric score
                            score_value = float(score)
                            if score_value >= 9.0:
                                return "CRITICAL"
                            elif score_value >= 7.0:
                                return "HIGH"
                            elif score_value >= 4.0:
                                return "MEDIUM"
                            elif score_value >= 0.1:
                                return "LOW"
                    except (ValueError, TypeError):
                        # If conversion fails, default to HIGH for safety
                        return "HIGH"

        # If no CVSS score is found or can't be parsed, check for CWE IDs that indicate higher severity
        for cwe in vulnerability.get("cwe", []):
            # CWEs commonly associated with high severity issues
            high_severity_cwes = ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-77", "CWE-22", "CWE-119", "CWE-120"]
            if any(cwe_id in cwe for cwe_id in high_severity_cwes):
                return "HIGH"

        return "UNKNOWN"

    def _store_affected_packages(self, vuln_id, affected_packages):
        """Store affected packages and their relationships to the vulnerability"""
        with self.driver.session() as session:
            for package in affected_packages:
                pkg_name = package.get("package", {}).get("name", "unknown")
                pkg_ecosystem = package.get("package", {}).get("ecosystem", "unknown")

                # Create package node
                session.run("""
                    MERGE (p:Package {name: $name, ecosystem: $ecosystem})
                    ON CREATE SET p.created_at = datetime()
                """, name=pkg_name, ecosystem=pkg_ecosystem)

                # Create relationship between vulnerability and package
                session.run("""
                    MATCH (v:Vulnerability {id: $vuln_id})
                    MATCH (p:Package {name: $pkg_name, ecosystem: $pkg_ecosystem})
                    MERGE (v)-[r:AFFECTS]->(p)
                    ON CREATE SET r.created_at = datetime()
                """, vuln_id=vuln_id, pkg_name=pkg_name, pkg_ecosystem=pkg_ecosystem)

    def collect_initial_data(self, max_pages=5):
        """Collect initial set of vulnerabilities"""
        print_status("Starting initial data collection")

        # Try collecting from multiple ecosystems
        ecosystems = ["PyPI", "npm", "Maven", "Go", "Debian", "NuGet", "RubyGems"]
        total_vulns = 0

        for ecosystem in ecosystems[:3]:  # Try top 3 ecosystems
            print_status(f"Trying to collect from ecosystem: {ecosystem}")
            vulns_count = self.collect_by_ecosystem(ecosystem, pages=1)
            total_vulns += vulns_count

            if vulns_count > 0:
                print_status(f"Successfully collected {vulns_count} vulnerabilities from {ecosystem}")
                break

            print_status(f"No vulnerabilities found in {ecosystem}, trying next ecosystem")
            time.sleep(1)

        if total_vulns == 0:
            print_status("Could not collect any vulnerabilities from common ecosystems")
            # Try a specific well-known package
            try:
                print_status("Trying to find vulnerabilities for specific packages...")
                for ecosystem in ['PyPI', 'npm']:
                    for package in ['requests', 'axios', 'django', 'react', 'flask']:
                        url = f"{self.osv_api_url}/query"
                        data = {
                            "package": {
                                "name": package,
                                "ecosystem": ecosystem
                            }
                        }

                        response = requests.post(url, json=data)
                        if response.status_code == 200:
                            result = response.json()
                            vulns = result.get("vulns", [])

                            if vulns:
                                print_status(f"Found {len(vulns)} vulnerabilities for {package} in {ecosystem}")
                                for vuln in vulns:
                                    vuln_id = vuln.get("id")
                                    vuln_details = self.get_vulnerability_details(vuln_id)
                                    if vuln_details:
                                        self.store_vulnerability(vuln_details)
                                        total_vulns += 1
                                break

                        time.sleep(0.5)

                    if total_vulns > 0:
                        break
            except Exception as e:
                print_status(f"Error searching for package vulnerabilities: {e}")

        print_status(f"Initial data collection complete. Total vulnerabilities: {total_vulns}")
        return total_vulns

    def collect_by_ecosystem(self, ecosystem, pages=1):
        """Collect vulnerabilities for a specific ecosystem"""
        print_status(f"Collecting vulnerabilities for ecosystem: {ecosystem}")

        try:
            url = f"{self.osv_api_url}/query"
            total_vulns = 0
            page_token = None

            for i in range(pages):
                data = {
                    "package": {
                        "name": "",
                        "ecosystem": ecosystem
                    }
                }

                if page_token:
                    data["page_token"] = page_token

                response = requests.post(url, json=data)
                response.raise_for_status()
                result = response.json()
                vulns = result.get("vulns", [])

                if not vulns:
                    print_status(f"No vulnerabilities found for ecosystem: {ecosystem}")
                    break

                print_status(f"Collected {len(vulns)} vulnerabilities for {ecosystem} (batch {i+1})")
                total_vulns += len(vulns)

                for vuln in vulns:
                    vuln_id = vuln.get("id")
                    vuln_details = self.get_vulnerability_details(vuln_id)
                    if vuln_details:
                        self.store_vulnerability(vuln_details)
                    time.sleep(0.1)

                # Check if there's a next page
                page_token = result.get("next_page_token")
                if not page_token:
                    break

                time.sleep(1)

            print_status(f"Collected {total_vulns} vulnerabilities for ecosystem: {ecosystem}")
            return total_vulns

        except requests.exceptions.RequestException as e:
            print_status(f"Error collecting vulnerabilities for {ecosystem}: {e}")
            return 0

    def update_vulnerabilities(self, days_back=1):
        """Update vulnerabilities modified in the last X days"""
        # Try a different approach - query for specific packages
        print_status(f"Looking for recent vulnerabilities (last {days_back} days)")

        popular_packages = {
            "PyPI": ["requests", "django", "flask", "numpy", "tensorflow"],
            "npm": ["axios", "express", "react", "lodash", "moment"]
        }

        total_updates = 0

        for ecosystem, packages in popular_packages.items():
            for package in packages:
                try:
                    print_status(f"Checking for vulnerabilities in {package} ({ecosystem})")
                    url = f"{self.osv_api_url}/query"
                    data = {
                        "package": {
                            "name": package,
                            "ecosystem": ecosystem
                        }
                    }

                    response = requests.post(url, json=data)
                    if response.status_code == 200:
                        result = response.json()
                        vulns = result.get("vulns", [])

                        if vulns:
                            print_status(f"Found {len(vulns)} vulnerabilities for {package}")
                            for vuln in vulns:
                                vuln_id = vuln.get("id")
                                vuln_details = self.get_vulnerability_details(vuln_id)
                                if vuln_details:
                                    self.store_vulnerability(vuln_details)
                                    total_updates += 1

                    time.sleep(0.5)
                except Exception as e:
                    print_status(f"Error updating vulnerabilities for {package}: {e}")

        print_status(f"Update complete. Added/updated {total_updates} vulnerabilities.")
        return total_updates

    def collect_top_ecosystems(self):
        """Collect vulnerabilities for top ecosystems"""
        ecosystems = [
            "PyPI", "npm", "Maven", "Go", "Debian",
            "NuGet", "RubyGems", "Packagist", "crates.io", "Alpine"
        ]

        total_vulns = 0

        # Create a list of specific packages for popular ecosystems
        packages_by_ecosystem = {
            "PyPI": ["django", "flask", "requests", "numpy", "tensorflow"],
            "npm": ["express", "react", "axios", "lodash", "moment"],
            "Maven": ["org.apache.logging.log4j", "com.fasterxml.jackson.core", "org.springframework"],
            "Go": ["github.com/golang/go", "github.com/kubernetes/kubernetes"]
        }

        # First try the ecosystem-wide approach
        for ecosystem in ecosystems[:4]:  # Try top 4 ecosystems
            try:
                count = self.collect_by_ecosystem(ecosystem, pages=1)
                total_vulns += count
                if count > 0:
                    print_status(f"Successfully collected {count} vulnerabilities from {ecosystem}")
                time.sleep(1)  # Delay between ecosystems
            except Exception as e:
                print_status(f"Error collecting from {ecosystem}: {e}")

        # If we couldn't get any vulnerabilities, try specific packages
        if total_vulns == 0:
            print_status("Trying specific packages for each ecosystem...")
            for ecosystem, packages in packages_by_ecosystem.items():
                for package in packages:
                    try:
                        print_status(f"Checking {package} in {ecosystem}...")
                        url = f"{self.osv_api_url}/query"
                        data = {
                            "package": {
                                "name": package,
                                "ecosystem": ecosystem
                            }
                        }

                        response = requests.post(url, json=data)
                        if response.status_code == 200:
                            result = response.json()
                            vulns = result.get("vulns", [])

                            if vulns:
                                print_status(f"Found {len(vulns)} vulnerabilities for {package}")
                                for vuln in vulns:
                                    vuln_id = vuln.get("id")
                                    vuln_details = self.get_vulnerability_details(vuln_id)
                                    if vuln_details:
                                        self.store_vulnerability(vuln_details)
                                        total_vulns += 1

                        time.sleep(0.5)
                    except Exception as e:
                        print_status(f"Error checking {package}: {e}")

                if total_vulns > 10:  # If we found enough, stop looking
                    break

        print_status(f"Total vulnerabilities collected: {total_vulns}")
        return total_vulns

    def get_stats(self):
        """Get basic statistics about the stored vulnerability data"""
        with self.driver.session() as session:
            # Count vulnerabilities
            result = session.run("MATCH (v:Vulnerability) RETURN count(v) as count")
            total_vulnerabilities = result.single()["count"]

            # Count packages
            result = session.run("MATCH (p:Package) RETURN count(p) as count")
            total_packages = result.single()["count"]

            # Count by severity
            result = session.run("""
                MATCH (v:Vulnerability)
                RETURN v.severity AS severity, count(v) AS count
                ORDER BY count DESC
            """)
            severity_counts = {record["severity"]: record["count"] for record in result}

            # Count by ecosystem
            result = session.run("""
                MATCH (p:Package)
                RETURN p.ecosystem AS ecosystem, count(p) AS count
                ORDER BY count DESC
                LIMIT 10
            """)
            ecosystem_counts = {record["ecosystem"]: record["count"] for record in result}

            return {
                "total_vulnerabilities": total_vulnerabilities,
                "total_packages": total_packages,
                "severity_counts": severity_counts,
                "ecosystem_counts": ecosystem_counts
            }

def main():
    """Main function to run the OSV collector"""
    import argparse

    parser = argparse.ArgumentParser(description="Simple OSV Vulnerability Collector")
    parser.add_argument("--initial", action="store_true", help="Perform initial collection")
    parser.add_argument("--update", action="store_true", help="Update recent vulnerabilities")
    parser.add_argument("--pages", type=int, default=5, help="Maximum number of pages to collect")
    parser.add_argument("--days", type=int, default=7, help="Days to look back for updates")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--ecosystem", help="Collect vulnerabilities for a specific ecosystem")
    parser.add_argument("--top-ecosystems", action="store_true", help="Collect vulnerabilities for top ecosystems")

    args = parser.parse_args()

    collector = OSVCollector()
    try:
        if args.ecosystem:
            # Collect for a specific ecosystem
            collector.collect_by_ecosystem(args.ecosystem, pages=args.pages)

        elif args.top_ecosystems:
            # Collect for top ecosystems
            collector.collect_top_ecosystems()

        elif args.initial:
            # Collect initial data
            collector.collect_initial_data(max_pages=args.pages)

        elif args.update:
            # Update recent vulnerabilities
            updated = collector.update_vulnerabilities(days_back=args.days)
            print_status(f"Updated {updated} vulnerabilities")

        # Show stats (either requested explicitly or after any operation)
        stats = collector.get_stats()
        print("\n==== VulGPT Database Statistics ====")
        print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"Total packages: {stats['total_packages']}")

        if stats['severity_counts']:
            print("\nVulnerabilities by severity:")
            for severity, count in stats['severity_counts'].items():
                print(f"  {severity}: {count}")

        if stats['ecosystem_counts']:
            print("\nTop package ecosystems:")
            for ecosystem, count in stats['ecosystem_counts'].items():
                print(f"  {ecosystem}: {count}")

    except KeyboardInterrupt:
        print_status("Operation interrupted by user")
    finally:
        collector.close()

if __name__ == "__main__":
    main()