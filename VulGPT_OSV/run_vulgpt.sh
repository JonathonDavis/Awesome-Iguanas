#!/usr/bin/env python3
"""
Direct OSV import - gets specific known CVEs and imports them to Neo4j
"""
import requests
import json
import time
import sys
from neo4j import GraphDatabase

def print_status(message):
    """Print status message with timestamp"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")

class OSVDirectImporter:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="jaguarai"):
        """Initialize the OSV importer with Neo4j connection parameters"""
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

                # Create references
                self._store_references(vuln_id, vulnerability.get("references", []))

                print_status(f"Stored vulnerability: {vuln_id}")
                return True

            except Exception as e:
                print_status(f"Error storing vulnerability {vulnerability.get('id')}: {e}")
                return False

    def _extract_severity(self, vulnerability):
        """Extract severity from the vulnerability"""
        # Check if CVSS score exists
        for severity in vulnerability.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                score = severity.get("score")
                if score:
                    # Extract severity based on CVSS score
                    score_value = float(score)
                    if score_value >= 9.0:
                        return "CRITICAL"
                    elif score_value >= 7.0:
                        return "HIGH"
                    elif score_value >= 4.0:
                        return "MEDIUM"
                    elif score_value >= 0.1:
                        return "LOW"

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

    def _store_references(self, vuln_id, references):
        """Store references related to the vulnerability"""
        with self.driver.session() as session:
            for i, ref in enumerate(references):
                ref_type = ref.get("type", "UNKNOWN")
                ref_url = ref.get("url", "")

                if ref_url:
                    # Create reference node
                    session.run("""
                        MERGE (r:Reference {url: $url})
                        ON CREATE SET r.type = $type, r.created_at = datetime()
                        ON MATCH SET r.type = $type, r.updated_at = datetime()
                    """, url=ref_url, type=ref_type)

                    # Create relationship between vulnerability and reference
                    session.run("""
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MATCH (r:Reference {url: $url})
                        MERGE (v)-[rel:HAS_REFERENCE]->(r)
                        ON CREATE SET rel.created_at = datetime()
                        ON MATCH SET rel.updated_at = datetime()
                    """, vuln_id=vuln_id, url=ref_url)

    def import_known_cves(self):
        """Import a list of known CVEs to seed the database"""
        # List of notable CVEs to import
        cve_list = [
            # Log4Shell vulnerability
            "CVE-2021-44228",
            # Spring4Shell
            "CVE-2022-22965",
            # Heartbleed
            "CVE-2014-0160",
            # Apache Struts vulnerability
            "CVE-2017-5638",
            # SolarWinds/SUNBURST
            "CVE-2020-10148",
            # Exchange Server vulnerability
            "CVE-2021-26855",
            # Shellshock
            "CVE-2014-6271",
            # POODLE
            "CVE-2014-3566",
            # EternalBlue/WannaCry
            "CVE-2017-0144",
            # Spectre
            "CVE-2017-5753",
            # Meltdown
            "CVE-2017-5754"
        ]

        # Also try some popular package vulnerabilities
        packages = [
            {"name": "django", "ecosystem": "PyPI"},
            {"name": "flask", "ecosystem": "PyPI"},
            {"name": "requests", "ecosystem": "PyPI"},
            {"name": "axios", "ecosystem": "npm"},
            {"name": "react", "ecosystem": "npm"},
            {"name": "express", "ecosystem": "npm"},
            {"name": "log4j", "ecosystem": "Maven"},
            {"name": "spring-boot", "ecosystem": "Maven"}
        ]

        successful_imports = 0

        # First try direct CVE lookups
        print_status("Importing known CVEs...")
        for cve_id in cve_list:
            print_status(f"Looking up {cve_id}")
            vulnerability = self.get_vulnerability_details(cve_id)

            if vulnerability:
                if self.store_vulnerability(vulnerability):
                    successful_imports += 1

            time.sleep(0.5)

        # Then try package lookups
        if successful_imports < 5:  # If we don't have enough data yet
            print_status("Searching for package vulnerabilities...")
            for package in packages:
                try:
                    print_status(f"Querying for {package['name']} ({package['ecosystem']}) vulnerabilities")
                    url = f"{self.osv_api_url}/query"
                    data = {
                        "package": {
                            "name": package["name"],
                            "ecosystem": package["ecosystem"]
                        }
                    }

                    response = requests.post(url, json=data)
                    if response.status_code == 200:
                        result = response.json()
                        vulns = result.get("vulns", [])

                        if vulns:
                            print_status(f"Found {len(vulns)} vulnerabilities for {package['name']}")
                            for vuln in vulns[:5]:  # Import up to 5 vulns per package
                                vuln_id = vuln.get("id")
                                vuln_details = self.get_vulnerability_details(vuln_id)

                                if vuln_details and self.store_vulnerability(vuln_details):
                                    successful_imports += 1

                                if successful_imports >= 25:  # Limit to 25 total imports
                                    break

                                time.sleep(0.5)

                        if successful_imports >= 25:
                            break

                except Exception as e:
                    print_status(f"Error querying for {package['name']}: {e}")

                time.sleep(1)

        print_status(f"Import complete. Successfully imported {successful_imports} vulnerabilities.")
        return successful_imports

    def get_stats(self):
        """Get basic statistics about the stored vulnerability data"""
        with self.driver.session() as session:
            # Count vulnerabilities
            result = session.run("MATCH (v:Vulnerability) RETURN count(v) as count")
            total_vulnerabilities = result.single()["count"]

            # Count packages
            result = session.run("MATCH (p:Package) RETURN count(p) as count")
            total_packages = result.single()["count"]

            # Count references
            result = session.run("MATCH (r:Reference) RETURN count(r) as count")
            total_references = result.single()["count"]

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
                "total_references": total_references,
                "severity_counts": severity_counts,
                "ecosystem_counts": ecosystem_counts
            }

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description="Import known CVEs directly into Neo4j")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")

    args = parser.parse_args()

    importer = OSVDirectImporter()
    try:
        importer.import_known_cves()

        stats = importer.get_stats()
        print("\n==== VulGPT Database Statistics ====")
        print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"Total packages: {stats['total_packages']}")
        print(f"Total references: {stats['total_references']}")

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
        importer.close()

if __name__ == "__main__":
    main()
