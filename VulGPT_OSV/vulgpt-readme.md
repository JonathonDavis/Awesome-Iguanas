# VulGPT - Vulnerability Analysis Tools

This collection of tools helps you analyze software vulnerabilities and store them in a Neo4j database for further analysis. These tools were created to work with the OSV (Open Source Vulnerabilities) API and Neo4j.

## Files Overview

### Main Tools

- **`run_vulgpt.sh`**: Main interactive script with a menu interface for all functionality
- **`osv_direct_import.py`**: Directly imports known CVEs (most reliable method)
- **`osv_collector_simple.py`**: Collects vulnerability data from OSV API by package/ecosystem
- **`vulgpt_analyzer.py`**: Tool for searching and analyzing stored vulnerability data

### Setup Scripts

- **`install.sh`**: Makes scripts executable and installs dependencies
- **`setup_vulgpt.sh`**: More extensive setup that checks Neo4j connection

## Quick Start

1. **Make the scripts executable**:
   ```bash
   chmod +x run_vulgpt.sh osv_direct_import.py osv_collector_simple.py vulgpt_analyzer.py
   ```

2. **Ensure Neo4j is running** with the credentials neo4j/jaguarai.

3. **Import vulnerability data**:
   ```bash
   python3 osv_direct_import.py
   ```

4. **Run the analyzer to see what was imported**:
   ```bash
   python3 vulgpt_analyzer.py --dashboard
   ```

## Usage Guide

### 1. Importing Data

Start with the direct import, which uses known CVEs:
```bash
python3 osv_direct_import.py
```

For specific packages (recommended approach):
```bash
python3 osv_collector_simple.py --ecosystem PyPI --package django
```

Common ecosystems to try:
- PyPI (Python)
- npm (JavaScript)
- Maven (Java)
- RubyGems (Ruby)
- Go (Go language)

### 2. Analyzing Data

View the dashboard summary:
```bash
python3 vulgpt_analyzer.py --dashboard
```

Search for vulnerabilities:
```bash
python3 vulgpt_analyzer.py --search "injection"
```

Filter by severity:
```bash
python3 vulgpt_analyzer.py --severity HIGH
```

Analyze a specific package:
```bash
python3 vulgpt_analyzer.py --analyze-package log4j --ecosystem Maven
```

View details of a specific vulnerability:
```bash
python3 vulgpt_analyzer.py --id CVE-2021-44228
```

### 3. Interactive Mode

For an easier interface, use the menu-driven script:
```bash
./run_vulgpt.sh
```

## Known Issues and Workarounds

### CVSS Score Format

**Issue**: The OSV API returns CVSS scores as strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" rather than numeric values.

**Workaround**: We've updated the scripts to handle these string formats and assign appropriate severity levels.

### API Changes

**Issue**: The OSV API endpoints and request formats have changed over time.

**Workaround**: We use a more direct approach by querying specific CVEs or packages rather than using the general search endpoints.

### Missing CVEs

**Issue**: Not all CVEs are available in the OSV database.

**Workaround**: Focus on collecting data for specific packages (like django, react, etc.) which tend to have better coverage.

### Neo4j Connection Issues

**Issue**: Scripts may fail if Neo4j is not running or has different credentials.

**Workaround**: Ensure Neo4j is running and check the connection parameters in the scripts (default is neo4j/jaguarai at bolt://localhost:7687).

## Best Practices

1. **Start with Direct Import**: The `osv_direct_import.py` script provides the most reliable way to get initial data.

2. **Focus on Popular Packages**: Target well-known packages like django, flask, react, etc. for better results.

3. **Check Specific CVEs**: If looking for a particular vulnerability, use its CVE ID directly.

4. **Use Dashboard First**: After importing data, check the dashboard to see what's available before doing specific searches.

## Neo4j Tips

### Viewing Data in Neo4j Browser

1. Go to http://localhost:7474 in your web browser
2. Log in with neo4j/jaguarai (or your current credentials)
3. Run Cypher queries to explore the data:

```cypher
// View all vulnerabilities
MATCH (v:Vulnerability) RETURN v LIMIT 25;

// View affected packages
MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package) RETURN v, p LIMIT 25;

// Get high severity vulnerabilities
MATCH (v:Vulnerability) WHERE v.severity = "HIGH" RETURN v;
```

## Troubleshooting

1. **Verify Neo4j Connection**:
   ```bash
   python3 -c "from neo4j import GraphDatabase; driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'jaguarai')); driver.verify_connectivity()"
   ```

2. **Check API Connectivity**:
   ```bash
   curl https://api.osv.dev/v1/vulns/CVE-2021-44228
   ```

3. **Debug Data Collection**:
   If not getting any results, try focusing on well-known packages. For example:
   ```bash
   python3 osv_collector_simple.py --ecosystem npm --package axios
   ```

4. **Clear Database** (if needed):
   In Neo4j Browser, run:
   ```cypher
   MATCH (n) DETACH DELETE n;
   ```
