import neo4j from 'neo4j-driver'
import axios from 'axios';

class Neo4jService {
  constructor() {
    this.uri = import.meta.env.VITE_NEO4J_URI
    this.user = import.meta.env.VITE_NEO4J_USER
    this.password = import.meta.env.VITE_NEO4J_PASSWORD
    
    if (!this.uri || !this.user || !this.password) {
      console.error('Neo4j environment variables missing: VITE_NEO4J_URI, VITE_NEO4J_USER, VITE_NEO4J_PASSWORD must be set in .env file')
      throw new Error('Neo4j configuration missing')
    }
    
    this.driver = neo4j.driver(
      this.uri,
      neo4j.auth.basic(this.user, this.password)
    )
    console.log('Neo4j connection established')
    
    // Used to track the timer for daily updates
    this.updateTimer = null;
    
    // Schedule daily updates when the service initializes
    this.scheduleDailyUpdates();
  }

  async getStatistics() {
    const session = this.driver.session()
    try {
      const result = await session.run(`
        MATCH (n)
        RETURN 
        count(n) as totalNodes,
        count(DISTINCT labels(n)) as uniqueLabels
      `)
      return result.records[0]
    } catch (error) {
      console.error('Database Error:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getNodeDistribution() {
    const session = this.driver.session()
    try {
      // First, let's get all unique labels in the database and log them
      const labelsResult = await session.run(`
        MATCH (n)
        UNWIND labels(n) as label
        RETURN DISTINCT label
        ORDER BY label
      `)
      
      console.log('All unique node labels in database:')
      labelsResult.records.forEach(record => {
        console.log(`- "${record.get('label')}"`)
      })

      // Then get the distribution as before
      const result = await session.run(`
        MATCH (n)
        WITH labels(n) as labels
        UNWIND labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
      `)
      
      console.log('\nNode label distribution:')
      result.records.forEach(record => {
        console.log(`Label: "${record.get('label')}", Count: ${record.get('count').low}`)
      })
      
      return result.records.map(record => ({
        label: record.get('label'),
        count: record.get('count').low
      }))
    } catch (error) {
      console.error('Database Error:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getAllLabelsSampleData() {
    const session = this.driver.session()
    try {
      // First, get all unique labels
      const labelsResult = await session.run(`
        MATCH (n)
        UNWIND labels(n) as label
        RETURN DISTINCT label
        ORDER BY label
      `)
      
      const allLabels = labelsResult.records.map(record => record.get('label'))
      console.log(`Found ${allLabels.length} different node labels:`, allLabels)
      
      // For each label, get sample nodes
      for (const label of allLabels) {
        console.log(`\n========== LABEL: ${label} ==========`)
        
        // Get sample nodes with this label (limit to 3)
        const sampleNodesResult = await session.run(`
          MATCH (n:${label})
          RETURN n
          LIMIT 3
        `)
        
        if (sampleNodesResult.records.length === 0) {
          console.log(`  No nodes found with label ${label}`)
          continue
        }
        
        // Get properties from the first node to understand structure
        const firstNode = sampleNodesResult.records[0].get('n')
        const properties = Object.keys(firstNode.properties)
        console.log(`  Properties for ${label}:`, properties)
        
        // Print sample nodes
        sampleNodesResult.records.forEach((record, index) => {
          const node = record.get('n')
          console.log(`  Sample ${index + 1}:`, node.properties)
        })
        
        // Get count of nodes with this label
        const countResult = await session.run(`
          MATCH (n:${label})
          RETURN count(n) as count
        `)
        
        const count = countResult.records[0].get('count').low
        console.log(`  Total nodes with label ${label}: ${count}`)
        
        // Get relationship types for this label
        const relationshipsResult = await session.run(`
          MATCH (n:${label})-[r]-()
          RETURN DISTINCT type(r) as relType
          LIMIT 10
        `)
        
        const relationships = relationshipsResult.records.map(r => r.get('relType'))
        if (relationships.length > 0) {
          console.log(`  Relationship types:`, relationships)
        } else {
          console.log(`  No relationships found for ${label} nodes`)
        }
      }
      
      return allLabels
    } catch (error) {
      console.error('Database Error when exploring labels:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async updateVulnerabilities() {
    console.log('Starting daily update for vulnerabilities...');

    try {
      // Fetch and store data from OSV
      const osvUpdates = await this.fetchOSVData();
      console.log(`Updated ${osvUpdates.length} vulnerabilities from OSV.`);

      // Fetch and store data from NVD
      const nvdUpdates = await this.fetchNVDData();
      console.log(`Updated ${nvdUpdates.length} vulnerabilities from NVD.`);

      // Fetch and store data from ExploitDB
      const exploitDBUpdates = await this.fetchExploitDBData();
      console.log(`Updated ${exploitDBUpdates.length} vulnerabilities from ExploitDB.`);

      console.log('Daily update completed.');
    } catch (error) {
      console.error('Error during daily update:', error);
    }
  }

  async fetchOSVData() {
    try {
      // Fetch the list of ecosystems
      const ecosystemsResponse = await axios.get('https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt');
      const ecosystems = ecosystemsResponse.data.split('\n').filter(Boolean); // Split by newline and remove empty lines
      
      const vulnerabilities = [];
      
      // For each ecosystem, fetch popular packages and their vulnerabilities
      for (const ecosystem of ecosystems) {
        console.log(`Processing ecosystem: ${ecosystem}`);
        
        // For each ecosystem, we'll define popular packages or use an empty name to get all ecosystem vulnerabilities
        const popularPackages = await this.getPopularPackagesForEcosystem(ecosystem);
        
        // If no specific packages, add an empty string to get ecosystem-wide vulnerabilities
        if (popularPackages.length === 0) {
          popularPackages.push("");
        }
        
        // Process each package individually to get detailed vulnerability data
        for (const packageName of popularPackages) {
          try {
            const response = await axios.post('https://api.osv.dev/v1/query', {
              package: {
                name: packageName,
                ecosystem: ecosystem
              }
            });
            
            if (response.data && response.data.vulns) {
              console.log(`Found ${response.data.vulns.length} vulnerabilities for ${packageName || 'all packages'} in ${ecosystem}`);
              
              // For each vulnerability ID, get the full details
              for (const vuln of response.data.vulns) {
                try {
                  const detailsResponse = await axios.get(`https://api.osv.dev/v1/vulns/${vuln.id}`);
                  if (detailsResponse.data) {
                    const processedVuln = this.processVulnerability(detailsResponse.data);
                    vulnerabilities.push(processedVuln);
                    
                    // Store vulnerability in Neo4j
                    await this.storeVulnerability(processedVuln);
                  }
                } catch (detailsError) {
                  console.error(`Error fetching details for vulnerability ${vuln.id}:`, detailsError);
                }
                
                // Delay to respect API rate limits
                await new Promise(resolve => setTimeout(resolve, 200));
              }
            }
            
            // Delay between package queries to respect API rate limits
            await new Promise(resolve => setTimeout(resolve, 1000));
          } catch (packageError) {
            console.error(`Error querying vulnerabilities for ${packageName} in ${ecosystem}:`, packageError);
          }
        }
      }
      
      return vulnerabilities;
    } catch (error) {
      console.error('Error fetching OSV data:', error);
      return [];
    }
  }
  
  async getPopularPackagesForEcosystem(ecosystem) {
    // Return predefined popular packages for common ecosystems
    const popularPackagesByEcosystem = {
      'AlmaLinux': ['kernel', 'glibc', 'openssl'],
      'Alpine': ['apk-tools', 'musl', 'busybox'],
      'Android': ['androidx.appcompat', 'com.google.android.material', 'androidx.core'],
      'Bitnami': ['apache', 'nginx', 'mysql'],
      'CRAN': ['ggplot2', 'dplyr', 'tidyverse'],
      'Chainguard': ['gvisor', 'distroless'],
      'Debian': ['linux-image', 'glibc', 'openssl'],
      'GHC': ['base', 'containers', 'bytestring'],
      'GIT': ['git', 'git-lfs'],
      'GSD': ['python', 'ruby', 'nodejs'],
      'GitHub Actions': ['actions/checkout', 'actions/setup-node', 'actions/setup-python', 'actions/cache'],
      'Go': ['github.com/gorilla/mux', 'github.com/gin-gonic/gin', 'github.com/stretchr/testify','github.com/kubernetes/kubernetes', 'github.com/golang/go', 'github.com/docker/docker'],
      'Hackage': ['base', 'containers', 'bytestring'],
      'Hex': ['phoenix', 'ecto', 'plug'],
      'Linux': ['linux', 'glibc', 'openssl'],
      'Mageia': ['kernel', 'glibc', 'openssl'],
      'NUGet': ['Newtonsoft.Json', 'Microsoft.AspNetCore.Mvc', 'System.Text.Json'],
      'OSS-Fuzz': ['libxml2', 'libpng', 'openssl'],
      'Packagist': ['symfony/symfony', 'laravel/framework', 'guzzlehttp/guzzle'],
      'Pub': ['http', 'json_serializable', 'provider'],
      'PyPI': ['django', 'flask', 'requests', 'numpy', 'pandas', 'tensorflow'],
      'npm': ['react', 'express', 'axios', 'lodash', 'moment', 'angular'],
      'Maven': ['org.apache.maven.plugins', 'org.apache.maven', 'org.apache.commons','org.springframework', 'com.fasterxml.jackson.core', 'log4j', 'apache.tomcat'],
      'Red Hat': ['kernel', 'glibc', 'openssl'],
      'Rocky Linux': ['kernel', 'glibc', 'openssl'],
      'RubyGems': ['rails', 'nokogiri', 'rack', 'activerecord'],
      'SUSE': ['kernel', 'glibc', 'openssl'],
      'SwiftURL': ['swift', 'foundation', 'dispatch'],
      'UVI': ['kernel', 'glibc', 'openssl'],
      'Ubuntu': ['linux-image', 'glibc', 'openssl'],
      'Wolfi': ['apk-tools', 'musl', 'busybox'],
      'crates.io': ['serde', 'tokio', 'actix-web', 'reqwest', 'rocket'],
      'openSUSE': ['kernel', 'glibc', 'openssl'],
    };
    
    return popularPackagesByEcosystem[ecosystem] || [];
  }
  
  processVulnerability(vuln) {
    return {
      id: vuln.id,
      summary: vuln.summary || '',
      details: vuln.details || '',
      modified: vuln.modified || new Date().toISOString(),
      published: vuln.published || new Date().toISOString(),
      ecosystems: vuln.affected?.map(a => a.package?.ecosystem).filter(Boolean) || [],
      packages: vuln.affected?.map(a => a.package?.name).filter(Boolean) || [],
      severity: this.extractSeverity(vuln)
    };
  }
  
  extractSeverity(vuln) {
    if (!vuln.severity || vuln.severity.length === 0) {
      return 'UNKNOWN';
    }
    
    // Try to find a CVSS score
    for (const sev of vuln.severity) {
      if (sev.type === 'CVSS_V3' && sev.score) {
        const score = parseFloat(sev.score);
        if (!isNaN(score)) {
          if (score >= 9.0) return 'CRITICAL';
          if (score >= 7.0) return 'HIGH';
          if (score >= 4.0) return 'MEDIUM';
          if (score >= 0.1) return 'LOW';
        }
      }
    }
    
    return 'UNKNOWN';
  }
  
  async storeVulnerability(vulnerability) {
    if (!vulnerability) return;
    
    const session = this.driver.session();
    try {
      // Create vulnerability node
      await session.run(`
        MERGE (v:Vulnerability {id: $id})
        ON CREATE SET 
          v.summary = $summary,
          v.details = $details,
          v.severity = $severity,
          v.published = datetime($published),
          v.modified = datetime($modified),
          v.created_at = datetime()
        ON MATCH SET 
          v.summary = $summary,
          v.details = $details,
          v.severity = $severity,
          v.modified = datetime($modified),
          v.updated_at = datetime()
      `, {
        id: vulnerability.id,
        summary: vulnerability.summary,
        details: vulnerability.details,
        severity: vulnerability.severity,
        published: vulnerability.published,
        modified: vulnerability.modified
      });
      
      // Create package nodes and relationships
      for (let i = 0; i < vulnerability.packages.length; i++) {
        const pkgName = vulnerability.packages[i];
        const ecosystem = vulnerability.ecosystems[i] || 'unknown';
        
        await session.run(`
          MERGE (p:Package {name: $name, ecosystem: $ecosystem})
          ON CREATE SET p.created_at = datetime()
          WITH p
          MATCH (v:Vulnerability {id: $vulnId})
          MERGE (v)-[r:AFFECTS]->(p)
          ON CREATE SET r.created_at = datetime()
        `, {
          name: pkgName,
          ecosystem: ecosystem,
          vulnId: vulnerability.id
        });
      }
    } catch (error) {
      console.error('Error storing vulnerability in Neo4j:', error);
    } finally {
      await session.close();
    }
  }

  scheduleDailyUpdates() {
    // Cancel any existing timer
    if (this.updateTimer) {
      clearTimeout(this.updateTimer);
    }
    
    // Calculate time until next midnight
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    
    const timeUntilMidnight = tomorrow.getTime() - now.getTime();
    
    // Schedule the update
    this.updateTimer = setTimeout(() => {
      this.updateVulnerabilities();
      
      // Set up the next day's update (recursive)
      this.scheduleDailyUpdates();
    }, timeUntilMidnight);
    
    console.log(`Scheduled next vulnerability update for ${tomorrow.toLocaleString()}, in ${Math.floor(timeUntilMidnight/1000/60)} minutes`);
  }
}

// Create and export a singleton instance instead of the class
const neo4jServiceInstance = new Neo4jService();
export default neo4jServiceInstance;