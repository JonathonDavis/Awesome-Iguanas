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
    
    // Used to track the timers for updates
    this.updateTimer = null;
    this.continuousUpdateTimer = null;
    this.continuousUpdateInterval = 3600000; // 1 hour in milliseconds
    
    // We'll keep the daily updates functionality but remove the console log
    this.scheduleDailyUpdatesQuietly();
    
    // Start continuous OSV updates
    this.startContinuousOSVUpdates();
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
  
  /**
   * Starts continuous updates from OSV with throttled fetching
   */
  startContinuousOSVUpdates() {
    // Clear any existing timer
    if (this.continuousUpdateTimer) {
      clearInterval(this.continuousUpdateTimer);
    }
    
    console.log(`Starting continuous OSV updates every ${this.continuousUpdateInterval/60000} minutes`);
    
    // Do an initial update
    this.fetchLatestOSVUpdates();
    
    // Set up recurring updates
    this.continuousUpdateTimer = setInterval(() => {
      this.fetchLatestOSVUpdates();
    }, this.continuousUpdateInterval);
  }
  
  /**
   * Stops the continuous OSV updates
   */
  stopContinuousOSVUpdates() {
    if (this.continuousUpdateTimer) {
      clearInterval(this.continuousUpdateTimer);
      this.continuousUpdateTimer = null;
      console.log('Continuous OSV updates stopped');
    }
  }
  
  /**
   * Fetch only the latest updates from OSV to minimize API usage
   */
  async fetchLatestOSVUpdates() {
    try {
      console.log('Fetching latest OSV vulnerability updates...');
      
      // Get the most recent update timestamp from our database
      const latestTimestamp = await this.getLatestVulnerabilityTimestamp();
      const since = latestTimestamp || new Date(Date.now() - 86400000).toISOString(); // Default to 24 hours ago
      
      // Fetch the list of ecosystems (limit to popular ones for continuous updates)
      const popularEcosystems = [
        'PyPI', 'npm', 'Maven', 'Go', 'NuGet', 'crates.io', 'Debian', 
        'Ubuntu', 'Alpine', 'GitHub Actions', 'Ruby', 'Packagist'
      ];
      
      let updatedVulnerabilities = 0;
      
      // Process each ecosystem
      for (const ecosystem of popularEcosystems) {
        try {
          // Get the most active packages for this ecosystem
          const activePackages = await this.getActivePackagesForEcosystem(ecosystem);
          
          // For each package, look for vulnerabilities modified since our last check
          for (const packageName of activePackages) {
            try {
              const response = await axios.post('https://api.osv.dev/v1/query', {
                package: {
                  name: packageName,
                  ecosystem: ecosystem
                },
                modified_since: since
              });
              
              if (response.data && response.data.vulns && response.data.vulns.length > 0) {
                console.log(`Found ${response.data.vulns.length} updated vulnerabilities for ${packageName} in ${ecosystem}`);
                
                // Process each vulnerability
                for (const vuln of response.data.vulns) {
                  try {
                    const detailsResponse = await axios.get(`https://api.osv.dev/v1/vulns/${vuln.id}`);
                    if (detailsResponse.data) {
                      const processedVuln = this.processVulnerability(detailsResponse.data);
                      await this.storeVulnerability(processedVuln);
                      updatedVulnerabilities++;
                    }
                  } catch (detailsError) {
                    console.error(`Error fetching details for vulnerability ${vuln.id}:`, detailsError);
                  }
                  
                  // Rate limiting
                  await new Promise(resolve => setTimeout(resolve, 200));
                }
              }
              
              // Rate limiting between package queries
              await new Promise(resolve => setTimeout(resolve, 500));
            } catch (packageError) {
              console.error(`Error querying vulnerabilities for ${packageName} in ${ecosystem}:`, packageError);
            }
          }
        } catch (ecosystemError) {
          console.error(`Error processing ecosystem ${ecosystem}:`, ecosystemError);
        }
      }
      
      if (updatedVulnerabilities > 0) {
        console.log(`Added or updated ${updatedVulnerabilities} vulnerabilities in continuous update`);
      } else {
        console.log('No new vulnerability updates found');
      }
      
      return updatedVulnerabilities;
    } catch (error) {
      console.error('Error during continuous OSV update:', error);
      return 0;
    }
  }
  
  /**
   * Get the timestamp of the most recently modified vulnerability in our database
   */
  async getLatestVulnerabilityTimestamp() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (v:Vulnerability)
        RETURN max(v.modified) as latestModified
      `);
      
      if (result.records[0].get('latestModified')) {
        // Convert Neo4j datetime to ISO string
        const neo4jDate = result.records[0].get('latestModified');
        return neo4jDate.toString(); // This should return an ISO string
      }
      return null;
    } catch (error) {
      console.error('Error getting latest vulnerability timestamp:', error);
      return null;
    } finally {
      await session.close();
    }
  }
  
  /**
   * Get the most active packages for an ecosystem based on vulnerability frequency
   */
  async getActivePackagesForEcosystem(ecosystem) {
    // First check if we have packages for this ecosystem in our database
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (p:Package {ecosystem: $ecosystem})<-[:AFFECTS]-(v:Vulnerability)
        RETURN p.name AS packageName, count(v) AS vulnCount
        ORDER BY vulnCount DESC
        LIMIT 5
      `, { ecosystem });
      
      if (result.records.length > 0) {
        return result.records.map(record => record.get('packageName'));
      }
    } catch (error) {
      console.error(`Error getting active packages for ${ecosystem}:`, error);
    } finally {
      await session.close();
    }
    
    // Fall back to predefined popular packages
    return this.getPopularPackagesForEcosystem(ecosystem).slice(0, 3);
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

  scheduleDailyUpdatesQuietly() {
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
    
    // Schedule the update without logging
    this.updateTimer = setTimeout(() => {
      this.updateVulnerabilities();
      
      // Set up the next day's update (recursive)
      this.scheduleDailyUpdatesQuietly();
    }, timeUntilMidnight);
  }
}

// Create and export a singleton instance instead of the class
const neo4jServiceInstance = new Neo4jService();
export default neo4jServiceInstance;