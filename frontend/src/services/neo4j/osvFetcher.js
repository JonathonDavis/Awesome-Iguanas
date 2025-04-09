import { apiClient } from './axiosConfig';

class OSVFetcher {
  constructor(driver) {
    this.driver = driver;
  }

  processVulnerability(vulnData) {
    // Process and normalize the vulnerability data
    return {
      id: vulnData.id,
      modified: vulnData.modified,
      published: vulnData.published,
      summary: vulnData.summary,
      details: vulnData.details,
      severity: vulnData.severity,
      ecosystem: vulnData.affected?.[0]?.package?.ecosystem,
      packageName: vulnData.affected?.[0]?.package?.name,
      ranges: vulnData.affected?.[0]?.ranges || [],
      references: vulnData.references || []
    };
  }

  async storeVulnerability(vulnData) {
    const session = this.driver.session();
    try {
      await session.run(`
        MERGE (v:Vulnerability {id: $id})
        SET v.modified = datetime($modified),
            v.published = datetime($published),
            v.summary = $summary,
            v.details = $details,
            v.severity = $severity
        WITH v
        MATCH (p:Package {name: $packageName, ecosystem: $ecosystem})
        MERGE (v)-[:AFFECTS]->(p)
        RETURN v
      `, {
        id: vulnData.id,
        modified: vulnData.modified,
        published: vulnData.published,
        summary: vulnData.summary,
        details: vulnData.details,
        severity: vulnData.severity,
        packageName: vulnData.packageName,
        ecosystem: vulnData.ecosystem
      });
    } finally {
      await session.close();
    }
  }

  async getPopularPackagesForEcosystem(ecosystem) {
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
      return [];
    } catch (error) {
      console.error(`Error getting active packages for ${ecosystem}:`, error);
      return [];
    } finally {
      await session.close();
    }
  }

  async getLatestVulnerabilityTimestamp() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (v:Vulnerability)
        RETURN max(v.modified) as latestModified
      `);
      
      if (result.records[0].get('latestModified')) {
        return result.records[0].get('latestModified').toString();
      }
      return null;
    } finally {
      await session.close();
    }
  }

  async fetchOSVData() {
    const ecosystems = ['npm', 'pypi', 'maven'];
    for (const ecosystem of ecosystems) {
      try {
        const packages = await this.getPopularPackagesForEcosystem(ecosystem);
        for (const pkg of packages) {
          const response = await apiClient.get(`/v1/query`, {
            data: {
              package: { name: pkg, ecosystem: ecosystem }
            }
          });

          if (response.data.vulns) {
            for (const vuln of response.data.vulns) {
              const processedVuln = this.processVulnerability(vuln);
              await this.storeVulnerability(processedVuln);
            }
          }

          // Rate limiting to avoid timeouts
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        console.error(`Error processing ecosystem ${ecosystem}:`, error);
      }
    }
  }

  async fetchLatestOSVUpdates() {
    const ecosystems = ['npm', 'pypi', 'maven'];
    const lastTimestamp = await this.getLatestVulnerabilityTimestamp();
    
    for (const ecosystem of ecosystems) {
      try {
        const packages = await this.getPopularPackagesForEcosystem(ecosystem);
        for (const pkg of packages) {
          const response = await apiClient.get(`/v1/query`, {
            data: {
              package: { name: pkg, ecosystem: ecosystem },
              modified_since: lastTimestamp
            }
          });

          if (response.data.vulns) {
            for (const vuln of response.data.vulns) {
              const processedVuln = this.processVulnerability(vuln);
              await this.storeVulnerability(processedVuln);
            }
          }

          // Rate limiting to avoid timeouts
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        console.error(`Error processing ecosystem ${ecosystem}:`, error);
      }
    }
  }
}

// Export an instance creator function
export function createOSVFetcher(driver) {
  return new OSVFetcher(driver);
} 