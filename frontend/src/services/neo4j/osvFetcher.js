import { apiClient } from './axiosConfig';

const OSV_API_PROXY_BASE = '/api/proxy/osv';

class OSVFetcher {
  constructor(driver, database) {
    this.driver = driver;
    this.database = database;
  }

  createSession() {
    if (this.database) {
      return this.driver.session({ database: this.database });
    }
    return this.driver.session();
  }

  getNextPageToken(data) {
    return data?.next_page_token || data?.nextPageToken || data?.next_pageToken || null;
  }

  async queryOSVForPackage(pkg, ecosystem) {
    const vulns = [];
    let pageToken = null;

    do {
      const body = {
        package: { name: pkg, ecosystem }
      };

      if (pageToken) {
        // OSV docs use page_token; OpenAPI uses pageToken.
        body.page_token = pageToken;
        body.pageToken = pageToken;
      }

      const response = await apiClient.post(`${OSV_API_PROXY_BASE}/v1/query`, body);
      const data = response?.data || {};

      if (Array.isArray(data.vulns)) {
        vulns.push(...data.vulns);
      }

      pageToken = this.getNextPageToken(data);
    } while (pageToken);

    return vulns;
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
    const session = this.createSession();
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
    const session = this.createSession();
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
    const session = this.createSession();
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
    const ecosystems = ['npm', 'PyPI', 'Maven'];
    for (const ecosystem of ecosystems) {
      try {
        const packages = await this.getPopularPackagesForEcosystem(ecosystem);
        for (const pkg of packages) {
          const vulns = await this.queryOSVForPackage(pkg, ecosystem);
          for (const vuln of vulns) {
            const processedVuln = this.processVulnerability(vuln);
            await this.storeVulnerability(processedVuln);
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
    const ecosystems = ['npm', 'PyPI', 'Maven'];
    const lastTimestamp = await this.getLatestVulnerabilityTimestamp();
    const lastModifiedDate = lastTimestamp ? new Date(lastTimestamp) : null;
    
    for (const ecosystem of ecosystems) {
      try {
        const packages = await this.getPopularPackagesForEcosystem(ecosystem);
        for (const pkg of packages) {
          const vulns = await this.queryOSVForPackage(pkg, ecosystem);
          for (const vuln of vulns) {
            if (lastModifiedDate && vuln?.modified) {
              const vulnModified = new Date(vuln.modified);
              if (!Number.isNaN(vulnModified.valueOf()) && vulnModified <= lastModifiedDate) {
                continue;
              }
            }

            const processedVuln = this.processVulnerability(vuln);
            await this.storeVulnerability(processedVuln);
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

export function createOSVFetcherWithDatabase(driver, database) {
  return new OSVFetcher(driver, database);
}