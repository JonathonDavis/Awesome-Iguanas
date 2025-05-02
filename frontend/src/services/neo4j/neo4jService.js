import neo4j from 'neo4j-driver'
import { setupAxiosClient } from './axiosConfig';
import { initializeUpdateTracking } from './updateSystem';
import { processVulnerability, storeVulnerability } from './vulnerabilityProcessor';
import { createOSVFetcher } from './osvFetcher';
import { getStatistics, getNodeDistribution, getVulnerabilityStatistics } from './statisticsService';
import { getRepositoryStatistics, getCVERepositoryData } from './repositoryService';
import { startUpdateSystem } from './updateSystem';
import nvdService from './nvdService';

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
    
    // Setup axios client with retry capability
    setupAxiosClient();
    
    // Initialize OSV fetcher
    this.osvFetcher = createOSVFetcher(this.driver);
    
    // Used to track the timers for updates
    this.updateTimer = null;
    this.continuousUpdateTimer = null;
    this.continuousUpdateInterval = 3600000; // 1 hour in milliseconds
    
    // Initialize update tracking
    this.lastUpdateTime = null;
    this.updateStatus = {
      lastSuccessfulUpdate: null,
      lastFailedUpdate: null,
      totalVulnerabilities: 0,
      lastUpdateCount: 0,
      updateErrors: [],
      totalNodes: 0
    };
    
    // Initialize the database with update tracking
    this.initializeUpdateTracking();
    
    // Start the update system
    this.startUpdateSystem();
  }
  // Re-export methods from other modules
  initializeUpdateTracking = initializeUpdateTracking;
  processVulnerability = processVulnerability;
  storeVulnerability = storeVulnerability;
  fetchOSVData = () => this.osvFetcher.fetchOSVData();
  fetchLatestOSVUpdates = () => this.osvFetcher.fetchLatestOSVUpdates();
  getStatistics = getStatistics;
  getNodeDistribution = getNodeDistribution;
  getVulnerabilityStatistics = getVulnerabilityStatistics;
  getRepositoryStatistics = getRepositoryStatistics;
  getCVERepositoryData = getCVERepositoryData;
  
  // Graph data retrieval methods
  async getGraphData() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN collect(distinct n) as nodes, collect(distinct r) as relationships
      `);
      
      if (result.records.length > 0) {
        const nodes = result.records[0].get('nodes').map(node => {
          return {
            id: node.identity.toString(),
            labels: node.labels,
            properties: node.properties,
            ...node.properties
          };
        });
        
        const relationships = result.records[0].get('relationships').map(rel => {
          return {
            id: rel.identity.toString(),
            source: rel.start.toString(),
            target: rel.end.toString(),
            type: rel.type,
            properties: rel.properties
          };
        });
        
        return { nodes, relationships };
      }
      return { nodes: [], relationships: [] };
    } catch (error) {
      console.error('Error fetching graph data:', error);
      return { nodes: [], relationships: [] };
    } finally {
      await session.close();
    }
  }

  async getOSVFiles() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (v:Vulnerability)
        RETURN v
        ORDER BY v.published DESC
        LIMIT 100
      `);
      
      return result.records.map(record => {
        const vulnerability = record.get('v');
        return {
          id: vulnerability.identity.toString(),
          properties: vulnerability.properties,
          ...vulnerability.properties
        };
      });
    } catch (error) {
      console.error('Error fetching OSV files:', error);
      return [];
    } finally {
      await session.close();
    }
  }

  async getASTGraph() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (n:AST)
        OPTIONAL MATCH (n)-[r:CHILD|SIBLING]->(m:AST)
        RETURN collect(distinct n) as nodes, collect(distinct r) as relationships
      `);
      
      if (result.records.length > 0) {
        const nodes = result.records[0].get('nodes').map(node => {
          return {
            id: node.identity.toString(),
            labels: node.labels,
            properties: node.properties,
            ...node.properties
          };
        });
        
        const relationships = result.records[0].get('relationships').map(rel => {
          return {
            id: rel.identity.toString(),
            source: rel.start.toString(),
            target: rel.end.toString(),
            type: rel.type,
            properties: rel.properties
          };
        });
        
        return { nodes, relationships };
      }
      return { nodes: [], relationships: [] };
    } catch (error) {
      console.error('Error fetching AST graph:', error);
      return { nodes: [], relationships: [] };
    } finally {
      await session.close();
    }
  }

  // Get update status
  getUpdateStatus() {
    return {
      ...this.updateStatus,
      lastUpdateTime: this.lastUpdateTime,
      isUpdating: this.updateTimer !== null || this.continuousUpdateTimer !== null
    };
  }

  // Get total node count from the database
  async getTotalNodeCount() {
    const session = this.driver.session();
    try {
      const result = await session.run(`
        MATCH (n)
        RETURN count(n) as totalNodes
      `);
      
      if (result.records.length > 0) {
        return result.records[0].get('totalNodes').toNumber();
      }
      return 0;
    } catch (error) {
      console.error('Error getting total node count:', error);
      return 0;
    } finally {
      await session.close();
    }
  }

  // Update the update tracking with total node count
  async updateTrackingWithNodeCount(nodeCount) {
    const session = this.driver.session();
    try {
      // Update the UpdateTracking node with the new count
      await session.run(`
        MATCH (t:UpdateTracking)
        SET t.last_update = datetime(),
            t.total_nodes = $nodeCount
        RETURN t
      `, { nodeCount });
      
      // Update local update status
      this.updateStatus.totalNodes = nodeCount;
      this.updateStatus.lastUpdate = new Date().toISOString();
      
      return true;
    } catch (error) {
      console.error('Error updating tracking with node count:', error);
      return false;
    } finally {
      await session.close();
    }
  }

  // Get the timestamp of the most recently modified vulnerability
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
    } catch (error) {
      console.error('Error getting latest vulnerability timestamp:', error);
      return null;
    } finally {
      await session.close();
    }
  }

  // Schedule updates to run quietly in the background
  async scheduleDailyUpdatesQuietly() {
    try {
      // Clear any existing timer
      if (this.updateTimer) {
        clearTimeout(this.updateTimer);
      }

      // Calculate time until next update (next day at 2 AM)
      const now = new Date();
      const nextUpdate = new Date(now);
      nextUpdate.setDate(nextUpdate.getDate() + 1);
      nextUpdate.setHours(2, 0, 0, 0);
      
      const timeUntilNextUpdate = nextUpdate.getTime() - now.getTime();
      
      // Schedule the next update
      this.updateTimer = setTimeout(async () => {
        try {
          await this.fetchLatestOSVUpdates();
          this.updateStatus.lastSuccessfulUpdate = new Date().toISOString();
        } catch (error) {
          console.error('Error in scheduled update:', error);
          this.updateStatus.lastFailedUpdate = new Date().toISOString();
          this.updateStatus.updateErrors.push(error.message);
        } finally {
          // Schedule the next update
          this.scheduleDailyUpdatesQuietly();
        }
      }, timeUntilNextUpdate);
      
      console.log(`Next update scheduled for ${nextUpdate.toLocaleString()}`);
    } catch (error) {
      console.error('Error scheduling updates:', error);
      this.updateStatus.updateErrors.push(error.message);
    }
  }

  // Start the update system
  async startUpdateSystem() {
    try {
      // Schedule daily updates
      await this.scheduleDailyUpdatesQuietly();
      
      // Start continuous updates
      if (!this.continuousUpdateTimer) {
        this.continuousUpdateTimer = setInterval(async () => {
          try {
            await this.fetchLatestOSVUpdates();
            this.updateStatus.lastSuccessfulUpdate = new Date().toISOString();
          } catch (error) {
            console.error('Error in continuous update:', error);
            this.updateStatus.lastFailedUpdate = new Date().toISOString();
            this.updateStatus.updateErrors.push(error.message);
          }
        }, this.continuousUpdateInterval);
        
        console.log('Continuous update system started');
      }
    } catch (error) {
      console.error('Error starting update system:', error);
      this.updateStatus.updateErrors.push(error.message);
    }
  }

  // Add method to update CVE severities from NVD API
  async updateCVESeverities(cveIds, progressCallback) {
    console.log(`Updating severities for ${cveIds.length} CVEs from NVD API`);
    
    if (!cveIds || cveIds.length === 0) {
      console.warn('No CVE IDs provided for severity update');
      return { success: false, updatedCount: 0, message: 'No CVE IDs provided' };
    }
    
    try {
      // Fetch updated severity data from NVD API
      const severityData = await nvdService.batchFetchCVESeverities(cveIds, (processedCveId) => {
        // Report individual CVE completion if callback provided
        if (progressCallback && typeof progressCallback === 'function') {
          progressCallback(processedCveId);
        }
      });
      
      if (!severityData || Object.keys(severityData).length === 0) {
        console.warn('No severity data returned from NVD API');
        return { 
          success: false, 
          updatedCount: 0, 
          message: 'No severity data returned from NVD API' 
        };
      }
      
      // Update each CVE in Neo4j database
      const session = this.driver.session();
      let updatedCount = 0;
      let failedCves = [];
      
      try {
        for (const [cveId, severity] of Object.entries(severityData)) {
          try {
            // Skip CVEs with no valid severity level
            if (!severity || !severity.level) {
              failedCves.push(cveId);
              continue;
            }
            
            const result = await session.run(`
              MATCH (c:CVE {id: $cveId})-[:IDENTIFIED_AS]->(v:Vulnerability)
              SET v.severity = $severityLevel,
                  v.severityScore = $severityScore,
                  v.modified = datetime()
              RETURN c, v
            `, {
              cveId,
              severityLevel: severity.level,
              severityScore: severity.score
            });
            
            if (result.records.length > 0) {
              updatedCount++;
            } else {
              console.warn(`No matching CVE found in database for ${cveId}`);
              failedCves.push(cveId);
            }
          } catch (error) {
            console.error(`Error updating CVE ${cveId} in Neo4j:`, error.message);
            failedCves.push(cveId);
          } finally {
            // Report progress on each individual CVE update
            if (progressCallback && typeof progressCallback === 'function') {
              progressCallback(cveId);
            }
          }
        }
        
        const message = failedCves.length > 0 
          ? `Updated ${updatedCount} CVEs, failed to update ${failedCves.length} CVEs` 
          : `Successfully updated ${updatedCount} CVEs with new severity data`;
        
        console.log(message);
        return { 
          success: updatedCount > 0, 
          updatedCount, 
          failedCount: failedCves.length,
          failedCves,
          message
        };
      } finally {
        await session.close();
      }
    } catch (error) {
      console.error('Error updating CVE severities:', error.message);
      return {
        success: false,
        updatedCount: 0,
        message: `Failed to update CVE severities: ${error.message}`,
        error: error.message
      };
    }
  }
}

// Create and export a singleton instance
const neo4jServiceInstance = new Neo4jService();
export default neo4jServiceInstance; 