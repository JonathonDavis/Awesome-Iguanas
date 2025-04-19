export async function initializeUpdateTracking() {
  const session = this.driver.session();
  try {
    // Create update tracking node if it doesn't exist
    await session.run(`
      MERGE (t:UpdateTracking)
      ON CREATE SET 
        t.last_update = datetime(),
        t.total_vulnerabilities = 0,
        t.total_nodes = 0,
        t.update_history = [],
        t.last_successful_update = datetime(),
        t.last_failed_update = null,
        t.update_errors = []
    `);
    
    // Get current statistics
    const result = await session.run(`
      MATCH (v:Vulnerability)
      RETURN count(v) as totalVulns
    `);
    
    this.updateStatus.totalVulnerabilities = result.records[0].get('totalVulns').low;
    
    // Get total node count
    const nodeResult = await session.run(`
      MATCH (n)
      RETURN count(n) as totalNodes
    `);
    
    this.updateStatus.totalNodes = nodeResult.records[0].get('totalNodes').low;
    
    // Get last update time and node count
    const trackingResult = await session.run(`
      MATCH (t:UpdateTracking)
      RETURN t.last_update as lastUpdate, t.total_nodes as totalNodes
    `);
    
    if (trackingResult.records.length > 0) {
      this.lastUpdateTime = trackingResult.records[0].get('lastUpdate');
      
      // If totalNodes is not in the database yet, update it
      const storedTotalNodes = trackingResult.records[0].get('totalNodes');
      if (storedTotalNodes === null) {
        await session.run(`
          MATCH (t:UpdateTracking)
          SET t.total_nodes = $totalNodes
        `, { totalNodes: this.updateStatus.totalNodes });
      }
    }
  } catch (error) {
    console.error('Error initializing update tracking:', error);
  } finally {
    await session.close();
  }
}

export async function startUpdateSystem() {
  // Schedule daily updates
  this.scheduleDailyUpdatesQuietly();
  
  // Start continuous OSV updates
  this.startContinuousOSVUpdates();
  
  // Do an initial update if needed
  if (!this.lastUpdateTime || 
      new Date() - new Date(this.lastUpdateTime) > 24 * 60 * 60 * 1000) {
    console.log('Performing initial update...');
    await this.updateVulnerabilities();
  }
}

export function scheduleDailyUpdatesQuietly() {
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

export function startContinuousOSVUpdates() {
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

export function stopContinuousOSVUpdates() {
  if (this.continuousUpdateTimer) {
    clearInterval(this.continuousUpdateTimer);
    this.continuousUpdateTimer = null;
    console.log('Continuous OSV updates stopped');
  }
} 