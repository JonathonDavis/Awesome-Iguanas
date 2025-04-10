<template>
  <div class="dashboard">
    <div class="welcome-banner">
      <h1>DataVault Pro Dashboard</h1>
      <p>Enterprise Database Vulnerability Management Solution</p>
    </div>
    
    <div class="dashboard-summary">
      <div class="summary-card">
        <div class="card-icon">
          <i class="fas fa-database"></i>
        </div>
        <div class="card-content">
          <h3>Database Status</h3>
          <p class="status-indicator success">Connected</p>
          <p class="status-details">Neo4j Server Active</p>
        </div>
      </div>
      
      <div class="summary-card">
        <div class="card-icon">
          <i class="fas fa-shield-alt"></i>
        </div>
        <div class="card-content">
          <h3>Vulnerabilities</h3>
          <p class="count-indicator">{{ stats.cveCount || '...' }}</p>
          <p class="status-details">CVEs Tracked</p>
        </div>
      </div>
      
      <div class="summary-card">
        <div class="card-icon">
          <i class="fas fa-code-branch"></i>
        </div>
        <div class="card-content">
          <h3>Repositories</h3>
          <p class="count-indicator">{{ stats.repoCount || '...' }}</p>
          <p class="status-details">Tracked Repositories</p>
        </div>
      </div>
      
      <div class="summary-card">
        <div class="card-icon">
          <i class="fas fa-sync"></i>
        </div>
        <div class="card-content">
          <h3>Last Update</h3>
          <p class="stat-value date">{{ formatDate(stats.lastUpdate) || 'Loading...' }}</p>
          <p class="status-details">DB Synchronized</p>
        </div>
      </div>
    </div>
    
    <div v-if="isLoading" class="loading-container">
      <div class="loading-spinner">
        <i class="fas fa-circle-notch fa-spin"></i>
      </div>
      <p>Loading dashboard data...</p>
    </div>
    
    <div v-else class="dashboard-content">
      <!-- Repository Statistics Section -->
      <div class="dashboard-section">
        <div class="section-header">
          <h2><i class="fas fa-code-branch"></i> Repository Statistics</h2>
          <router-link to="/analytics" class="view-more-link">
            View All <i class="fas fa-arrow-right"></i>
          </router-link>
        </div>
        
        <div class="section-content">
          <div class="stat-cards">
            <div class="stat-card">
              <h3>Total Repositories</h3>
              <p class="stat-value">{{ stats.repoCount || 0 }}</p>
            </div>
            <div class="stat-card">
              <h3>Total Versions</h3>
              <p class="stat-value">{{ stats.versionCount || 0 }}</p>
            </div>
            <div class="stat-card">
              <h3>Avg Versions per Repo</h3>
              <p class="stat-value">{{ stats.repoCount ? (stats.versionCount / stats.repoCount).toFixed(1) : 0 }}</p>
            </div>
          </div>
          
          <div class="language-distribution">
            <h3>Top Languages</h3>
            <div class="language-bars">
              <div 
                v-for="(count, language) in topLanguages" 
                :key="language"
                class="language-bar-wrapper"
              >
                <div class="language-label">
                  <span>{{ language }}</span>
                  <span>{{ count }}</span>
                </div>
                <div class="progress-bar">
                  <div 
                    class="progress-fill" 
                    :style="{
                      width: `${(count / Math.max(...Object.values(topLanguages))) * 100}%`,
                      backgroundColor: getLanguageColor(language)
                    }"
                  ></div>
                </div>
              </div>
            </div>
          </div>
          
          <div class="recent-repos">
            <h3>Recent Repositories</h3>
            <div class="repo-list">
              <router-link 
                to="/analytics" 
                v-for="(repo, index) in recentRepos" 
                :key="index"
                class="repo-item"
              >
                <div class="repo-name">{{ getRepoName(repo.url) }}</div>
                <div class="repo-meta">
                  <span class="repo-language">{{ repo.primaryLanguage || 'Unknown' }}</span>
                  <span class="repo-versions">{{ repo.versions || 0 }} versions</span>
                </div>
              </router-link>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Vulnerability Statistics Section -->
      <div class="dashboard-section">
        <div class="section-header">
          <h2><i class="fas fa-shield-alt"></i> Vulnerability Statistics</h2>
          <router-link to="/visualizations" class="view-more-link">
            View All <i class="fas fa-arrow-right"></i>
          </router-link>
        </div>
        
        <div class="section-content">
          <div class="stat-cards">
            <div class="stat-card severity-critical">
              <h3>Critical</h3>
              <p class="stat-value">{{ stats.severityCounts?.Critical || 0 }}</p>
            </div>
            <div class="stat-card severity-high">
              <h3>High</h3>
              <p class="stat-value">{{ stats.severityCounts?.High || 0 }}</p>
            </div>
            <div class="stat-card severity-medium">
              <h3>Medium</h3>
              <p class="stat-value">{{ stats.severityCounts?.Medium || 0 }}</p>
            </div>
            <div class="stat-card severity-low">
              <h3>Low</h3>
              <p class="stat-value">{{ stats.severityCounts?.Low || 0 }}</p>
            </div>
          </div>
          
          <div class="severity-distribution">
            <h3>Severity Distribution</h3>
            <div class="severity-chart">
              <div class="severity-bar">
                <div 
                  v-for="(count, severity) in stats.severityCounts" 
                  :key="severity"
                  class="severity-segment"
                  :class="severity.toLowerCase()"
                  :style="{width: `${(count / stats.cveCount) * 100}%`}"
                  :title="`${severity}: ${count}`"
                ></div>
              </div>
              <div class="severity-legend">
                <div v-for="(count, severity) in stats.severityCounts" :key="severity" class="legend-item">
                  <span class="legend-color" :class="severity.toLowerCase()"></span>
                  <span class="legend-label">{{ severity }}: {{ count }}</span>
                </div>
              </div>
            </div>
          </div>
          
          <div class="recent-cves">
            <h3>Recent Vulnerabilities</h3>
            <div class="cve-list">
              <router-link 
                to="/visualizations" 
                v-for="(cve, index) in recentCVEs" 
                :key="index"
                class="cve-item"
              >
                <div class="cve-id">{{ cve.id }}</div>
                <div class="cve-severity" :class="cve.severity.toLowerCase()">{{ cve.severity }}</div>
                <div class="cve-meta">{{ cve.affectedRepos }} affected repos</div>
              </router-link>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div class="action-panel">
      <h2>Quick Actions</h2>
      <div class="action-buttons">
        <button class="action-button" @click="goToAnalytics">
          <i class="fas fa-chart-line"></i>
          <span>Repository Analytics</span>
        </button>
        <button class="action-button" @click="goToVisualizations">
          <i class="fas fa-project-diagram"></i>
          <span>Vulnerability Insights</span>
        </button>
        <button class="action-button" @click="goToDocumentation">
          <i class="fas fa-book"></i>
          <span>Documentation</span>
        </button>
        <button class="action-button refresh" @click="refreshData">
          <i class="fas fa-sync-alt"></i>
          <span>Refresh Data</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import neo4jService from '../services/neo4j/neo4jService';

const router = useRouter();
const isLoading = ref(true);

const stats = reactive({
  cveCount: 0,
  repoCount: 0,
  versionCount: 0,
  lastUpdate: new Date(),
  severityCounts: {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Unknown: 0
  }
});

const topLanguages = reactive({
  'JavaScript': 0,
  'Python': 0,
  'Java': 0,
  'TypeScript': 0,
  'C++': 0
});

const recentRepos = ref([]);
const recentCVEs = ref([]);

onMounted(async () => {
  await fetchDashboardData();
});

async function fetchDashboardData() {
  isLoading.value = true;
  
  try {
    // Fetch repository data
    const repoData = await neo4jService.getRepositoryStatistics();
    stats.repoCount = repoData.length;
    
    // Calculate version count
    let totalVersions = 0;
    const languageCounts = {};
    
    repoData.forEach(repo => {
      if (repo.versions && Array.isArray(repo.versions)) {
        totalVersions += repo.versions.length;
        
        // Count languages from first version
        if (repo.versions.length > 0 && repo.versions[0].primaryLanguage) {
          const lang = repo.versions[0].primaryLanguage;
          languageCounts[lang] = (languageCounts[lang] || 0) + 1;
        }
      }
    });
    
    stats.versionCount = totalVersions;
    
    // Set recent repositories
    recentRepos.value = repoData.slice(0, 5).map(repo => ({
      url: repo.repository,
      primaryLanguage: repo.versions && repo.versions[0] ? repo.versions[0].primaryLanguage : 'Unknown',
      versions: repo.versions ? repo.versions.length : 0
    }));
    
    // Update top languages
    const sortedLanguages = Object.entries(languageCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    
    // Clear previous data
    Object.keys(topLanguages).forEach(key => {
      delete topLanguages[key];
    });
    
    // Add new data
    sortedLanguages.forEach(([lang, count]) => {
      topLanguages[lang] = count;
    });
    
    // Fetch CVE data
    const cveData = await neo4jService.getCVERepositoryData();
    stats.cveCount = cveData.length;
    
    // Count severity levels
    const sevCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Unknown: 0
    };
    
    cveData.forEach(cve => {
      const severity = cve.severity || 'Unknown';
      sevCounts[severity] = (sevCounts[severity] || 0) + 1;
    });
    
    stats.severityCounts = sevCounts;
    
    // Set recent CVEs
    recentCVEs.value = cveData.slice(0, 5).map(cve => ({
      id: cve.cveId,
      severity: cve.severity || 'Unknown',
      affectedRepos: cve.repositories ? cve.repositories.length : 0
    }));
    
    // Use the same last update source as Stats.vue page
    try {
      // Get vulnerability statistics for lastUpdate time
      const vulnStats = await neo4jService.getVulnerabilityStatistics();
      if (vulnStats && vulnStats.lastUpdate) {
        stats.lastUpdate = vulnStats.lastUpdate;
      }
      
      // Try to get update status for possibly more recent time
      const updateStatus = await neo4jService.getUpdateStatus();
      if (updateStatus && updateStatus.last_update) {
        const updateStatusTime = new Date(updateStatus.last_update);
        const currentLastUpdate = stats.lastUpdate ? new Date(stats.lastUpdate) : null;
        
        // Use the most recent update time
        if (!currentLastUpdate || updateStatusTime > currentLastUpdate) {
          stats.lastUpdate = updateStatus.last_update;
        }
      }
      
      // Get latest vulnerability timestamp
      const latestVulnTime = await neo4jService.getLatestVulnerabilityTimestamp();
      if (latestVulnTime) {
        const latestVulnDate = new Date(latestVulnTime);
        const currentLastUpdate = stats.lastUpdate ? new Date(stats.lastUpdate) : null;
        
        // Use the most recent update time
        if (!currentLastUpdate || latestVulnDate > currentLastUpdate) {
          stats.lastUpdate = latestVulnTime;
        }
      }
    } catch (e) {
      console.warn('Could not get more precise lastUpdate time', e);
      // Keep the current value or set to now if not set
      if (!stats.lastUpdate) {
        stats.lastUpdate = new Date();
      }
    }
  } catch (error) {
    console.error('Failed to load dashboard data:', error);
  } finally {
    isLoading.value = false;
  }
}

function formatDate(dateString) {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  return date.toLocaleString();
}

function getRepoName(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.pathname.split('/').slice(-2).join('/');
  } catch {
    return url;
  }
}

function getLanguageColor(language) {
  const colors = {
    'JavaScript': '#f1e05a',
    'TypeScript': '#2b7489',
    'Python': '#3572A5',
    'Java': '#b07219',
    'C++': '#f34b7d',
    'C': '#555555',
    'Go': '#00ADD8',
    'Ruby': '#701516',
    'PHP': '#4F5D95',
    'Rust': '#dea584'
  };
  
  return colors[language] || '#cccccc';
}

function goToAnalytics() {
  router.push('/analytics');
}

function goToVisualizations() {
  router.push('/visualizations');
}

function goToDocumentation() {
  router.push('/documentation');
}

async function refreshData() {
  await fetchDashboardData();
}
</script>

<style scoped>
.dashboard {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem 1rem;
}

.welcome-banner {
  text-align: center;
  margin-bottom: 2.5rem;
}

.welcome-banner h1 {
  color: var(--primary-color);
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
}

.welcome-banner p {
  color: var(--light-text);
  font-size: 1.2rem;
}

.dashboard-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.summary-card {
  background: var(--card-background);
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
  display: flex;
  align-items: flex-start;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.summary-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
}

.card-icon {
  background: #e6f7ff;
  border-radius: 50%;
  width: 50px;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 1rem;
  font-size: 1.5rem;
  color: var(--secondary-color);
}

.card-content h3 {
  color: var(--text-color);
  margin: 0 0 0.5rem 0;
  font-size: 1.1rem;
}

.status-indicator {
  font-weight: 600;
  font-size: 1.1rem;
  margin: 0.25rem 0;
}

.status-indicator.success {
  color: var(--success-color);
}

.count-indicator {
  font-weight: 600;
  font-size: 1.8rem;
  margin: 0.25rem 0;
  color: var(--secondary-color);
}

.stat-value.date {
  font-size: 1.2rem;
  color: #3e2573;
  font-weight: 600;
}

.time-indicator {
  font-weight: 600;
  font-size: 1.1rem;
  margin: 0.25rem 0;
  color: #805ad5;
}

.status-details {
  color: var(--light-text);
  font-size: 0.9rem;
  margin: 0;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 4rem 2rem;
  text-align: center;
}

.loading-spinner {
  font-size: 2.5rem;
  color: var(--accent-color);
  margin-bottom: 1rem;
}

.dashboard-content {
  display: flex;
  flex-direction: column;
  gap: 2rem;
  margin-bottom: 2rem;
}

.dashboard-section {
  background: var(--card-background);
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.25rem 1.5rem;
  border-bottom: 1px solid var(--border-color);
}

.section-header h2 {
  color: var(--primary-color);
  margin: 0;
  font-size: 1.3rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.view-more-link {
  color: var(--accent-color);
  text-decoration: none;
  font-size: 0.95rem;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transition: color 0.2s;
}

.view-more-link:hover {
  color: var(--secondary-color);
}

.section-content {
  padding: 1.5rem;
}

.stat-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  background-color: var(--background-color);
  padding: 1rem;
  border-radius: 6px;
  text-align: center;
  border-top: 3px solid var(--accent-color);
}

.stat-card.severity-critical {
  border-top-color: #F56565;
}

.stat-card.severity-high {
  border-top-color: #ED8936;
}

.stat-card.severity-medium {
  border-top-color: #ECC94B;
}

.stat-card.severity-low {
  border-top-color: #48BB78;
}

.stat-card h3 {
  color: var(--light-text);
  margin: 0 0 0.5rem 0;
  font-size: 0.9rem;
  font-weight: 500;
}

.stat-value {
  color: var(--text-color);
  font-size: 1.8rem;
  font-weight: 600;
  margin: 0;
}

.language-distribution,
.severity-distribution {
  background-color: var(--background-color);
  padding: 1.25rem;
  border-radius: 6px;
  margin-bottom: 1.5rem;
}

.language-distribution h3,
.severity-distribution h3,
.recent-repos h3,
.recent-cves h3 {
  color: var(--text-color);
  margin: 0 0 1rem 0;
  font-size: 1.1rem;
}

.language-bars {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.language-bar-wrapper {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.language-label {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
}

.progress-bar {
  height: 10px;
  background-color: var(--border-color);
  border-radius: 5px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  transition: width 0.3s ease;
}

.severity-chart {
  margin-top: 1rem;
}

.severity-bar {
  display: flex;
  height: 16px;
  width: 100%;
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 0.75rem;
}

.severity-segment {
  height: 100%;
  transition: width 0.3s ease;
}

.severity-segment.critical {
  background-color: #F56565;
}

.severity-segment.high {
  background-color: #ED8936;
}

.severity-segment.medium {
  background-color: #ECC94B;
}

.severity-segment.low {
  background-color: #48BB78;
}

.severity-segment.unknown {
  background-color: #CBD5E0;
}

.severity-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 3px;
}

.legend-color.critical {
  background-color: #F56565;
}

.legend-color.high {
  background-color: #ED8936;
}

.legend-color.medium {
  background-color: #ECC94B;
}

.legend-color.low {
  background-color: #48BB78;
}

.legend-color.unknown {
  background-color: #CBD5E0;
}

.recent-repos,
.recent-cves {
  margin-bottom: 1rem;
}

.repo-list,
.cve-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.repo-item,
.cve-item {
  background-color: var(--background-color);
  padding: 0.75rem 1rem;
  border-radius: 6px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  text-decoration: none;
  color: var(--text-color);
  transition: background-color 0.2s;
}

.repo-item:hover,
.cve-item:hover {
  background-color: #edf2f7;
}

.repo-name {
  font-weight: 500;
  color: var(--primary-color);
}

.repo-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.85rem;
  color: var(--light-text);
}

.repo-language {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.cve-id {
  font-weight: 500;
  color: var(--primary-color);
}

.cve-severity {
  font-size: 0.8rem;
  font-weight: 600;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  text-transform: uppercase;
}

.cve-severity.critical {
  background-color: #F56565;
  color: white;
}

.cve-severity.high {
  background-color: #ED8936;
  color: white;
}

.cve-severity.medium {
  background-color: #ECC94B;
  color: #744210;
}

.cve-severity.low {
  background-color: #48BB78;
  color: white;
}

.cve-severity.unknown {
  background-color: #CBD5E0;
  color: #2D3748;
}

.cve-meta {
  font-size: 0.85rem;
  color: var(--light-text);
}

.action-panel {
  background: var(--card-background);
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}

.action-panel h2 {
  color: var(--text-color);
  margin: 0 0 1.25rem 0;
  font-size: 1.3rem;
}

.action-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}

.action-button {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  background: var(--background-color);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 0.9rem 1.5rem;
  font-size: 1rem;
  color: var(--text-color);
  cursor: pointer;
  transition: all 0.2s ease;
  flex: 1;
  min-width: 200px;
  justify-content: center;
}

.action-button:hover {
  background: #edf2f7;
  transform: translateY(-2px);
  border-color: var(--accent-color);
}

.action-button.refresh {
  background-color: var(--accent-color);
  color: white;
  border-color: var(--accent-color);
}

.action-button.refresh:hover {
  background-color: var(--secondary-color);
  border-color: var(--secondary-color);
}

@media (max-width: 768px) {
  .dashboard {
    padding: 1rem;
  }
  
  .welcome-banner h1 {
    font-size: 2rem;
  }
  
  .stat-cards {
    grid-template-columns: 1fr 1fr;
  }
  
  .repo-item, 
  .cve-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .repo-meta,
  .cve-meta {
    width: 100%;
    justify-content: space-between;
  }
  
  .action-button {
    min-width: unset;
    width: 100%;
    flex: unset;
  }
}
</style>