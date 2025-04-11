<template>
  <div class="analytics-container">
    <!-- Database Statistics -->
    <div class="section-header">
      <h1>Analytics Dashboard</h1>
      <p class="subtitle">Comprehensive database vulnerability insights</p>
    </div>
    
    <div class="card">
      <h2 class="heading-secondary">Database Overview</h2>
      <div class="stats-grid">
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-database"></i></div>
          <div class="stat-content">
            <h3>Total Nodes</h3>
            <p class="stat-value">{{ statistics.totalNodes || 'Loading...' }}</p>
          </div>
        </div>
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-tags"></i></div>
          <div class="stat-content">
            <h3>Unique Labels</h3>
            <p class="stat-value">{{ statistics.uniqueLabels || 'Loading...' }}</p>
          </div>
        </div>
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-bug"></i></div>
          <div class="stat-content">
            <h3>Total Vulnerabilities</h3>
            <p class="stat-value">{{ statistics.totalVulnerabilities || 'Loading...' }}</p>
          </div>
        </div>
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-box"></i></div>
          <div class="stat-content">
            <h3>Affected Packages</h3>
            <p class="stat-value">{{ statistics.totalPackages || 'Loading...' }}</p>
          </div>
        </div>
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-globe"></i></div>
          <div class="stat-content">
            <h3>Unique Ecosystems</h3>
            <p class="stat-value">{{ statistics.uniqueEcosystems || 'Loading...' }}</p>
          </div>
        </div>
        <div class="stat-box">
          <div class="stat-icon"><i class="fas fa-clock"></i></div>
          <div class="stat-content">
            <h3>Last Update</h3>
            <p class="stat-value date">{{ formatDate(statistics.lastUpdate) || 'Loading...' }}</p>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 class="heading-secondary">Distribution Analysis</h2>
      <div class="distribution-grid">
        <div class="distribution-section">
          <h3>Node Type Distribution</h3>
          <div class="distribution-list">
            <div v-for="(item, index) in nodeDistribution" :key="index" class="distribution-item">
              <span class="distribution-label">{{ item.label }}</span>
              <div class="distribution-bar-container">
                <div class="distribution-bar" :style="{ width: getPercentage(item.count) + '%' }"></div>
              </div>
              <span class="distribution-count">{{ item.count }}</span>
            </div>
          </div>
        </div>
        <div class="distribution-chart">
          <h3>Visual Distribution</h3>
          <PieChart />
        </div>
      </div>
    </div>
    
    <!-- Breakdowns Section -->
    <div class="breakdown-section">
    
      <!-- Repository Breakdowns -->
      <div class="card" id="Repository-Analysis">
        <div class="card-header">
          <h2 class="heading-secondary">Repository Analysis</h2>
          <button 
            class="toggle-button"
            @click="showRepositoryStats = !showRepositoryStats"
          >
            <i :class="showRepositoryStats ? 'fas fa-chevron-up' : 'fas fa-chevron-down'"></i>
          </button>
        </div>
        <RepositoryStats v-if="showRepositoryStats" />
      </div>

      <!-- CVE Breakdown -->
      <div class="card vulnerability-section" id="Vulnerability-Analysis">
        <div class="card-header">
          <h2 class="heading-secondary">Vulnerability Analysis</h2>
          <button 
            class="toggle-button"
            @click="showCVEStats = !showCVEStats"
          >
            <i :class="showCVEStats ? 'fas fa-chevron-up' : 'fas fa-chevron-down'"></i>
          </button>
        </div>
        <CVEStats v-if="showCVEStats" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import neo4jService from '../services/neo4j/neo4jService'
import PieChart from '../components/PieChart.vue';
import RepositoryStats from '../components/RepositoryStats.vue'
import CVEStats from '../components/CVEStats.vue'

const statistics = ref({})
const nodeDistribution = ref([])
const chartDescription = ref('Loading database statistics...')
const showCVEStats = ref(true)
const showRepositoryStats = ref(true)

const formatDate = (dateString) => {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  return date.toLocaleString();
}

const getPercentage = (count) => {
  const total = nodeDistribution.value.reduce((sum, item) => sum + item.count, 0);
  return total > 0 ? (count / total) * 100 : 0;
}

const fetchData = async () => {
  try {
    // Get basic statistics
    const statsResult = await neo4jService.getStatistics()
    statistics.value = {
      totalNodes: statsResult.get('totalNodes').low,
      uniqueLabels: statsResult.get('uniqueLabels').low
    }
    
    // Get vulnerability statistics
    const vulnStats = await neo4jService.getVulnerabilityStatistics()
    statistics.value = {
      ...statistics.value,
      totalVulnerabilities: vulnStats.totalVulnerabilities,
      totalPackages: vulnStats.totalPackages,
      uniqueEcosystems: vulnStats.uniqueEcosystems,
      lastUpdate: vulnStats.lastUpdate
    }
    
    // Get node distribution
    const distributionResult = await neo4jService.getNodeDistribution()
    nodeDistribution.value = distributionResult
    
    // Get update status and compare with current lastUpdate
    const updateStatus = await neo4jService.getUpdateStatus()
    if (updateStatus) {
      const updateStatusTime = new Date(updateStatus.last_update);
      const currentLastUpdate = statistics.value.lastUpdate ? new Date(statistics.value.lastUpdate) : null;
      
      // Use the most recent update time
      if (!currentLastUpdate || updateStatusTime > currentLastUpdate) {
        statistics.value.lastUpdate = updateStatus.last_update;
      }
    }
    
    // Get latest vulnerability timestamp
    const latestVulnTime = await neo4jService.getLatestVulnerabilityTimestamp();
    if (latestVulnTime) {
      const latestVulnDate = new Date(latestVulnTime);
      const currentLastUpdate = statistics.value.lastUpdate ? new Date(statistics.value.lastUpdate) : null;
      
      // Use the most recent update time
      if (!currentLastUpdate || latestVulnDate > currentLastUpdate) {
        statistics.value.lastUpdate = latestVulnTime;
      }
    }
    
    chartDescription.value = `Database contains ${statistics.value.totalNodes} nodes across ${statistics.value.uniqueLabels} different types. 
    There are ${statistics.value.totalVulnerabilities} vulnerabilities affecting ${statistics.value.totalPackages} packages across ${statistics.value.uniqueEcosystems} ecosystems.`
  } catch (error) {
    console.error('Error fetching data:', error)
    chartDescription.value = 'Error loading database statistics.'
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.analytics-container {
  max-width: 1200px;
  margin: 0 auto;
}

.section-header {
  text-align: center;
  margin-bottom: 2rem;
}

.section-header h1 {
  color: var(--primary-color);
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.subtitle {
  color: var(--light-text);
  font-size: 1.1rem;
}

.card {
  background-color: var(--card-background);
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 2rem;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.heading-secondary {
  color: var(--secondary-color);
  font-size: 1.4rem;
  margin-bottom: 1.5rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--accent-color);
  display: inline-block;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 1rem;
}

.stat-box {
  background-color: white;
  padding: 1.5rem;
  border-radius: 8px;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
  display: flex;
  align-items: center;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.stat-box:hover {
  transform: translateY(-5px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
}

.stat-icon {
  background-color: rgba(66, 153, 225, 0.1);
  color: var(--accent-color);
  width: 50px;
  height: 50px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  margin-right: 1rem;
}

.stat-content {
  flex: 1;
}

.stat-content h3 {
  color: var(--text-color);
  font-size: 1rem;
  margin: 0 0 0.5rem 0;
}

.stat-value {
  color: var(--secondary-color);
  font-size: 1.6rem;
  font-weight: 600;
  margin: 0;
}

.stat-value.date {
  font-size: 1.1rem;
}

.distribution-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 2rem;
}

.distribution-section h3, .distribution-chart h3 {
  color: var(--text-color);
  font-size: 1.2rem;
  margin-bottom: 1.5rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

.distribution-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.distribution-item {
  display: grid;
  grid-template-columns: 150px 1fr 60px;
  align-items: center;
  gap: 1rem;
}

.distribution-label {
  font-weight: 500;
  color: var(--text-color);
}

.distribution-bar-container {
  height: 10px;
  background-color: var(--border-color);
  border-radius: 5px;
  overflow: hidden;
}

.distribution-bar {
  height: 100%;
  background-color: var(--accent-color);
  border-radius: 5px;
}

.distribution-count {
  font-weight: 600;
  color: var(--secondary-color);
  text-align: right;
}

.toggle-button {
  background-color: transparent;
  color: var(--accent-color);
  border: none;
  cursor: pointer;
  font-size: 1.2rem;
  padding: 0.5rem;
  transition: all 0.2s ease;
}

.toggle-button:hover {
  color: var(--secondary-color);
}

#Repository-Analysis, #Vulnerability-Analysis {
  scroll-margin-top: 100px; /* Provides space at the top when scrolled to */
}

.vulnerability-section {
  border-left: 4px solid var(--secondary-color);
}

@media (max-width: 992px) {
  .distribution-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .stat-box {
    padding: 1rem;
  }
  
  .stat-icon {
    width: 40px;
    height: 40px;
    font-size: 1rem;
  }
  
  .stat-value {
    font-size: 1.4rem;
  }
  
  .distribution-item {
    grid-template-columns: 100px 1fr 50px;
  }
}
</style>