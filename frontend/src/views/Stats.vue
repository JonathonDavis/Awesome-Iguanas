<template>
  <div class="charts-container">
    <!-- Database Statistics -->
    <div class="chart-section">
      <h2>Database Statistics</h2>
      <div class="stats-grid">
        <div class="stat-box">
          <h3>Total Nodes</h3>
          <p>{{ statistics.totalNodes || 'Loading...' }}</p>
        </div>
        <div class="stat-box">
          <h3>Unique Labels</h3>
          <p>{{ statistics.uniqueLabels || 'Loading...' }}</p>
        </div>
        <div class="stat-box">
          <h3>Total Vulnerabilities</h3>
          <p>{{ statistics.totalVulnerabilities || 'Loading...' }}</p>
        </div>
        <div class="stat-box">
          <h3>Affected Packages</h3>
          <p>{{ statistics.totalPackages || 'Loading...' }}</p>
        </div>
        <div class="stat-box">
          <h3>Unique Ecosystems</h3>
          <p>{{ statistics.uniqueEcosystems || 'Loading...' }}</p>
        </div>
        <div class="stat-box">
          <h3>Last Update</h3>
          <p>{{ formatDate(statistics.lastUpdate) || 'Loading...' }}</p>
        </div>
      </div>
      <div class="distribution-grid">
        <div class="distribution-section">
          <h3>Nodes Distribution</h3>
          <div v-for="(item, index) in nodeDistribution" :key="index" class="distribution-item">
            <span>{{ item.label }}:</span>
            <span>{{ item.count }}</span>
          </div>
        </div>
        <div class="distribution-chart">
          <h3>Pie Chart</h3>
          <PieChart />
        </div>
      </div>
    </div>

    <!-- Database Information -->
    <!-- <div class="text-section">
      <h3>Information</h3>
      <p>{{ chartDescription }}</p>
    </div> -->


    
    <!--Breakdown of CVE, Repository sections -->
    <div class="breakdown-section">
      <!-- CVE Breakdown -->
      <div class="cve-section">
        <div class="section-header">
          <h2>CVE Breakdown</h2>
          <button 
            class="toggle-button"
            @click="showCVEStats = !showCVEStats"
            :class="{ 'active': showCVEStats }"
          >
            {{ showCVEStats ? 'Hide' : 'Show' }}
          </button>
        </div>
        <CVEStats v-if="showCVEStats" />
      </div>

      <!-- Repository Breakdowns -->
      <div class="repository-section">
        <div class="section-header">
          <h2>Repository Breakdowns</h2>
          <button 
            class="toggle-button"
            @click="showRepositoryStats = !showRepositoryStats"
            :class="{ 'active': showRepositoryStats }"
          >
            {{ showRepositoryStats ? 'Hide' : 'Show' }}
          </button>
        </div>
        <RepositoryStats v-if="showRepositoryStats" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import neo4jService from '../services/neo4jService'
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
.charts-container {
  margin: 1rem;
  padding: 1rem;
  border: 1px solid #ffffff;
  border-radius: 8px;
  min-width: 60vh;

}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}

.stat-box {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  text-align: center;
  transition: transform 0.2s;
}

.stat-box:hover {
  transform: translateY(-2px);
}

.distribution-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1rem;
  margin-bottom: 1rem;
}

.distribution-section {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
  max-height: 300px;
  overflow-y: auto;
}

.distribution-chart {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
  min-height: 300px;
}

.distribution-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.text-section {
  padding: 1rem;
  background-color: #259a67;
  border-radius: 4px;
  margin-top: 1rem;
}

h2, h3 {
  color: white;
  margin-bottom: 1rem;
}

p, span {
  color: white;
}

@media (min-width: 768px) {
  .charts-container {
    margin: 2rem;
    padding: 2rem;
  }

  .distribution-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .distribution-section {
    max-height: 500px;
  }

  .distribution-chart {
    min-height: 400px;
  }

  .stats-grid {
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  }
}

@media (max-width: 767px) {
  .charts-container {
    margin: 0.5rem;
    padding: 0.5rem;
  }

  .distribution-section {
    max-height: 300px;
  }

  .distribution-chart {
    min-height: 300px;
  }

  h2 {
    font-size: 1.5rem;
  }

  h3 {
    font-size: 1.2rem;
  }
}

.repository-section {
  margin-top: 2rem;
  padding: 1rem;
  background-color: #259a67;
  border-radius: 4px;
}

.repository-section h2 {
  color: white;
  margin-bottom: 1rem;
}

.cve-section {
  margin-top: 2rem;
  padding: 1rem;
  background-color: #259a67;
  border-radius: 4px;
}

.cve-section h2 {
  color: white;
  margin-bottom: 1rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.toggle-button {
  padding: 0.5rem 1rem;
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.2s ease;
}

.toggle-button:hover {
  background-color: rgba(255, 255, 255, 0.2);
}

.toggle-button.active {
  background-color: rgba(97, 218, 251, 0.2);
  border-color: #61dafb;
}

@media (max-width: 768px) {
  .section-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .toggle-button {
    width: 100%;
  }
}
</style>