<template>
  <div class="charts-container">
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
    <div class="text-section">
      <h3>Information</h3>
      <p>{{ chartDescription }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import neo4jService from '../services/neo4jService'
import PieChart from '../components/PieChart.vue';

const statistics = ref({})
const nodeDistribution = ref([])
const chartDescription = ref('Loading database statistics...')

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
    
    // Get update status
    const updateStatus = await neo4jService.getUpdateStatus()
    if (updateStatus) {
      statistics.value.lastUpdate = updateStatus.last_update;
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
</style>