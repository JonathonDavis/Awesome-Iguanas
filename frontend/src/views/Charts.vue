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

const fetchData = async () => {
  try {
    const statsResult = await neo4jService.getStatistics()
    statistics.value = {
      totalNodes: statsResult.get('totalNodes').low,
      uniqueLabels: statsResult.get('uniqueLabels').low
    }
    
    const distributionResult = await neo4jService.getNodeDistribution()
    nodeDistribution.value = distributionResult
    
    // Call our new method to print detailed information about all labels
    console.log('Fetching detailed information about all labels...')
    await neo4jService.getAllLabelsSampleData()
    
    chartDescription.value = `Database contains ${statistics.value.totalNodes} nodes across ${statistics.value.uniqueLabels} different types.`
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
  margin: 2rem;
  padding: 1rem;
  border: 1px solid #ffffff;
  border-radius: 8px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  /* margin-bottom: 1rem; */
}

.stat-box {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  text-align: center;
}

.distribution-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}

.distribution-section {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
  max-height: 500px;
  overflow-y: auto;
}

.distribution-chart {
  background-color: #259a67;
  padding: 1rem;
  border-radius: 4px;
  margin-top: 1rem;
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
</style>