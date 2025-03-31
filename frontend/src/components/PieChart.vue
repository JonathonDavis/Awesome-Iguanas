<template>
  <div class="chart-container">
    <canvas ref="pieChart"></canvas>
  </div>
</template>

<script>
import { Chart } from 'chart.js/auto'
import neo4jService from '../services/neo4jService'

export default {
  name: 'PieChart',
  data() {
    return {
      chart: null
    }
  },
  async mounted() {
    const distribution = await neo4jService.getNodeDistribution()
    
    // Create the chart
    const ctx = this.$refs.pieChart
    this.chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: distribution.map(item => item.label),
        datasets: [{
          data: distribution.map(item => item.count),
          backgroundColor: [
            '#FF6384',
            '#36A2EB',
            '#FFCE56',
            '#4BC0C0',
            '#9966FF', 
            '#FF9F40',
            '#FF6384',
            '#36A2EB',
            '#FFCE56',
            '#4BC0C0',
            '#9966FF' 
          ]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          title: {
            display: true,
            text: 'Node Distribution',
            color: 'white'
          },
          legend: {
            labels: {
              color: 'white'
            }
          }
        }
      }
    })
  },
  beforeUnmount() {
    // Clean up the chart when component is destroyed
    if (this.chart) {
      this.chart.destroy()
    }
  }
}
</script>

<style scoped>
.chart-container {
  width: 400px;
  height: 400px;
  margin: auto;
}
</style> 