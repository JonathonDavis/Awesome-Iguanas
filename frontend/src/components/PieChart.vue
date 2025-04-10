<template>
  <div class="chart-container">
    <canvas ref="pieChart"></canvas>
  </div>
</template>

<script>
import { Chart } from 'chart.js/auto'
import neo4jService from '../services/neo4j/neo4jService'

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
            '#4299E1', // accent-color
            '#2C5282', // secondary-color
            '#48BB78', // success-color
            '#ED8936', // warning-color
            '#E53E3E', // error-color
            '#805AD5', // purple
            '#DD6B20', // orange
            '#3182CE', // blue
            '#38B2AC', // teal
            '#D53F8C', // pink
            '#718096'  // light-text
          ]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: true,
            text: 'Database Node Distribution',
            color: '#2D3748', // text-color
            font: {
              size: 16,
              weight: 'bold',
              family: "'Inter', sans-serif"
            },
            padding: {
              top: 10,
              bottom: 20
            }
          },
          legend: {
            position: 'right',
            labels: {
              color: '#2D3748', // text-color
              font: {
                family: "'Inter', sans-serif"
              },
              padding: 15
            }
          },
          tooltip: {
            backgroundColor: '#1A2942', // primary-color
            titleFont: {
              family: "'Inter', sans-serif",
              size: 14
            },
            bodyFont: {
              family: "'Inter', sans-serif",
              size: 13
            },
            padding: 12,
            cornerRadius: 6
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
  width: 100%;
  height: 400px;
  margin: 0 auto;
  position: relative;
}

/* Make chart responsive */
@media (max-width: 768px) {
  .chart-container {
    height: 300px;
  }
}
</style> 