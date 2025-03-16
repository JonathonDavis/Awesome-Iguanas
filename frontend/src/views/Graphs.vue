<template>
  <div class="graphs-container">
    <h1 class="page-title">Vulnerability Graph Analysis</h1>
    
    <!-- Statistics Section -->
    <div class="statistics-section">
      <h2>Overview Statistics</h2>
      <div class="stats-grid" v-if="statistics">
        <div class="stat-box">
          <h3>Total Nodes</h3>
          <p>{{ statistics.get('totalNodes').low }}</p>
        </div>
        <div class="stat-box">
          <h3>Unique Labels</h3>
          <p>{{ statistics.get('uniqueLabels').low }}</p>
        </div>
      </div>
    </div>

    <!-- Graph Visualization Section -->
    <div class="graph-section">
      <h2>Network Graph</h2>
      <div class="graph-container" ref="graphContainer">
        <div class="graph-controls">
          <button @click="loadASTGraph">Show AST Graph</button>
        </div>
      </div>
    </div>

    <!-- OSV Files Section -->
    <div class="osv-section">
      <h2>OSV Vulnerabilities</h2>
      <div class="osv-grid">
        <div v-for="osv in osvFiles" :key="osv.id" class="osv-card">
          <h3>{{ osv.id }}</h3>
          <p class="summary">{{ osv.summary }}</p>
          <div class="metadata">
            <span class="severity" :class="osv.severity">
              Severity: {{ osv.severity || 'Not specified' }}
            </span>
            <span class="published">
              Published: {{ new Date(osv.published).toLocaleDateString() }}
            </span>
          </div>
          <button @click="showOSVDetails(osv)">View Details</button>
        </div>
      </div>
    </div>

    <!-- OSV Details Modal -->
    <div v-if="selectedOSV" class="modal" @click.self="selectedOSV = null">
      <div class="modal-content">
        <h2>{{ selectedOSV.id }}</h2>
        <div class="details-grid">
          <div class="detail-item">
            <strong>Summary:</strong>
            <p>{{ selectedOSV.summary }}</p>
          </div>
          <div class="detail-item">
            <strong>Details:</strong>
            <p>{{ selectedOSV.details }}</p>
          </div>
          <div class="detail-item">
            <strong>Affected:</strong>
            <ul>
              <li v-for="(item, index) in selectedOSV.affected" :key="index">
                {{ item }}
              </li>
            </ul>
          </div>
          <div class="detail-item">
            <strong>References:</strong>
            <ul>
              <li v-for="(ref, index) in selectedOSV.references" :key="index">
                <a :href="ref" target="_blank" rel="noopener">{{ ref }}</a>
              </li>
            </ul>
          </div>
        </div>
        <button @click="selectedOSV = null">Close</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import * as d3 from 'd3'
import neo4jService from '../services/neo4jService'
import { Network, DataSet } from 'vis-network/standalone'

export default {
  name: 'Graphs',
  setup() {
    const graphContainer = ref(null)
    const statistics = ref(null)
    const osvFiles = ref([])
    const selectedOSV = ref(null)
    const graphData = ref(null)
    const network = ref(null)
    const nodes = ref(new DataSet([]))
    const edges = ref(new DataSet([]))

    const initializeGraph = (data) => {
      const width = graphContainer.value.clientWidth
      const height = 600

      // Clear any existing SVG
      d3.select(graphContainer.value).selectAll('*').remove()

      const svg = d3.select(graphContainer.value)
        .append('svg')
        .attr('width', width)
        .attr('height', height)

      const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.relationships)
          .id(d => d.id)
          .distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))

      const links = svg.append('g')
        .selectAll('line')
        .data(data.relationships)
        .enter()
        .append('line')
        .attr('stroke', '#999')
        .attr('stroke-opacity', 0.6)

      const nodes = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter()
        .append('circle')
        .attr('r', 5)
        .attr('fill', d => getNodeColor(d.labels[0]))
        .call(drag(simulation))

      nodes.append('title')
        .text(d => d.labels.join(', '))

      simulation.on('tick', () => {
        links
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)

        nodes
          .attr('cx', d => d.x)
          .attr('cy', d => d.y)
      })
    }

    const getNodeColor = (label) => {
      const colors = {
        OSV: '#ff7f0e',
        Package: '#1f77b4',
        Vulnerability: '#2ca02c',
        default: '#7f7f7f'
      }
      return colors[label] || colors.default
    }

    const drag = (simulation) => {
      const dragstarted = (event) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        event.subject.fx = event.subject.x
        event.subject.fy = event.subject.y
      }

      const dragged = (event) => {
        event.subject.fx = event.x
        event.subject.fy = event.y
      }

      const dragended = (event) => {
        if (!event.active) simulation.alphaTarget(0)
        event.subject.fx = null
        event.subject.fy = null
      }

      return d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended)
    }

    const showOSVDetails = (osv) => {
      selectedOSV.value = osv
    }

    const loadASTGraph = async () => {
      try {
        const astData = await neo4jService.getASTGraph()
        
        // Clear existing graph
        nodes.value.clear()
        edges.value.clear()

        // Transform nodes for visualization
        const visNodes = astData.nodes.map(node => ({
          id: node.id,
          label: `${node.type}\n${node.value || ''}`,
          title: JSON.stringify(node.properties, null, 2),
          group: node.type // For different colors based on AST node type
        }))

        // Transform relationships for visualization
        const visEdges = astData.relationships.map(rel => ({
          id: rel.id,
          from: rel.source,
          to: rel.target,
          arrows: 'to', // Add arrows to show direction
          label: rel.type
        }))

        // Add the new nodes and edges
        nodes.value.add(visNodes)
        edges.value.add(visEdges)

        // If network doesn't exist, create it
        if (!network.value) {
          const container = graphContainer.value
          const data = {
            nodes: nodes.value,
            edges: edges.value
          }
          const options = {
            nodes: {
              shape: 'box',
              font: {
                size: 12,
                multi: true
              }
            },
            edges: {
              font: {
                size: 12
              }
            },
            layout: {
              hierarchical: {
                direction: 'UD', // Up to Down layout
                sortMethod: 'directed',
                levelSeparation: 100
              }
            },
            physics: false // Disable physics for AST visualization
          }
          network.value = new Network(container, data, options)
        }
      } catch (error) {
        console.error('Error loading AST graph:', error)
        // Handle error (show notification, etc.)
      }
    }

    onMounted(async () => {
      try {
        // Fetch all data in parallel
        const [statsData, graphResult, osvData] = await Promise.all([
          neo4jService.getStatistics(),
          neo4jService.getGraphData(),
          neo4jService.getOSVFiles()
        ])

        statistics.value = statsData
        graphData.value = graphResult
        osvFiles.value = osvData

        if (graphData.value) {
          initializeGraph(graphData.value)
        }
      } catch (error) {
        console.error('Error loading data:', error)
      }
    })

    return {
      graphContainer,
      statistics,
      osvFiles,
      selectedOSV,
      showOSVDetails,
      loadASTGraph
    }
  }
}
</script>

<style scoped>
.graphs-container {
  margin: 2rem;
  padding: 1rem;
  border: 1px solid #ffffff;
  border-radius: 8px;
}

.page-title {
  color: white;
  margin-bottom: 2rem;
}

.statistics-section,
.graph-section,
.osv-section {
  margin-bottom: 2rem;
  background-color: #259a67;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

h2, h3 {
  color: white;
  margin-bottom: 1rem;
}

p, span {
  color: white;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.stat-box {
  background-color: rgba(255, 255, 255, 0.1);
  padding: 1rem;
  border-radius: 4px;
  text-align: center;
}

.graph-container {
  width: 100%;
  height: 600px;
  background: rgba(255, 255, 255, 0.9);
  border-radius: 8px;
  overflow: hidden;
  margin-top: 1rem;
}

.osv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
  margin-top: 1rem;
}

.osv-card {
  background: rgba(255, 255, 255, 0.1);
  padding: 20px;
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.2);
}

.osv-card h3 {
  margin: 0 0 10px 0;
  color: white;
}

.summary {
  font-size: 0.9em;
  color: rgba(255, 255, 255, 0.9);
  margin-bottom: 15px;
}

.metadata {
  display: flex;
  justify-content: space-between;
  margin-bottom: 15px;
  font-size: 0.8em;
}

.severity {
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.1);
}

.severity.CRITICAL { background: #dc3545; color: white; }
.severity.HIGH { background: #fd7e14; color: white; }
.severity.MEDIUM { background: #ffc107; color: black; }
.severity.LOW { background: #28a745; color: white; }

.modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background: #259a67;
  padding: 30px;
  border-radius: 8px;
  max-width: 800px;
  max-height: 80vh;
  overflow-y: auto;
  position: relative;
  color: white;
}

.details-grid {
  display: grid;
  gap: 20px;
  margin: 20px 0;
}

.detail-item {
  border-bottom: 1px solid rgba(255, 255, 255, 0.2);
  padding-bottom: 15px;
}

.detail-item strong {
  color: rgba(255, 255, 255, 0.9);
}

.detail-item p {
  margin-top: 0.5rem;
}

.detail-item a {
  color: #8cffb6;
  text-decoration: none;
}

.detail-item a:hover {
  text-decoration: underline;
}

button {
  background: rgba(255, 255, 255, 0.1);
  color: white;
  border: 1px solid rgba(255, 255, 255, 0.2);
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.3s;
}

button:hover {
  background: rgba(255, 255, 255, 0.2);
}

.graph-controls {
  margin-bottom: 1rem;
}
</style> 