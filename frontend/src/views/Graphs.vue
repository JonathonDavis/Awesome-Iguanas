<template>
  <div class="graphs-container">
    <h1 class="page-title">Vulnerability Graph Analysis</h1>
    
    <!-- Graph Visualization Section -->
    <div class="graph-section">
      <h2>AST Network Graph</h2>
      <div v-if="error" class="error-message">
        Error: {{ error }}
      </div>
      <div v-else-if="!graphData && !network" class="no-data-message">
        No graph data available
      </div>
      <div class="graph-container" ref="graphContainer" v-else>
        <div class="graph-controls">
          <div class="control-group">
            <label>Node Size:</label>
            <input type="range" v-model="nodeSize" min="8" max="30" @input="updateGraph">
          </div>
          <div class="control-group">
            <label>Node Distance:</label>
            <input type="range" v-model="nodeDistance" min="25" max="100" @input="updateGraph">
          </div>
          <div class="control-group">
            <label>Zoom:</label>
            <input type="range" v-model="zoomLevel" min="0.25" max="2" step="0.1" @input="updateGraph">
          </div>
          <button @click="resetView" class="control-button">Reset View</button>
        </div>
      </div>
    </div>

    <!-- OSV Files Section -->
    <div class="osv-section">
      <h2>OSV Vulnerabilities</h2>
      <div v-if="error" class="error-message">
        Error: {{ error }}
      </div>
      <div v-else-if="!osvFiles || osvFiles.length === 0" class="no-data-message">
        No OSV vulnerabilities found
      </div>
      <div v-else class="osv-grid">
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
import { ref, onMounted, nextTick } from 'vue'
import * as d3 from 'd3'
import neo4jService from '../services/neo4jService'
import { Network, DataSet } from 'vis-network/standalone'

export default {
  name: 'Graphs',
  setup() {
    const graphContainer = ref(null)
    const osvFiles = ref([])
    const selectedOSV = ref(null)
    const graphData = ref(null)
    const network = ref(null)
    const nodes = ref(new DataSet([]))
    const edges = ref(new DataSet([]))
    const astContainer = ref(null)
    const astData = ref(null)
    const astNetwork = ref(null)
    const astNodes = ref(new DataSet([]))
    const astEdges = ref(new DataSet([]))
    const error = ref(null)
    const nodeSize = ref(12)
    const nodeDistance = ref(150)
    const zoomLevel = ref(1)
    const svg = ref(null)
    const simulation = ref(null)
    const transform = ref({ x: 0, y: 0, k: 1 })

    const getNodeColor = (label) => {
      const colors = {
        Vulnerability: '#ff7f0e',
        Package: '#1f77b4',
        default: '#7f7f7f'
      }
      return colors[label] || colors.default
    }

    const getNodeSize = (type) => {
      return type === 'Vulnerability' ? nodeSize.value : nodeSize.value * 0.75
    }

    const initializeGraph = (data) => {
      if (!graphContainer.value) {
        console.warn('Graph container not found')
        return
      }

      const width = graphContainer.value.clientWidth
      const height = 600

      // Clear any existing SVG
      d3.select(graphContainer.value).selectAll('*').remove()

      // Create SVG with zoom support
      svg.value = d3.select(graphContainer.value)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('background-color', '#1a1a1a')
        .call(d3.zoom()
          .scaleExtent([0.5, 2])
          .on('zoom', (event) => {
            transform.value = event.transform
            g.attr('transform', event.transform)
          }))

      // Create a group for the graph elements
      const g = svg.value.append('g')

      // Create unique IDs for nodes and links
      const nodes = data.nodes.map(node => ({
        ...node,
        id: `node-${node.id}` // Ensure unique IDs
      }))

      const links = data.relationships.map(link => ({
        ...link,
        source: `node-${link.source}`,
        target: `node-${link.target}`
      }))

      // Initialize force simulation
      simulation.value = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links)
          .id(d => d.id)
          .distance(nodeDistance.value))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(width / 2, height / 2))

      // Create links with updated color
      const linkElements = g.append('g')
        .selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('stroke', '#4a4a4a')
        .attr('stroke-opacity', 0.6)
        .attr('stroke-width', 2)

      // Create nodes
      const nodeElements = g.append('g')
        .selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .call(drag(simulation.value))

      // Add circles for nodes
      nodeElements.append('circle')
        .attr('r', d => getNodeSize(d.type))
        .attr('fill', d => getNodeColor(d.type))
        .attr('stroke', '#fff')
        .attr('stroke-width', 2)

      // Add labels for nodes
      nodeElements.append('text')
        .text(d => {
          if (d.type === 'Vulnerability') {
            return d.id.substring(0, 12) + '...'
          }
          return d.id
        })
        .attr('x', 12)
        .attr('y', 4)
        .attr('font-size', '12px')
        .attr('fill', '#fff')

      // Add tooltips
      nodeElements.append('title')
        .text(d => {
          const info = []
          
          // Basic info
          info.push(`ID: ${d.id}`)
          info.push(`Type: ${d.type}`)
          
          // Vulnerability specific info
          if (d.type === 'Vulnerability') {
            if (d.severity) info.push(`Severity: ${d.severity}`)
            if (d.summary) info.push(`Summary: ${d.summary}`)
            if (d.details) info.push(`Details: ${d.details}`)
            if (d.published) info.push(`Published: ${new Date(d.published).toLocaleDateString()}`)
            if (d.modified) info.push(`Modified: ${new Date(d.modified).toLocaleDateString()}`)
            if (d.withdrawn) info.push(`Withdrawn: ${new Date(d.withdrawn).toLocaleDateString()}`)
          }
          
          // Package specific info
          if (d.type === 'Package') {
            if (d.ecosystem) info.push(`Ecosystem: ${d.ecosystem}`)
            if (d.name) info.push(`Name: ${d.name}`)
            if (d.version) info.push(`Version: ${d.version}`)
            if (d.purl) info.push(`PURL: ${d.purl}`)
          }
          
          // Additional properties
          if (d.properties) {
            Object.entries(d.properties).forEach(([key, value]) => {
              if (typeof value === 'object') {
                info.push(`${key}: ${JSON.stringify(value)}`)
              } else {
                info.push(`${key}: ${value}`)
              }
            })
          }
          
          return info.join('\n')
        })

      // Update positions on each tick
      simulation.value.on('tick', () => {
        linkElements
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)

        nodeElements
          .attr('transform', d => `translate(${d.x},${d.y})`)
      })
    }

    const updateGraph = () => {
      if (!simulation.value || !svg.value) return

      // Update node sizes
      svg.value.selectAll('circle')
        .attr('r', d => getNodeSize(d.type))

      // Update link distances
      simulation.value.force('link').distance(nodeDistance.value)

      // Update zoom level
      svg.value.transition()
        .duration(300)
        .call(d3.zoom().transform, d3.zoomIdentity
          .translate(transform.value.x, transform.value.y)
          .scale(zoomLevel.value))
    }

    const resetView = () => {
      if (!svg.value) return
      
      // Reset zoom and pan
      zoomLevel.value = 1
      transform.value = { x: 0, y: 0, k: 1 }
      
      svg.value.transition()
        .duration(300)
        .call(d3.zoom().transform, d3.zoomIdentity)
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

    onMounted(async () => {
      try {
        error.value = null
        console.log('Starting data fetch...')
        
        // Fetch all data in parallel
        const [graphResult, osvData, astResult] = await Promise.all([
          neo4jService.getGraphData(),
          neo4jService.getOSVFiles(),
          neo4jService.getASTGraph()
        ])

        console.log('Data fetched:', {
          hasGraphData: !!graphResult,
          hasOSVData: !!osvData,
          hasASTData: !!astResult
        })

        // Handle graph data
        if (graphResult && graphResult.nodes && graphResult.nodes.length > 0) {
          console.log('Initializing main graph with:', {
            nodes: graphResult.nodes.length,
            relationships: graphResult.relationships.length
          })
          graphData.value = graphResult
          await nextTick()
          initializeGraph(graphResult)
        } else {
          console.warn('No main graph data available')
        }

        // Handle OSV data
        if (osvData && Array.isArray(osvData)) {
          osvFiles.value = osvData
          console.log('OSV files loaded:', osvFiles.value.length)
        } else {
          console.warn('No OSV data available')
          osvFiles.value = []
        }

        // Handle AST data
        if (astResult && astResult.nodes && astResult.nodes.length > 0) {
          console.log('Initializing AST graph with:', {
            nodes: astResult.nodes.length,
            relationships: astResult.relationships.length
          })
          
          astData.value = astResult
          
          // Clear existing AST graph data and destroy network if it exists
          if (astNetwork.value) {
            astNetwork.value.destroy()
            astNetwork.value = null
          }
          astNodes.value.clear()
          astEdges.value.clear()

          // Transform nodes for visualization with unique IDs
          const visNodes = astResult.nodes.map(node => ({
            id: `ast-${node.id}`, // Add prefix to ensure unique IDs
            label: `${node.type}\n${node.value || ''}`,
            title: JSON.stringify(node.properties, null, 2),
            group: node.type
          }))

          // Transform relationships for visualization with updated IDs
          const visEdges = astResult.relationships.map(rel => ({
            id: `ast-${rel.id}`,
            from: `ast-${rel.source}`,
            to: `ast-${rel.target}`,
            arrows: 'to',
            label: rel.type
          }))

          // Add the new nodes and edges
          astNodes.value.add(visNodes)
          astEdges.value.add(visEdges)

          // Create new network
          if (astContainer.value) {
            const container = astContainer.value
            const data = {
              nodes: astNodes.value,
              edges: astEdges.value
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
                  direction: 'UD',
                  sortMethod: 'directed',
                  levelSeparation: 100
                }
              },
              physics: false
            }
            astNetwork.value = new Network(container, data, options)
          }
        } else {
          console.warn('No AST graph data available')
        }

      } catch (error) {
        console.error('Error loading data:', error)
        error.value = `Failed to load data: ${error.message}`
      }
    })

    return {
      graphContainer,
      astContainer,
      osvFiles,
      selectedOSV,
      showOSVDetails,
      error,
      graphData,
      astData,
      network,
      astNetwork,
      nodes,
      edges,
      astNodes,
      astEdges,
      nodeSize,
      nodeDistance,
      zoomLevel,
      resetView
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
  position: absolute;
  top: 10px;
  right: 10px;
  background: rgba(255, 255, 255, 0.95);
  padding: 15px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
  z-index: 1000;
  min-width: 200px;
}

.control-group {
  margin-bottom: 10px;
}

.control-group label {
  display: block;
  margin-bottom: 5px;
  color: #333;
  font-size: 12px;
  font-weight: bold;
}

.control-group input[type="range"] {
  width: 150px;
  margin: 0;
}

.control-button {
  background: #259a67;
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  margin-top: 10px;
  width: 100%;
  font-weight: bold;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.control-button:hover {
  background: #1d7a52;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

.error-message {
  background-color: #dc3545;
  color: white;
  padding: 1rem;
  border-radius: 4px;
  margin: 1rem 0;
  text-align: center;
}

.no-data-message {
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  padding: 1rem;
  border-radius: 4px;
  margin: 1rem 0;
  text-align: center;
  font-style: italic;
}
</style> 