<template>
  <div class="graphs-container">
    <h1 class="page-title">Vulnerability Graph Analysis</h1>
    
    <!-- Graph Visualization Section -->
    <div class="graph-section">
      <h2>AST Network Graph</h2>
      <div class="graph-legend">
        <div class="legend-item">
          <div class="legend-color" style="background-color: #ff7f0e;"></div>
          <span>Vulnerability/OSV Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Vulnerability" @change="toggleNodeType('Vulnerability')">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background-color: #1f77b4;"></div>
          <span>Package Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Package" @change="toggleNodeType('Package')">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="legend-item">
          <div class="legend-color" style="background-color: #7f7f7f;"></div>
          <span>Other Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Other" @change="toggleNodeType('Other')">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
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

    <!-- Node Details Modal -->
    <div v-if="selectedNode" class="modal" @click.self="selectedNode = null">
      <div class="modal-content">
        <h2>{{ selectedNode.type || (selectedNode.labels && selectedNode.labels[0]) }}</h2>
        <div class="details-grid">
          <!-- Basic Information -->
          <div class="detail-item">
            <strong>ID:</strong>
            <p>{{ selectedNode.id }}</p>
          </div>

          <!-- Vulnerability Information -->
          <template v-if="selectedNode.type === 'Vulnerability' || (selectedNode.labels && selectedNode.labels[0] === 'Vulnerability')">
            <div class="detail-item">
              <strong>Severity:</strong>
              <p :class="['severity', selectedNode.severity]">{{ selectedNode.severity || 'Not specified' }}</p>
            </div>
            <div class="detail-item">
              <strong>Summary:</strong>
              <p>{{ selectedNode.summary }}</p>
            </div>
            <div class="detail-item">
              <strong>Details:</strong>
              <p>{{ selectedNode.details }}</p>
            </div>
            <div class="detail-item">
              <strong>Published:</strong>
              <p>{{ selectedNode.published ? new Date(selectedNode.published).toLocaleDateString() : 'Not specified' }}</p>
            </div>
            <div class="detail-item">
              <strong>Modified:</strong>
              <p>{{ selectedNode.modified ? new Date(selectedNode.modified).toLocaleDateString() : 'Not specified' }}</p>
            </div>
            <div class="detail-item">
              <strong>CVE ID:</strong>
              <p>{{ selectedNode.cve_id || 'Not specified' }}</p>
            </div>
            <div class="detail-item">
              <strong>GHSA ID:</strong>
              <p>{{ selectedNode.ghsa_id || 'Not specified' }}</p>
            </div>
            <div v-if="selectedNode.aliases && selectedNode.aliases.length" class="detail-item">
              <strong>Aliases:</strong>
              <ul>
                <li v-for="(alias, index) in selectedNode.aliases" :key="index">{{ alias }}</li>
              </ul>
            </div>
          </template>

          <!-- Package Information -->
          <template v-if="selectedNode.type === 'Package' || (selectedNode.labels && selectedNode.labels[0] === 'Package')">
            <div class="detail-item">
              <strong>Name:</strong>
              <p>{{ selectedNode.name }}</p>
            </div>
            <div class="detail-item">
              <strong>Version:</strong>
              <p>{{ selectedNode.version }}</p>
            </div>
            <div class="detail-item">
              <strong>Ecosystem:</strong>
              <p>{{ selectedNode.ecosystem }}</p>
            </div>
            <div class="detail-item">
              <strong>PURL:</strong>
              <p>{{ selectedNode.purl }}</p>
            </div>
            <div class="detail-item">
              <strong>Package Manager:</strong>
              <p>{{ selectedNode.package_manager }}</p>
            </div>
            <div class="detail-item">
              <strong>Language:</strong>
              <p>{{ selectedNode.language }}</p>
            </div>
            <div class="detail-item">
              <strong>Description:</strong>
              <p>{{ selectedNode.description }}</p>
            </div>
            <div class="detail-item">
              <strong>License:</strong>
              <p>{{ selectedNode.license }}</p>
            </div>
            <div v-if="selectedNode.homepage" class="detail-item">
              <strong>Homepage:</strong>
              <p><a :href="selectedNode.homepage" target="_blank" rel="noopener">{{ selectedNode.homepage }}</a></p>
            </div>
            <div v-if="selectedNode.repository" class="detail-item">
              <strong>Repository:</strong>
              <p><a :href="selectedNode.repository" target="_blank" rel="noopener">{{ selectedNode.repository }}</a></p>
            </div>
          </template>

          <!-- OSV Information -->
          <template v-if="selectedNode.type === 'OSV' || (selectedNode.labels && selectedNode.labels[0] === 'OSV')">
            <div class="detail-item">
              <strong>Severity:</strong>
              <p :class="['severity', selectedNode.severity]">{{ selectedNode.severity || 'Not specified' }}</p>
            </div>
            <div class="detail-item">
              <strong>Summary:</strong>
              <p>{{ selectedNode.summary }}</p>
            </div>
            <div class="detail-item">
              <strong>Details:</strong>
              <p>{{ selectedNode.details }}</p>
            </div>
            <div class="detail-item">
              <strong>Published:</strong>
              <p>{{ selectedNode.published ? new Date(selectedNode.published).toLocaleDateString() : 'Not specified' }}</p>
            </div>
            <div v-if="selectedNode.affected && selectedNode.affected.length" class="detail-item">
              <strong>Affected:</strong>
              <ul>
                <li v-for="(item, index) in selectedNode.affected" :key="index">{{ item }}</li>
              </ul>
            </div>
            <div v-if="selectedNode.references && selectedNode.references.length" class="detail-item">
              <strong>References:</strong>
              <ul>
                <li v-for="(ref, index) in selectedNode.references" :key="index">
                  <a :href="ref" target="_blank" rel="noopener">{{ ref }}</a>
                </li>
              </ul>
            </div>
          </template>

          <!-- Additional Properties -->
          <template v-if="selectedNode.properties">
            <div v-for="(value, key) in selectedNode.properties" :key="key" class="detail-item">
              <strong>{{ key }}:</strong>
              <p>{{ typeof value === 'object' ? JSON.stringify(value) : value }}</p>
            </div>
          </template>
        </div>
        <button @click="selectedNode = null">Close</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, nextTick } from 'vue'
import * as d3 from 'd3'
import neo4jService from '../services/neo4j/neo4jService'
import { Network, DataSet } from 'vis-network/standalone'

export default {
  name: 'Graphs',
  setup() {
    const graphContainer = ref(null)
    const osvFiles = ref([])
    const selectedOSV = ref(null)
    const selectedNode = ref(null)
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
    const visibleNodeTypes = ref({
      Vulnerability: true,
      Package: true,
      OSV: true,
      Other: true
    })

    const getNodeColor = (node) => {
      // Log the node to see what properties we have
      console.log('Node for color:', node);
      
      // Try to get the type from either the type property or the first label
      const nodeType = node.type || (node.labels && node.labels[0]);
      console.log('Determined node type:', nodeType);
      
      const colors = {
        Vulnerability: '#ff7f0e',  // Orange
        Package: '#1f77b4',        // Blue
        OSV: '#ff7f0e',           // Orange
        default: '#7f7f7f'        // Gray
      }
      return colors[nodeType] || colors.default
    }

    const getNodeSize = (type) => {
      return type === 'Vulnerability' ? nodeSize.value : nodeSize.value * 0.75
    }

    const toggleNodeType = (type) => {
      visibleNodeTypes.value[type] = !visibleNodeTypes.value[type]
      updateVisibleNodes()
    }

    const updateVisibleNodes = () => {
      if (!svg.value || !graphData.value) return

      // Update node visibility
      svg.value.selectAll('g.node')
        .style('opacity', d => {
          const nodeType = d.type || (d.labels && d.labels[0])
          if (nodeType === 'Vulnerability' || nodeType === 'OSV') {
            return visibleNodeTypes.value.Vulnerability ? 1 : 0
          }
          if (nodeType === 'Package') {
            return visibleNodeTypes.value.Package ? 1 : 0
          }
          return visibleNodeTypes.value.Other ? 1 : 0
        })

      // Update link visibility based on connected nodes
      svg.value.selectAll('line')
        .style('opacity', d => {
          const sourceType = d.source.type || (d.source.labels && d.source.labels[0])
          const targetType = d.target.type || (d.target.labels && d.target.labels[0])
          
          const sourceVisible = sourceType === 'Package' ? visibleNodeTypes.value.Package :
                              sourceType === 'Vulnerability' || sourceType === 'OSV' ? visibleNodeTypes.value.Vulnerability :
                              visibleNodeTypes.value.Other
          
          const targetVisible = targetType === 'Package' ? visibleNodeTypes.value.Package :
                              targetType === 'Vulnerability' || targetType === 'OSV' ? visibleNodeTypes.value.Vulnerability :
                              visibleNodeTypes.value.Other
          
          return sourceVisible && targetVisible ? 0.6 : 0
        })
    }

    const initializeGraph = (data) => {
      if (!graphContainer.value) {
        console.warn('Graph container not found')
        return
      }

      const width = graphContainer.value.clientWidth * 1.2
      const height = 700

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

      // Create nodes with class for easier selection
      const nodeElements = g.append('g')
        .selectAll('g.node')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'node')
        .call(drag(simulation.value))
        .on('click', (event, d) => {
          showNodeDetails(d)
        })

      // Add circles for nodes
      nodeElements.append('circle')
        .attr('r', d => getNodeSize(d.type || d.labels[0]))
        .attr('fill', d => getNodeColor(d))
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
          info.push(`Type: ${d.type || (d.labels && d.labels[0])}`)
          
          // Vulnerability specific info
          if (d.type === 'Vulnerability' || (d.labels && d.labels[0] === 'Vulnerability')) {
            if (d.severity) info.push(`Severity: ${d.severity}`)
            if (d.summary) info.push(`Summary: ${d.summary}`)
            if (d.details) info.push(`Details: ${d.details}`)
            if (d.published) info.push(`Published: ${new Date(d.published).toLocaleDateString()}`)
            if (d.modified) info.push(`Modified: ${new Date(d.modified).toLocaleDateString()}`)
            if (d.withdrawn) info.push(`Withdrawn: ${new Date(d.withdrawn).toLocaleDateString()}`)
            if (d.cve_id) info.push(`CVE ID: ${d.cve_id}`)
            if (d.ghsa_id) info.push(`GHSA ID: ${d.ghsa_id}`)
            if (d.aliases) info.push(`Aliases: ${d.aliases.join(', ')}`)
          }
          
          // Package specific info
          if (d.type === 'Package' || (d.labels && d.labels[0] === 'Package')) {
            if (d.ecosystem) info.push(`Ecosystem: ${d.ecosystem}`)
            if (d.name) info.push(`Name: ${d.name}`)
            if (d.version) info.push(`Version: ${d.version}`)
            if (d.purl) info.push(`PURL: ${d.purl}`)
            if (d.package_manager) info.push(`Package Manager: ${d.package_manager}`)
            if (d.language) info.push(`Language: ${d.language}`)
            if (d.description) info.push(`Description: ${d.description}`)
            if (d.homepage) info.push(`Homepage: ${d.homepage}`)
            if (d.repository) info.push(`Repository: ${d.repository}`)
            if (d.license) info.push(`License: ${d.license}`)
          }
          
          // OSV specific info
          if (d.type === 'OSV' || (d.labels && d.labels[0] === 'OSV')) {
            if (d.severity) info.push(`Severity: ${d.severity}`)
            if (d.summary) info.push(`Summary: ${d.summary}`)
            if (d.details) info.push(`Details: ${d.details}`)
            if (d.published) info.push(`Published: ${new Date(d.published).toLocaleDateString()}`)
            if (d.modified) info.push(`Modified: ${new Date(d.modified).toLocaleDateString()}`)
            if (d.withdrawn) info.push(`Withdrawn: ${new Date(d.withdrawn).toLocaleDateString()}`)
            if (d.aliases) info.push(`Aliases: ${d.aliases.join(', ')}`)
            if (d.affected) info.push(`Affected: ${d.affected.join(', ')}`)
            if (d.references) info.push(`References: ${d.references.join(', ')}`)
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
          
          // Add any remaining direct properties that weren't caught above
          Object.entries(d).forEach(([key, value]) => {
            if (!['id', 'type', 'labels', 'properties', 'x', 'y', 'vx', 'vy', 'fx', 'fy'].includes(key) && 
                typeof value !== 'object' && 
                value !== undefined && 
                value !== null) {
              info.push(`${key}: ${value}`)
            }
          })
          
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
        .attr('r', d => getNodeSize(d.type || d.labels[0]))

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

    const showNodeDetails = (node) => {
      selectedNode.value = node
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
      selectedNode,
      showOSVDetails,
      showNodeDetails,
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
      resetView,
      visibleNodeTypes,
      toggleNodeType
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

.graph-legend {
  display: flex;
  gap: 20px;
  margin-bottom: 15px;
  padding: 10px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  border: 1px solid rgba(255, 255, 255, 0.2);
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  color: white;
  font-size: 14px;
}

.legend-color {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 2px solid white;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 20px;
  margin-left: 10px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.2);
  transition: .4s;
  border-radius: 20px;
}

.toggle-slider:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  left: 2px;
  bottom: 2px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked + .toggle-slider {
  background-color: #8cffb6;
}

input:checked + .toggle-slider:before {
  transform: translateX(20px);
}
</style> 