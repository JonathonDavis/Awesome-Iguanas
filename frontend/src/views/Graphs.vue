<template>
  <div class="visualizations-container">
    <div class="section-header">
      <h1>Data Visualizations</h1>
      <p class="subtitle">Interactive graph-based vulnerability analysis</p>
    </div>
    
    <!-- Graph Visualization Section -->
    <div class="card">
      <h2 class="heading-secondary">Network Graph Visualization</h2>
      <div class="graph-legend">
        <div class="legend-item">
          <div class="legend-color vulnerability"></div>
          <span>Vulnerability Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Vulnerability" @change="toggleNodeType('Vulnerability')">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="legend-item">
          <div class="legend-color package"></div>
          <span>Package Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Package" @change="toggleNodeType('Package')">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="legend-item">
          <div class="legend-color other"></div>
          <span>Other Nodes</span>
          <label class="toggle-switch">
            <input type="checkbox" :checked="visibleNodeTypes.Other" @change="toggleNodeType('Other')">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
      
      <div v-if="error" class="error-message">
        <i class="fas fa-exclamation-circle"></i> Error: {{ error }}
      </div>
      <div v-else-if="!graphData && !network" class="empty-state">
        <i class="fas fa-project-diagram"></i>
        <p>No graph data available</p>
      </div>
      <div class="graph-container" ref="graphContainer" v-else>
        <div class="graph-controls">
          <div class="control-group">
            <label><i class="fas fa-expand"></i> Node Size:</label>
            <input type="range" v-model="nodeSize" min="8" max="30" @input="updateGraph">
          </div>
          <div class="control-group">
            <label><i class="fas fa-arrows-alt-h"></i> Node Distance:</label>
            <input type="range" v-model="nodeDistance" min="25" max="100" @input="updateGraph">
          </div>
          <div class="control-group">
            <label><i class="fas fa-search"></i> Zoom:</label>
            <input type="range" v-model="zoomLevel" min="0.25" max="2" step="0.1" @input="updateGraph">
          </div>
          <button @click="resetView" class="control-button">
            <i class="fas fa-redo-alt"></i> Reset View
          </button>
        </div>
      </div>
    </div>

    <!-- OSV Files Section -->
    <div class="card">
      <h2 class="heading-secondary">Vulnerability Catalog</h2>
      <div v-if="error" class="error-message">
        <i class="fas fa-exclamation-circle"></i> Error: {{ error }}
      </div>
      <div v-else-if="!osvFiles || osvFiles.length === 0" class="empty-state">
        <i class="fas fa-shield-alt"></i>
        <p>No vulnerability records available</p>
      </div>
      <div v-else class="osv-grid">
        <div v-for="osv in osvFiles" :key="osv.id" class="osv-card">
          <div class="osv-card-header">
            <h3>{{ osv.id }}</h3>
            <span class="severity-badge" :class="getSeverityClass(osv.severity)">
              {{ osv.severity || 'UNKNOWN' }}
            </span>
          </div>
          <p class="summary">{{ osv.summary }}</p>
          <div class="metadata">
            <span class="metadata-item">
              <i class="fas fa-calendar-alt"></i> {{ formatDate(osv.published) }}
            </span>
            <span class="metadata-item">
              <i class="fas fa-box"></i> {{ getAffectedPackages(osv) }}
            </span>
          </div>
          <button class="view-details-btn" @click="showOSVDetails(osv)">
            <i class="fas fa-info-circle"></i> View Details
          </button>
        </div>
      </div>
    </div>

    <!-- OSV Details Modal -->
    <div v-if="selectedOSV" class="modal-overlay" @click.self="selectedOSV = null">
      <div class="modal-content">
        <div class="modal-header">
          <h2>{{ selectedOSV.id }}</h2>
          <button class="close-button" @click="selectedOSV = null">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body">
          <div class="detail-section">
            <h3><i class="fas fa-info-circle"></i> Overview</h3>
            <div class="detail-item">
              <strong>Summary:</strong>
              <p>{{ selectedOSV.summary }}</p>
            </div>
            <div class="detail-item">
              <strong>Details:</strong>
              <p>{{ selectedOSV.details }}</p>
            </div>
            <div class="detail-item">
              <strong>Severity:</strong>
              <span class="severity-badge large" :class="getSeverityClass(selectedOSV.severity)">
                {{ selectedOSV.severity || 'UNKNOWN' }}
              </span>
            </div>
          </div>
          
          <div class="detail-section">
            <h3><i class="fas fa-boxes"></i> Affected Packages</h3>
            <ul class="affected-list">
              <li v-for="(item, index) in selectedOSV.affected" :key="index"> 
                {{ formatAffectedItem(item) }}
              </li>
            </ul>
          </div>
          
          <div class="detail-section">
            <h3><i class="fas fa-link"></i> References</h3>
            <ul class="reference-list">
              <li v-for="(ref, index) in selectedOSV.references" :key="index">
                <a :href="ref" target="_blank" rel="noopener">
                  <i class="fas fa-external-link-alt"></i> {{ formatReferenceLink(ref) }}
                </a>
              </li>
            </ul>
          </div>
        </div>
        <div class="modal-footer">
          <button class="close-btn" @click="selectedOSV = null">Close</button>
        </div>
      </div>
    </div>

    <!-- Node Details Modal -->
    <div v-if="selectedNode" class="modal-overlay" @click.self="selectedNode = null">
      <div class="modal-content">
        <div class="modal-header">
          <h2>{{ getNodeTitle(selectedNode) }}</h2>
          <button class="close-button" @click="selectedNode = null">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body">
          <!-- Node type specific content here, keeping the existing templates -->
          <!-- ... existing code ... -->
        </div>
        <div class="modal-footer">
          <button class="close-btn" @click="selectedNode = null">Close</button>
        </div>
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
      const g = svg.value.append('g')      // Create unique IDs for nodes and links
      const nodes = data.nodes.map(node => ({
        ...node,
        id: `node-${node.id}` // Ensure unique IDs
      }))
      
      // Create a Set of node IDs for quick lookup
      const nodeIdSet = new Set(data.nodes.map(node => node.id.toString()))
      
      // Filter relationships to only include those with valid source and target nodes
      const validRelationships = data.relationships.filter(link => {
        const sourceExists = nodeIdSet.has(link.source.toString())
        const targetExists = nodeIdSet.has(link.target.toString())
        
        if (!sourceExists || !targetExists) {
          console.debug(`Skipping invalid relationship: ${link.id} (${link.source} -> ${link.target})`)
          return false
        }
        return true
      })
      
      // Map the valid relationships to links with the correct node-prefixed IDs
      const links = validRelationships.map(link => ({
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

    function getSeverityClass(severity) {
      if (!severity) return 'unknown';
      return severity.toLowerCase();
    }

    function formatDate(dateString) {
      if (!dateString) return 'Unknown date';
      return new Date(dateString).toLocaleDateString();
    }

    function getAffectedPackages(osv) {
      if (!osv.affected || !osv.affected.length) return 'No affected packages';
      return `${osv.affected.length} package${osv.affected.length > 1 ? 's' : ''}`;
    }

    function formatAffectedItem(item) {
      if (typeof item === 'string') return item;
      if (typeof item === 'object') {
        if (item.package && item.package.name) {
          let result = `${item.package.name}`;
          if (item.package.ecosystem) result += ` (${item.package.ecosystem})`;
          if (item.versions && item.versions.length) result += `: ${item.versions.join(', ')}`;
          return result;
        }
      }
      return JSON.stringify(item);
    }

    function formatReferenceLink(url) {
      try {
        const urlObj = new URL(url);
        return urlObj.hostname + urlObj.pathname;
      } catch {
        return url;
      }
    }

    function getNodeTitle(node) {
      if (node.type) return node.type;
      if (node.labels && node.labels.length) return node.labels[0];
      return 'Node Details';
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
        }      } catch (error) {
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
      toggleNodeType,
      // Add missing functions that are used in the template
      getSeverityClass,
      formatDate,
      getAffectedPackages,
      formatAffectedItem,
      formatReferenceLink,
      getNodeTitle,
      getNodeColor,
      updateGraph
    }
  }
}
</script>

<style scoped>
.visualizations-container {
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

.heading-secondary {
  color: var(--secondary-color);
  font-size: 1.4rem;
  margin-bottom: 1.5rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--accent-color);
  display: inline-block;
}

.graph-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
  padding: 1rem;
  background-color: rgba(0, 0, 0, 0.02);
  border-radius: 6px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.legend-color {
  width: 16px;
  height: 16px;
  border-radius: 50%;
}

.legend-color.vulnerability {
  background-color: #ff7f0e;
}

.legend-color.package {
  background-color: #1f77b4;
}

.legend-color.other {
  background-color: #7f7f7f;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 22px;
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
  background-color: #ccc;
  transition: .4s;
  border-radius: 22px;
}

.toggle-slider:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked + .toggle-slider {
  background-color: var(--accent-color);
}

input:focus + .toggle-slider {
  box-shadow: 0 0 1px var(--accent-color);
}

input:checked + .toggle-slider:before {
  transform: translateX(18px);
}

.error-message {
  padding: 1rem;
  background-color: rgba(229, 62, 62, 0.1);
  border-left: 4px solid var(--error-color);
  border-radius: 4px;
  color: var(--error-color);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  background-color: rgba(0, 0, 0, 0.02);
  border-radius: 6px;
  color: var(--light-text);
}

.empty-state i {
  font-size: 3rem;
  margin-bottom: 1rem;
  opacity: 0.5;
}

.graph-container {
  height: 600px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  position: relative;
  overflow: hidden;
}

.graph-controls {
  position: absolute;
  top: 1rem;
  right: 1rem;
  background-color: rgba(255, 255, 255, 0.9);
  padding: 1rem;
  border-radius: 6px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  z-index: 100;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.control-group {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.control-group label {
  font-size: 0.9rem;
  color: var(--text-color);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.control-group input {
  width: 200px;
}

.control-button {
  margin-top: 0.5rem;
  padding: 0.5rem 1rem;
  background-color: var(--accent-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  transition: background-color 0.2s ease;
}

.control-button:hover {
  background-color: var(--secondary-color);
}

.osv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}

.osv-card {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  border: 1px solid var(--border-color);
}

.osv-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
}

.osv-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.osv-card h3 {
  margin: 0;
  color: var(--primary-color);
  font-size: 1.1rem;
}

.severity-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.critical {
  background-color: #F56565;
  color: white;
}

.severity-badge.high {
  background-color: #ED8936;
  color: white;
}

.severity-badge.medium {
  background-color: #ECC94B;
  color: #744210;
}

.severity-badge.low {
  background-color: #48BB78;
  color: white;
}

.severity-badge.unknown {
  background-color: #CBD5E0;
  color: #2D3748;
}

.severity-badge.large {
  font-size: 1rem;
  padding: 0.5rem 0.75rem;
}

.summary {
  flex: 1;
  margin: 0 0 1rem;
  color: var(--text-color);
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.metadata {
  display: flex;
  margin-bottom: 1rem;
  flex-wrap: wrap;
  gap: 1rem;
}

.metadata-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--light-text);
  font-size: 0.9rem;
}

.view-details-btn {
  padding: 0.5rem 1rem;
  background-color: var(--accent-color);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  align-self: flex-start;
  transition: background-color 0.2s ease;
}

.view-details-btn:hover {
  background-color: var(--secondary-color);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  width: 90%;
  max-width: 800px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
}

.modal-header {
  padding: 1.5rem;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-header h2 {
  margin: 0;
  color: var(--primary-color);
  font-size: 1.4rem;
}

.close-button {
  background: transparent;
  border: none;
  color: var(--light-text);
  cursor: pointer;
  font-size: 1.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.2s ease;
}

.close-button:hover {
  color: var(--text-color);
}

.modal-body {
  padding: 1.5rem;
  overflow-y: auto;
  max-height: calc(90vh - 150px);
}

.modal-footer {
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--border-color);
  display: flex;
  justify-content: flex-end;
}

.close-btn {
  padding: 0.5rem 1.5rem;
  background-color: var(--border-color);
  color: var(--text-color);
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.close-btn:hover {
  background-color: #CBD5E0;
}

.detail-section {
  margin-bottom: 2rem;
}

.detail-section h3 {
  color: var(--secondary-color);
  font-size: 1.2rem;
  margin: 0 0 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.detail-item {
  margin-bottom: 1rem;
}

.detail-item strong {
  display: block;
  margin-bottom: 0.25rem;
  color: var(--light-text);
}

.affected-list, .reference-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.affected-list li, .reference-list li {
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--border-color);
}

.affected-list li:last-child, .reference-list li:last-child {
  border-bottom: none;
}

.reference-list a {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

@media (max-width: 768px) {
  .graph-legend {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.75rem;
  }
  
  .graph-controls {
    left: 1rem;
    right: 1rem;
    width: auto;
  }
  
  .control-group input {
    width: 100%;
  }
  
  .osv-grid {
    grid-template-columns: 1fr;
  }
}
</style> 