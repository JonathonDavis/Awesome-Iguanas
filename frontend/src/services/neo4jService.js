import neo4j from 'neo4j-driver'

/* Only Remove When Neo4j is ready to be used */
class Neo4jService {
  constructor() {
    this.uri = import.meta.env.VITE_NEO4J_URI
    this.user = import.meta.env.VITE_NEO4J_USER
    this.password = import.meta.env.VITE_NEO4J_PASSWORD
    
    this.driver = neo4j.driver(
      this.uri,
      neo4j.auth.basic(this.user, this.password)
    )
  }

  async getStatistics() {
    const session = this.driver.session()
    try {
      // Example query - modify according to your data structure
      const result = await session.run(`
        MATCH (n)
        RETURN 
        count(n) as totalNodes,
        count(DISTINCT labels(n)) as uniqueLabels
      `)
      return result.records[0]
    } catch (error) {
      console.error('Database Error:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  // Add more specific query methods as needed
  async getNodeDistribution() {
    const session = this.driver.session()
    try {
      const result = await session.run(`
        MATCH (n)
        WITH labels(n) as labels
        UNWIND labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
      `)
      return result.records.map(record => ({
        label: record.get('label'),
        count: record.get('count').low
      }))
    } catch (error) {
      console.error('Database Error:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getOSVFiles() {
    const session = this.driver.session()
    try {
      const result = await session.run(`
        MATCH (o:OSV)
        RETURN o {
          .*,
          id: o.id,
          modified: o.modified,
          published: o.published,
          withdrawn: o.withdrawn,
          aliases: o.aliases,
          related: o.related,
          summary: o.summary,
          details: o.details,
          severity: o.severity,
          affected: o.affected,
          references: o.references,
          credits: o.credits
        } as osvData
        ORDER BY o.published DESC
      `)
      return result.records.map(record => record.get('osvData'))
    } catch (error) {
      console.error('Error fetching OSV files:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getGraphData() {
    const session = this.driver.session()
    try {
      // Get nodes and relationships for graph visualization
      const result = await session.run(`
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        WITH DISTINCT n, r, m
        WITH 
          collect(DISTINCT {
            id: id(n),
            labels: labels(n),
            properties: properties(n)
          }) as nodes,
          collect(DISTINCT CASE WHEN r IS NOT NULL THEN {
            id: id(r),
            type: type(r),
            properties: properties(r),
            source: id(startNode(r)),
            target: id(endNode(r))
          } END) as rels
        RETURN {
          nodes: nodes,
          relationships: [rel in rels WHERE rel IS NOT NULL]
        } as graphData
      `)
      
      if (!result.records || result.records.length === 0) {
        console.warn('No graph data found in database')
        return null
      }

      const graphData = result.records[0].get('graphData')
      console.log('Retrieved graph data:', {
        nodeCount: graphData.nodes.length,
        relationshipCount: graphData.relationships.length
      })
      return graphData
    } catch (error) {
      console.error('Error fetching graph data:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getOSVById(osvId) {
    const session = this.driver.session()
    try {
      const result = await session.run(`
        MATCH (o:OSV {id: $osvId})
        RETURN o {.*} as osvData
      `, { osvId })
      
      return result.records[0]?.get('osvData') || null
    } catch (error) {
      console.error('Error fetching OSV by ID:', error)
      throw error
    } finally {
      await session.close()
    }
  }

  async getASTGraph() {
    const session = this.driver.session()
    try {
      const result = await session.run(`
        MATCH (n:Vulnerability)
        OPTIONAL MATCH (n)-[r:AFFECTS]->(m:Package)
        WITH DISTINCT n, r, m
        WITH 
          collect(DISTINCT {
            id: n.id,
            labels: labels(n),
            type: 'Vulnerability',
            summary: n.summary,
            severity: n.severity,
            details: n.details,
            properties: properties(n)
          }) as vulnNodes,
          collect(DISTINCT CASE WHEN m IS NOT NULL THEN {
            id: m.name,
            labels: labels(m),
            type: 'Package',
            ecosystem: m.ecosystem,
            properties: properties(m)
          } END) as pkgNodes,
          collect(DISTINCT CASE WHEN r IS NOT NULL THEN {
            id: id(r),
            type: type(r),
            properties: properties(r),
            source: n.id,
            target: m.name
          } END) as rels
        RETURN {
          nodes: vulnNodes + [node in pkgNodes WHERE node IS NOT NULL],
          relationships: [rel in rels WHERE rel IS NOT NULL]
        } as astGraph
      `)
      
      if (!result.records || result.records.length === 0) {
        console.warn('No AST graph data found in database')
        return null
      }

      const astData = result.records[0].get('astGraph')
      console.log('Retrieved AST data:', {
        nodeCount: astData.nodes.length,
        relationshipCount: astData.relationships.length
      })
      return astData
    } catch (error) {
      console.error('Error fetching AST graph:', error)
      throw error
    } finally {
      await session.close()
    }
  }
}

export default new Neo4jService()

// Mock data for development
/*
const mockStatistics = {
  get: (key) => ({
    low: key === 'totalNodes' ? 150 : 5
  })
}

const mockDistribution = [
  { label: 'Person', count: 50 },
  { label: 'Movie', count: 40 },
  { label: 'Actor', count: 35 },
  { label: 'Director', count: 15 },
  { label: 'Genre', count: 10 }
]

// Mock service methods
const neo4jService = {
  getStatistics: async () => {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500));
    return mockStatistics;
  },

  getNodeDistribution: async () => {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500));
    return mockDistribution;
  }
};

export default neo4jService;
*/