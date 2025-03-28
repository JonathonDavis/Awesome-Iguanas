import neo4j from 'neo4j-driver'

class Neo4jService {
  constructor() {
    this.uri = import.meta.env.VITE_NEO4J_URI
    this.user = import.meta.env.VITE_NEO4J_USER
    this.password = import.meta.env.VITE_NEO4J_PASSWORD
    
    if (!this.uri || !this.user || !this.password) {
      console.error('Neo4j environment variables missing: VITE_NEO4J_URI, VITE_NEO4J_USER, VITE_NEO4J_PASSWORD must be set in .env file')
      throw new Error('Neo4j configuration missing')
    }
    
    this.driver = neo4j.driver(
      this.uri,
      neo4j.auth.basic(this.user, this.password)
    )
    console.log('Neo4j connection established')
  }

  async getStatistics() {
    const session = this.driver.session()
    try {
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

  async getNodeDistribution() {
    const session = this.driver.session()
    try {
      // First, let's get all unique labels in the database and log them
      const labelsResult = await session.run(`
        MATCH (n)
        UNWIND labels(n) as label
        RETURN DISTINCT label
        ORDER BY label
      `)
      
      console.log('All unique node labels in database:')
      labelsResult.records.forEach(record => {
        console.log(`- "${record.get('label')}"`)
      })

      // Then get the distribution as before
      const result = await session.run(`
        MATCH (n)
        WITH labels(n) as labels
        UNWIND labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
      `)
      
      console.log('\nNode label distribution:')
      result.records.forEach(record => {
        console.log(`Label: "${record.get('label')}", Count: ${record.get('count').low}`)
      })
      
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

  async getAllLabelsSampleData() {
    const session = this.driver.session()
    try {
      // First, get all unique labels
      const labelsResult = await session.run(`
        MATCH (n)
        UNWIND labels(n) as label
        RETURN DISTINCT label
        ORDER BY label
      `)
      
      const allLabels = labelsResult.records.map(record => record.get('label'))
      console.log(`Found ${allLabels.length} different node labels:`, allLabels)
      
      // For each label, get sample nodes
      for (const label of allLabels) {
        console.log(`\n========== LABEL: ${label} ==========`)
        
        // Get sample nodes with this label (limit to 3)
        const sampleNodesResult = await session.run(`
          MATCH (n:${label})
          RETURN n
          LIMIT 3
        `)
        
        if (sampleNodesResult.records.length === 0) {
          console.log(`  No nodes found with label ${label}`)
          continue
        }
        
        // Get properties from the first node to understand structure
        const firstNode = sampleNodesResult.records[0].get('n')
        const properties = Object.keys(firstNode.properties)
        console.log(`  Properties for ${label}:`, properties)
        
        // Print sample nodes
        sampleNodesResult.records.forEach((record, index) => {
          const node = record.get('n')
          console.log(`  Sample ${index + 1}:`, node.properties)
        })
        
        // Get count of nodes with this label
        const countResult = await session.run(`
          MATCH (n:${label})
          RETURN count(n) as count
        `)
        
        const count = countResult.records[0].get('count').low
        console.log(`  Total nodes with label ${label}: ${count}`)
        
        // Get relationship types for this label
        const relationshipsResult = await session.run(`
          MATCH (n:${label})-[r]-()
          RETURN DISTINCT type(r) as relType
          LIMIT 10
        `)
        
        const relationships = relationshipsResult.records.map(r => r.get('relType'))
        if (relationships.length > 0) {
          console.log(`  Relationship types:`, relationships)
        } else {
          console.log(`  No relationships found for ${label} nodes`)
        }
      }
      
      return allLabels
    } catch (error) {
      console.error('Database Error when exploring labels:', error)
      throw error
    } finally {
      await session.close()
    }
  }
}

export default new Neo4jService()