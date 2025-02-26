import neo4j from 'neo4j-driver'

class Neo4jService {
  constructor() {
    // Replace these with your Neo4j credentials
    this.uri = 'neo4j://localhost:7687'
    this.user = 'neo4j'
    this.password = 'your-password'
    
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
}

export default new Neo4jService() 