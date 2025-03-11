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