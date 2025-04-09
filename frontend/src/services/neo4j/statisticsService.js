export async function getStatistics() {
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

export async function getNodeDistribution() {
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

export async function getVulnerabilityStatistics() {
  const session = this.driver.session()
  try {
    const result = await session.run(`
      MATCH (v:Vulnerability)
      WITH count(v) as totalVulns
      MATCH (p:Package)
      WITH totalVulns, count(p) as totalPkgs
      MATCH (p:Package)
      WITH totalVulns, totalPkgs, count(DISTINCT p.ecosystem) as uniqueEcos
      MATCH (t:UpdateTracking)
      RETURN {
        totalVulnerabilities: totalVulns,
        totalPackages: totalPkgs,
        uniqueEcosystems: uniqueEcos,
        lastUpdate: t.last_update
      } as stats
    `)
    
    if (result.records.length > 0) {
      const stats = result.records[0].get('stats')
      return {
        totalVulnerabilities: stats.totalVulnerabilities.low,
        totalPackages: stats.totalPackages.low,
        uniqueEcosystems: stats.uniqueEcosystems.low,
        lastUpdate: stats.lastUpdate
      }
    }
    
    return {
      totalVulnerabilities: 0,
      totalPackages: 0,
      uniqueEcosystems: 0,
      lastUpdate: null
    }
  } catch (error) {
    console.error('Error getting vulnerability statistics:', error)
    throw error
  } finally {
    await session.close()
  }
} 