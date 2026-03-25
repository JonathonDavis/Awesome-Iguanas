import { methodNotAllowed, runCypher, sendJson } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN collect(distinct n) as nodes, collect(distinct r) as relationships
      `
    })

    if (!result.records.length) return sendJson(res, 200, { nodes: [], relationships: [] })

    const nodesRaw = result.records[0].get('nodes') || []
    const relsRaw = result.records[0].get('relationships') || []

    const nodes = nodesRaw.map(node => ({
      id: node.identity.toString(),
      labels: node.labels,
      properties: node.properties,
      ...node.properties
    }))

    const relationships = relsRaw.map(rel => ({
      id: rel.identity.toString(),
      source: rel.start.toString(),
      target: rel.end.toString(),
      type: rel.type,
      properties: rel.properties
    }))

    return sendJson(res, 200, { nodes, relationships })
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch graph data' })
  }
}
