import { methodNotAllowed, runCypher, sendJson, toNumber } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (n)
        RETURN count(n) as totalNodes
      `
    })

    const total = result.records?.[0]?.get('totalNodes')
    return sendJson(res, 200, { totalNodes: toNumber(total) || 0 })
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch total node count' })
  }
}
