import { methodNotAllowed, runCypher, sendJson, toNumber } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (n)
        RETURN count(n) as totalNodes,
               count(DISTINCT labels(n)) as uniqueLabels
      `
    })

    if (!result.records.length) return sendJson(res, 200, { totalNodes: 0, uniqueLabels: 0 })

    const record = result.records[0]
    return sendJson(res, 200, {
      totalNodes: toNumber(record.get('totalNodes')) || 0,
      uniqueLabels: toNumber(record.get('uniqueLabels')) || 0
    })
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch statistics' })
  }
}
