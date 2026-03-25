import { methodNotAllowed, runCypher, sendJson, toNumber } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (n)
        WITH labels(n) as labels
        UNWIND labels as label
        RETURN label, count(*) as count
        ORDER BY count DESC
      `
    })

    const distribution = result.records.map(record => ({
      label: record.get('label'),
      count: toNumber(record.get('count')) || 0
    }))

    return sendJson(res, 200, distribution)
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch node distribution' })
  }
}
