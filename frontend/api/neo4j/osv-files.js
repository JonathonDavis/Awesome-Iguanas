import { methodNotAllowed, runCypher, sendJson } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (v:Vulnerability)
        RETURN v
        ORDER BY v.published DESC
        LIMIT 100
      `
    })

    const rows = result.records.map(record => {
      const vuln = record.get('v')
      return {
        id: vuln.identity.toString(),
        properties: vuln.properties,
        ...vuln.properties
      }
    })

    return sendJson(res, 200, rows)
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch OSV files' })
  }
}
