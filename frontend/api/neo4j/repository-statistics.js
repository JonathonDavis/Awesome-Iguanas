import { methodNotAllowed, runCypher, sendJson, toNumber } from '../_lib/neo4j.js'

export default async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(req, res, ['GET'])

  try {
    const result = await runCypher({
      query: `
        MATCH (r:Repository)-[:HAS_VERSION]->(v:Version)
        OPTIONAL MATCH (c1:CVE)-[:IDENTIFIED_AS]->(vuln1:Vulnerability)-[:FOUND_IN]->(r)
        OPTIONAL MATCH (vuln2:Vulnerability)-[:REFERS_TO]->(ref:Reference)
        WHERE ref.url CONTAINS r.url
        OPTIONAL MATCH (c2:CVE)-[:IDENTIFIED_AS]->(vuln2)
        RETURN r.url AS RepositoryURL,
               v.version AS Version,
               v.size AS Size,
               v.primary_language AS PrimaryLanguage,
               v.language_count AS LanguageCount,
               v.language_json AS AllLanguages,
               collect(DISTINCT c1.id) + collect(DISTINCT c2.id) as cves
        ORDER BY r.url, v.version
      `
    })

    const repoMap = new Map()

    for (const record of result.records) {
      const url = record.get('RepositoryURL')
      const version = record.get('Version')
      const size = record.get('Size')
      const primaryLanguage = record.get('PrimaryLanguage')
      const languageCount = record.get('LanguageCount')
      const allLanguages = record.get('AllLanguages')
      const cves = record.get('cves')

      if (!repoMap.has(url)) {
        repoMap.set(url, { repository: url, versions: [] })
      }

      let languages = {}
      if (allLanguages) {
        try {
          const parsed = typeof allLanguages === 'string' ? JSON.parse(allLanguages) : allLanguages
          const totalBytes = Object.values(parsed).reduce((sum, bytes) => sum + bytes, 0)
          for (const [lang, bytes] of Object.entries(parsed)) {
            const pct = totalBytes > 0 ? (bytes / totalBytes) * 100 : 0
            languages[lang] = pct
          }
        } catch (e) {
          // ignore language parse failures
        }
      }

      let sizeValue = '0M'
      if (size) {
        if (typeof size === 'object') {
          if (size.low !== undefined) sizeValue = `${size.low}M`
          else if (typeof size.toNumber === 'function') sizeValue = `${size.toNumber()}M`
          else if (typeof size.toString === 'function') sizeValue = size.toString()
        } else if (typeof size === 'number') {
          sizeValue = `${size}M`
        } else if (typeof size === 'string') {
          if (size.endsWith('K')) {
            const kb = parseFloat(size.slice(0, -1))
            sizeValue = `${(kb / 1024).toFixed(2)}M`
          } else {
            sizeValue = size
          }
        }
      }

      repoMap.get(url).versions.push({
        version,
        size: sizeValue,
        languages,
        primaryLanguage,
        languageCount: toNumber(languageCount) || 0,
        cves: Array.isArray(cves) ? [...new Set(cves.filter(Boolean))] : []
      })
    }

    return sendJson(res, 200, Array.from(repoMap.values()))
  } catch (error) {
    return sendJson(res, 500, { error: error?.message || 'Failed to fetch repository statistics' })
  }
}
