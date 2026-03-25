import neo4j from 'neo4j-driver'

let cachedDriver = null

function pickEnv(...keys) {
  for (const key of keys) {
    const value = process.env[key]
    if (value !== undefined && value !== null && String(value).trim() !== '') return String(value)
  }
  return undefined
}

export function getNeo4jConfig() {
  const uri = pickEnv('NEO4J_URI', 'VITE_NEO4J_URI')
  const user = pickEnv('NEO4J_USER', 'NEO4J_USERNAME', 'VITE_NEO4J_USER', 'VITE_NEO4J_USERNAME')
  const password = pickEnv('NEO4J_PASSWORD', 'VITE_NEO4J_PASSWORD')
  const database = pickEnv('NEO4J_DATABASE', 'VITE_NEO4J_DATABASE')

  if (!uri || !user || !password) {
    throw new Error('Missing Neo4j server env vars: set NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD (and optionally NEO4J_DATABASE).')
  }

  return { uri, user, password, database }
}

export function getNeo4jDriver() {
  if (cachedDriver) return cachedDriver

  const { uri, user, password } = getNeo4jConfig()

  cachedDriver = neo4j.driver(
    uri,
    neo4j.auth.basic(user, password),
    {
      logging: neo4j.logging.console('error')
    }
  )

  return cachedDriver
}

export async function runCypher({ query, params = {}, database } = {}) {
  const driver = getNeo4jDriver()
  const cfg = getNeo4jConfig()

  const session = (database || cfg.database)
    ? driver.session({ database: database || cfg.database })
    : driver.session()

  try {
    return await session.run(query, params)
  } finally {
    await session.close()
  }
}

export function sendJson(res, status, body) {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.end(JSON.stringify(body))
}

export function methodNotAllowed(req, res, allowed = ['GET']) {
  res.statusCode = 405
  res.setHeader('Allow', allowed.join(', '))
  sendJson(res, 405, { error: 'Method Not Allowed' })
}

export function toNumber(value) {
  if (value == null) return value
  if (typeof value === 'number') return value
  if (typeof value === 'object') {
    if (typeof value.toNumber === 'function') return value.toNumber()
    if (typeof value.low === 'number') return value.low
  }
  const num = Number(value)
  return Number.isNaN(num) ? value : num
}
