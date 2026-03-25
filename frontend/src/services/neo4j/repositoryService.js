export async function getRepositoryStatistics() {
  const session = this.createSession();
  try {
    console.log('Executing repository statistics query...');
    const result = await session.run(`
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
    `);
    
    // Group versions by repository
    const repoMap = new Map();
    result.records.forEach(record => {
      const url = record.get('RepositoryURL');
      const version = record.get('Version');
      const size = record.get('Size');
      const primaryLanguage = record.get('PrimaryLanguage');
      const languageCount = record.get('LanguageCount');
      const allLanguages = record.get('AllLanguages');
      const cves = record.get('cves');
      
      if (!repoMap.has(url)) {
        repoMap.set(url, {
          repository: url,
          versions: []
        });
      }
      
      // Parse language_json if it exists
      let languages = {};
      if (allLanguages) {
        try {
          const parsedLanguages = typeof allLanguages === 'string' ? 
                                JSON.parse(allLanguages) : 
                                allLanguages;
          
          // Convert to percentage-based format with decimal precision
          const totalBytes = Object.values(parsedLanguages).reduce((sum, bytes) => sum + bytes, 0);
          Object.entries(parsedLanguages).forEach(([lang, bytes]) => {
            // Calculate percentage with full precision
            const percentage = (bytes / totalBytes) * 100;
            // Store the raw percentage without rounding
            languages[lang] = percentage;
          });
        } catch (e) {
          console.error('Error parsing language_json:', e);
        }
      }
      
      // Handle size value
      let sizeValue = '0M';
      if (size) {
        if (typeof size === 'object') {
          if (size.low !== undefined) {
            sizeValue = size.low.toString() + 'M';
          } else if (size.toNumber) {
            sizeValue = size.toNumber().toString() + 'M';
          } else if (size.toString) {
            sizeValue = size.toString();
          }
        } else if (typeof size === 'number') {
          sizeValue = size.toString() + 'M';
        } else if (typeof size === 'string') {
          // Check if the size ends with K (KB)
          if (size.endsWith('K')) {
            // Convert KB to MB by dividing by 1024
            const kbValue = parseFloat(size.slice(0, -1));
            const mbValue = (kbValue / 1024).toFixed(2);
            sizeValue = mbValue + 'M';
          } else {
            sizeValue = size;
          }
        }
      }
      
      repoMap.get(url).versions.push({
        version,
        size: sizeValue,
        languages: languages,
        primaryLanguage: primaryLanguage,
        languageCount: languageCount ? languageCount.low || 0 : 0,
        cves: Array.isArray(cves) ? [...new Set(cves.filter(Boolean))] : []
      });
    });
    
    const stats = Array.from(repoMap.values());
    return stats;
  } catch (error) {
    console.error('Error getting repository statistics:', error);
    throw error;
  } finally {
    await session.close();
  }
}

export async function getCVERepositoryData() {
  const session = this.createSession();
  try {
    console.log('Fetching CVE repository data...');
    const result = await session.run(`
      MATCH (c:CVE)-[:IDENTIFIED_AS]->(v:Vulnerability)
      OPTIONAL MATCH (v)-[:FOUND_IN]->(rFound:Repository)
      OPTIONAL MATCH (v)-[:REFERS_TO]->(ref:Reference)
      WHERE ref.url CONTAINS 'github.com/'
      WITH c, v, collect(DISTINCT rFound.url) AS foundRepoUrls, collect(DISTINCT ref.url) AS refUrls

      WITH c, v, foundRepoUrls,
        [u IN refUrls |
          CASE
            WHEN u IS NULL THEN null
            ELSE
              // Strip query and fragment first
              CASE
                WHEN size(split(split(u, '?')[0], '#')) = 0 THEN null
                ELSE
                  CASE
                    WHEN (split(split(u, '?')[0], '#')[0] CONTAINS 'github.com/advisories/') THEN null
                    WHEN (split(split(u, '?')[0], '#')[0] CONTAINS 'github.com/security/advisories/') THEN null
                    WHEN size(split(split(split(u, '?')[0], '#')[0], 'github.com/')) < 2 THEN null
                    ELSE
                      CASE
                        WHEN size(split(split(split(split(u, '?')[0], '#')[0], 'github.com/')[1], '/')) < 2 THEN null
                        ELSE
                          'https://github.com/' +
                          split(split(split(split(u, '?')[0], '#')[0], 'github.com/')[1], '/')[0] + '/' +
                            replace(split(split(split(split(u, '?')[0], '#')[0], 'github.com/')[1], '/')[1], '.git', '')
                      END
                  END
              END
          END
        ] AS inferredRepoUrls

      WITH c, v, foundRepoUrls + inferredRepoUrls AS repoUrls
      UNWIND repoUrls AS repoUrl
      WITH c, v, collect(DISTINCT repoUrl) AS repositories
      WITH c, v, [url IN repositories WHERE url IS NOT NULL] AS repositories
      RETURN
        c.id as cveId,
        repositories,
        v.published as publishedDate,
        v.modified as modifiedDate,
        v.summary as summary,
        CASE
          WHEN v.severity IS NULL THEN 'UNKNOWN'
          WHEN toUpper(trim(toString(v.severity))) IN ['CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN'] THEN toUpper(trim(toString(v.severity)))
          ELSE 'UNKNOWN'
        END as severity,
        v.withdrawn as withdrawn,
        v.details as details
      ORDER BY c.id DESC
    `);
    
    if (!result.records || result.records.length === 0) {
      console.warn('No CVE data found in database');
      return [];
    }

    console.log(`Found ${result.records.length} total CVEs in database`);

    // Create a Map to deduplicate CVEs by ID
    const cveMap = new Map();
    
    result.records.forEach(record => {
      const cveId = record.get('cveId');
      const repositories = record.get('repositories');
      const publishedDate = record.get('publishedDate');
      const modifiedDate = record.get('modifiedDate');
      const summary = record.get('summary');
      const severity = record.get('severity');
      const withdrawn = record.get('withdrawn');
      const details = record.get('details');
      
      // If we already have this CVE, merge the repositories
      if (cveMap.has(cveId)) {
        const existingCVE = cveMap.get(cveId);
        const combinedRepos = [...new Set([...existingCVE.repositories, ...repositories])];
        existingCVE.repositories = combinedRepos;
      } else {
        // Otherwise add it to the map
        cveMap.set(cveId, {
          cveId: cveId,
          repositories: repositories,
          publishedDate: publishedDate ? new Date(publishedDate.toString()) : null,
          modifiedDate: modifiedDate ? new Date(modifiedDate.toString()) : null,
          summary: summary || 'No summary available',
          details: details || 'No details available',
          severity: severity || 'UNKNOWN',
          withdrawn: withdrawn ? new Date(withdrawn.toString()) : null,
          status: withdrawn ? 'WITHDRAWN' : 'ACTIVE'
        });
      }
    });

    // Convert the map to an array
    const cveData = Array.from(cveMap.values());

    console.log(`Processed ${cveData.length} unique CVEs with repositories`);
    return cveData;
  } catch (error) {
    console.error('Error getting CVE repository data:', error);
    throw error;
  } finally {
    await session.close();
  }
} 