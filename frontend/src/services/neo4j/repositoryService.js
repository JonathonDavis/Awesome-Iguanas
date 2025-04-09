export async function getRepositoryStatistics() {
  const session = this.driver.session();
  try {
    console.log('Executing repository statistics query...');
    const result = await session.run(`
      MATCH (r:Repository)-[:HAS_VERSION]->(v:Version)
      OPTIONAL MATCH (c:CVE)-[:IDENTIFIED_AS]->(vuln:Vulnerability)-[:FOUND_IN]->(r)
      RETURN r.url AS RepositoryURL, 
             v.version AS Version, 
             v.size AS Size, 
             v.primary_language AS PrimaryLanguage,
             v.language_count AS LanguageCount,
             v.language_json AS AllLanguages,
             collect(DISTINCT c.id) as cves
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
        cves: cves || []
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
  const session = this.driver.session();
  try {
    console.log('Fetching CVE repository data...');
    const result = await session.run(`
      MATCH (c:CVE)-[:IDENTIFIED_AS]->(v:Vulnerability)-[:FOUND_IN]->(r:Repository)
      WITH c, v, collect(DISTINCT r.url) as repositories
      RETURN 
        c.id as cveId,
        repositories,
        v.published as publishedDate,
        v.modified as modifiedDate,
        v.summary as summary,
        v.severity as severity,
        v.withdrawn as withdrawn,
        v.details as details
      ORDER BY c.id DESC
    `);
    
    if (!result.records || result.records.length === 0) {
      console.warn('No CVE data found in database');
      return [];
    }

    console.log(`Found ${result.records.length} total CVEs in database`);

    const cveData = result.records.map(record => {
      const cveId = record.get('cveId');
      const repositories = record.get('repositories');
      const publishedDate = record.get('publishedDate');
      const modifiedDate = record.get('modifiedDate');
      const summary = record.get('summary');
      const severity = record.get('severity');
      const withdrawn = record.get('withdrawn');
      const details = record.get('details');
      
      return {
        cveId: cveId,
        repositories: repositories,
        publishedDate: publishedDate ? new Date(publishedDate.toString()) : null,
        modifiedDate: modifiedDate ? new Date(modifiedDate.toString()) : null,
        summary: summary || 'No summary available',
        details: details || 'No details available',
        severity: severity || 'UNKNOWN',
        withdrawn: withdrawn ? new Date(withdrawn.toString()) : null,
        status: withdrawn ? 'WITHDRAWN' : 'ACTIVE'
      };
    });

    console.log(`Processed ${cveData.length} CVEs with repositories`);
    return cveData;
  } catch (error) {
    console.error('Error getting CVE repository data:', error);
    throw error;
  } finally {
    await session.close();
  }
} 