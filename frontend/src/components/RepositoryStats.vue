<template>
  <div class="repository-explorer">
    <div class="explorer-header">
      <div class="search-container">
        <div class="search-input-wrapper">
          <i class="fas fa-search search-icon"></i>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search repositories..."
            class="search-input"
          />
        </div>
        <button 
          @click="expandAllRepos" 
          class="action-button"
          :disabled="!repositories.length"
        >
          <i :class="expandedRepos.length === repositories.length ? 'fas fa-compress-alt' : 'fas fa-expand-alt'"></i>
          {{ expandedRepos.length === repositories.length ? 'Collapse All' : 'Expand All' }}
        </button>
      </div>
      
      <!-- Debug info - remove in production -->
      <div class="debug-info" v-if="searchQuery">
        <span>Search: "{{ searchQuery }}" - Found {{ filteredRepositories.length }} / {{ repositories.length }} repositories</span>
      </div>
    </div>
    
    <div v-if="loading" class="loading-state">
      <i class="fas fa-circle-notch fa-spin"></i>
      <p>Loading repository data...</p>
    </div>
    
    <div v-else-if="!repositories.length" class="empty-state">
      <i class="fas fa-database"></i>
      <p>No repository data available</p>
    </div>
    
    <div v-else class="repository-list">
      <div 
        v-for="repo in filteredRepositories" 
        :key="repo.repository"
        class="repository-item"
      >
        <div 
          class="repository-header"
          @click="toggleRepo(repo)"
        >
          <div class="repository-header-main">
            <div class="repository-title">
              <i :class="expandedRepos.includes(repo.repository) ? 'fas fa-chevron-down' : 'fas fa-chevron-right'" class="expand-icon"></i>
              <a 
                :href="repo.repository" 
                target="_blank" 
                rel="noopener noreferrer"
                class="repository-link"
                @click.stop
              >
                {{ getRepoName(repo.repository) }}
              </a>
            </div>
            <div class="stats-badge">
              <span class="badge-item">
                <i class="fas fa-tag"></i> {{ repo.versions.length }}
              </span>
              <span class="badge-item" v-if="repo.versions.some(v => v.cves && v.cves.length)">
                <i class="fas fa-shield-alt"></i> {{ getTotalCVEs(repo) }}
              </span>
            </div>
          </div>
          <div class="repository-meta">
            <span class="meta-item" v-if="repo.versions && repo.versions[0] && repo.versions[0].primaryLanguage">
              <i class="fas fa-code-branch"></i> {{ repo.versions[0].primaryLanguage }}
            </span>
            <span class="meta-item" v-if="getLatestVersion(repo)">
              <i class="fas fa-tag"></i> Latest: {{ getLatestVersion(repo) }}
            </span>
          </div>
        </div>
        
        <div class="repository-details" v-if="expandedRepos.includes(repo.repository)">
          <div class="details-section">
            <h3 class="section-title"><i class="fas fa-info-circle"></i> Repository Information</h3>
            <div class="details-grid">
              <div class="detail-item">
                <strong>Owner:</strong> {{ getRepoOwner(repo.repository) }}
              </div>
              <div class="detail-item" v-if="repo.versions && repo.versions[0] && repo.versions[0].primaryLanguage">
                <strong>Primary Language:</strong> {{ repo.versions[0].primaryLanguage }}
              </div>
              <div class="detail-item">
                <strong>Total Versions:</strong> {{ repo.versions.length }}
              </div>
              <div class="detail-item">
                <strong>Total CVEs:</strong> {{ getTotalCVEs(repo) }}
              </div>
            </div>
          </div>
          
          <div class="details-section" v-if="repo.versions && repo.versions.length">
            <h3 class="section-title"><i class="fas fa-tag"></i> Versions</h3>
            <div class="version-list">
              <div 
                v-for="version in repo.versions" 
                :key="version.version"
                class="version-item"
              >
                <div class="version-header">
                  <span class="version-number">{{ version.version }}</span>
                  <span class="version-size">{{ formatSize(version.size) }}</span>
                </div>
                <div class="version-cves" v-if="version.cves && version.cves.length">
                  <div class="cve-chip-list">
                    <a 
                      v-for="cve in version.cves" 
                      :key="cve"
                      :href="`https://nvd.nist.gov/vuln/detail/${cve}`"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="cve-chip"
                    >
                      {{ cve }}
                    </a>
                  </div>
                </div>
                <div class="language-breakdown" v-if="version.languages">
                  <div class="severity-bar">
                    <div 
                      v-for="(percentage, language) in version.languages" 
                      :key="language"
                      class="language-segment"
                      :style="{width: `${percentage}%`, backgroundColor: getLanguageColor(language)}"
                      :title="`${language}: ${percentage.toFixed(1)}%`"
                    ></div>
                  </div>
                  <div class="language-legend">
                    <div 
                      v-for="(percentage, language) in getTopLanguages(version.languages)" 
                      :key="language" 
                      class="legend-item"
                    >
                      <span class="legend-color" :style="{backgroundColor: getLanguageColor(language)}"></span>
                      <span class="legend-label">{{ language }}: {{ percentage.toFixed(1) }}%</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div v-if="!showAll && repositories.length > displayLimit" class="pagination-controls">
        <button @click="showLessRepos" class="page-button" v-if="displayLimit > 10">
          <i class="fas fa-chevron-left"></i> Previous 10
        </button>
        <span class="page-info">Showing {{ Math.min(displayLimit, filteredRepositories.length) }} of {{ repositories.length }}</span>
        <button @click="showMoreRepos" class="page-button">
          Next 10 <i class="fas fa-chevron-right"></i>
        </button>
        <button @click="toggleShowAll" class="show-all-button">
          <i class="fas fa-list"></i> Show All
        </button>
      </div>
      
      <div v-if="showAll" class="pagination-controls">
        <button @click="toggleShowAll" class="show-all-button">
          <i class="fas fa-list-alt"></i> Show Less
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import neo4jService from '../services/neo4j/neo4jService'

const repositories = ref([])
const expandedRepos = ref([])
const searchQuery = ref('')
const debouncedSearchQuery = ref('')
const loading = ref(true)
const displayLimit = ref(10)
const showAll = ref(false)

// Debounce the search query
let debounceTimeout = null
watch(searchQuery, (newValue) => {
  clearTimeout(debounceTimeout)
  debounceTimeout = setTimeout(() => {
    debouncedSearchQuery.value = newValue
    console.log('Search debounced:', newValue)
  }, 300) // 300ms debounce
})

const filteredRepositories = computed(() => {
  // Return all repositories if no search query
  if (!debouncedSearchQuery.value || debouncedSearchQuery.value.trim() === '') {
    const repos = showAll.value ? repositories.value : repositories.value.slice(0, displayLimit.value);
    console.log(`No search query - returning ${repos.length} repositories`);
    return repos;
  }
  
  try {
    const query = debouncedSearchQuery.value.toLowerCase().trim();
    console.log(`Filtering repositories with query: "${query}"`);
    
    if (!repositories.value || !Array.isArray(repositories.value)) {
      console.error('Repository data is not an array:', repositories.value);
      return [];
    }
    
    // Define a safe accessor function to avoid null/undefined errors
    const safeString = (val) => {
      if (val === null || val === undefined) return '';
      return String(val).toLowerCase();
    };
    
    const filtered = repositories.value.filter(repo => {
      try {
        if (!repo) return false;
        
        // Check repository URL
        const repoUrl = safeString(repo.repository);
        if (repoUrl.includes(query)) return true;
        
        // Check repository name
        try {
          const repoName = safeString(getRepoName(repo.repository));
          if (repoName.includes(query)) return true;
        } catch (e) {
          console.warn('Error parsing repo name:', e);
        }
        
        // Exit early if no versions
        if (!repo.versions || !Array.isArray(repo.versions) || repo.versions.length === 0) {
          return false;
        }
        
        // Check versions and their properties
        return repo.versions.some(version => {
          try {
            if (!version) return false;
            
            // Check version number
            if (safeString(version.version).includes(query)) return true;
            
            // Check primary language
            if (safeString(version.primaryLanguage).includes(query)) return true;
            
            // Check languages object
            if (version.languages && typeof version.languages === 'object') {
              // Check if any language key matches
              const langMatch = Object.keys(version.languages).some(lang => 
                safeString(lang).includes(query)
              );
              if (langMatch) return true;
            }
            
            // Check CVEs if they exist
            if (Array.isArray(version.cves)) {
              const cveMatch = version.cves.some(cve => 
                safeString(cve).includes(query)
              );
              if (cveMatch) return true;
            }
            
            return false;
          } catch (e) {
            console.warn('Error filtering version:', e);
            return false;
          }
        });
      } catch (e) {
        console.error('Error in repository filtering:', e);
        return false;
      }
    });
    
    console.log(`Search query "${query}" found ${filtered.length} matching repositories`);
    return showAll.value ? filtered : filtered.slice(0, displayLimit.value);
  } catch (error) {
    console.error('Error in filteredRepositories:', error);
    return [];
  }
});

const getRepoName = (url) => {
  try {
    const urlObj = new URL(url)
    return urlObj.pathname.split('/').slice(-2).join('/')
  } catch {
    return url
  }
}

const getRepoOwner = (url) => {
  try {
    const urlObj = new URL(url)
    return urlObj.pathname.split('/').slice(-2)[0]
  } catch {
    return 'Unknown'
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'Not available';
  return new Date(dateString).toLocaleDateString();
}

const toggleRepo = (repo) => {
  const index = expandedRepos.value.indexOf(repo.repository)
  if (index === -1) {
    expandedRepos.value.push(repo.repository)
  } else {
    expandedRepos.value.splice(index, 1)
  }
}

const getTotalCVEs = (repo) => {
  if (!repo.versions) return 0;
  let total = 0;
  repo.versions.forEach(version => {
    if (version.cves && Array.isArray(version.cves)) {
      total += version.cves.length;
    }
  });
  return total;
}

const getLatestVersion = (repo) => {
  if (!repo.versions || !repo.versions.length) return null;
  
  // Simple assumption: the first version is the latest
  return repo.versions[0].version;
}

const formatSize = (sizeValue) => {
  if (!sizeValue) return '0 MB';
  
  // Convert to string if it's a number
  const sizeStr = typeof sizeValue === 'number' ? sizeValue.toString() : sizeValue;
  
  // Remove the 'M' suffix and format the number
  const number = parseFloat(sizeStr.replace('M', ''));
  
  if (isNaN(number)) return '0 MB';
  
  // Format the number to show decimals only if they exist
  const formattedSize = number % 1 === 0 ? number.toString() : number.toFixed(2).replace(/\.?0+$/, '');
  
  return `${formattedSize} MB`;
}

// GitHub-like language colors
const languageColors = {
  'JavaScript': '#f1e05a',
  'TypeScript': '#2b7489',
  'Python': '#3572A5',
  'Java': '#b07219',
  'C++': '#f34b7d',
  'C': '#555555',
  'Go': '#00ADD8',
  'Ruby': '#701516',
  'PHP': '#4F5D95',
  'Rust': '#dea584',
  'Swift': '#ffac45',
  'Kotlin': '#F18E33',
  // Add more languages as needed
  'Other': '#cccccc'
}

const getLanguageColor = (lang) => {
  return languageColors[lang] || languageColors['Other'];
}

const getTopLanguages = (languages) => {
  // Get top 5 languages by percentage
  if (!languages) return {};
  
  const entries = Object.entries(languages);
  entries.sort((a, b) => b[1] - a[1]);
  
  const topLanguages = {};
  entries.slice(0, 5).forEach(([lang, percentage]) => {
    topLanguages[lang] = percentage;
  });
  
  return topLanguages;
}

const expandAllRepos = () => {
  if (expandedRepos.value.length === repositories.value.length) {
    expandedRepos.value = [];
  } else {
    expandedRepos.value = repositories.value.map(repo => repo.repository);
  }
};

const toggleShowAll = () => {
  showAll.value = !showAll.value;
  if (!showAll.value) {
    expandedRepos.value = [];
    displayLimit.value = 10; // Reset display limit when showing less
  }
}

const showMoreRepos = () => {
  displayLimit.value += 10;
}

const showLessRepos = () => {
  displayLimit.value = Math.max(10, displayLimit.value - 10);
}

const fetchData = async () => {
  try {
    loading.value = true;
    const data = await neo4jService.getRepositoryStatistics();
    
    // Log repository data
    console.log(`Fetched ${data.length} repositories`);
    
    // Log structure of first repository for debugging
    if (data.length > 0) {
      const sampleRepo = data[0];
      console.log('Sample repository structure:', {
        repository: sampleRepo.repository,
        versionsCount: sampleRepo.versions ? sampleRepo.versions.length : 0
      });
      
      // Log first version if available
      if (sampleRepo.versions && sampleRepo.versions.length > 0) {
        const sampleVersion = sampleRepo.versions[0];
        console.log('Sample version structure:', {
          version: sampleVersion.version,
          size: sampleVersion.size,
          primaryLanguage: sampleVersion.primaryLanguage,
          languageCount: sampleVersion.languageCount,
          languages: sampleVersion.languages ? Object.keys(sampleVersion.languages).length : 0,
          cves: sampleVersion.cves ? sampleVersion.cves.length : 0
        });
      }
    }
    
    repositories.value = data;
  } catch (error) {
    console.error('Error fetching repository data:', error);
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  fetchData();
})
</script>

<style scoped>
.repository-explorer {
  width: 100%;
}

.explorer-header {
  margin-bottom: 1.5rem;
}

.search-container {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}

.search-input-wrapper {
  position: relative;
  flex: 1;
  min-width: 250px;
}

.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--light-text);
}

.search-input {
  width: 100%;
  padding: 0.75rem 1rem 0.75rem 2.5rem;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.search-input:focus {
  border-color: var(--accent-color);
  box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.15);
}

.action-button {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.25rem;
  background-color: white;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.95rem;
  font-weight: 500;
  color: var(--text-color);
  cursor: pointer;
  transition: all 0.2s ease;
}

.action-button:hover {
  background-color: var(--background-color);
  border-color: var(--accent-color);
}

.action-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.loading-state, .empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  text-align: center;
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
  margin-bottom: 1.5rem;
}

.loading-state i, .empty-state i {
  font-size: 2.5rem;
  color: var(--light-text);
  margin-bottom: 1rem;
}

.loading-state p, .empty-state p {
  color: var(--light-text);
  font-size: 1.1rem;
}

.repository-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.repository-item {
  background-color: white;
  border-radius: 8px;
  border: 1px solid var(--border-color);
  overflow: hidden;
  transition: box-shadow 0.2s ease;
}

.repository-item:hover {
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}

.repository-header {
  padding: 1rem 1.25rem;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.repository-header:hover {
  background-color: rgba(0, 0, 0, 0.02);
}

.repository-header-main {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.repository-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 600;
  color: var(--primary-color);
}

.expand-icon {
  font-size: 0.85rem;
  color: var(--light-text);
  width: 16px;
}

.repository-link {
  color: var(--primary-color);
  text-decoration: none;
  font-size: 1.1rem;
  transition: color 0.2s ease;
}

.repository-link:hover {
  color: var(--accent-color);
  text-decoration: underline;
}

.repository-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 1.25rem;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--light-text);
  font-size: 0.9rem;
}

.stats-badge {
  display: flex;
  gap: 0.75rem;
}

.badge-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.25rem 0.5rem;
  background-color: var(--background-color);
  border-radius: 4px;
  font-size: 0.85rem;
  color: var(--text-color);
}

.repository-details {
  padding: 0 1.25rem 1.25rem;
  border-top: 1px solid var(--border-color);
}

.details-section {
  margin-top: 1rem;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--secondary-color);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.detail-item {
  margin-bottom: 0.75rem;
}

.full-width {
  grid-column: 1 / -1;
}

.detail-item strong {
  display: block;
  font-weight: 500;
  color: var(--light-text);
  margin-bottom: 0.25rem;
}

.detail-text {
  line-height: 1.5;
  color: var(--text-color);
}

.version-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.version-item {
  padding: 0.75rem;
  background-color: var(--background-color);
  border-radius: 6px;
  border: 1px solid var(--border-color);
}

.version-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
}

.version-number {
  font-weight: 600;
  color: var(--primary-color);
}

.version-date {
  color: var(--light-text);
  font-size: 0.9rem;
}

.version-cves {
  margin-top: 0.5rem;
}

.cve-chip-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.cve-chip {
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  text-decoration: none;
  transition: opacity 0.2s;
  background-color: #CBD5E0;
  color: #2D3748;
}

.cve-chip:hover {
  opacity: 0.8;
}

.cve-chip.critical {
  background-color: #F56565;
  color: white;
}

.cve-chip.high {
  background-color: #ED8936;
  color: white;
}

.cve-chip.medium {
  background-color: #ECC94B;
  color: #744210;
}

.cve-chip.low {
  background-color: #48BB78;
  color: white;
}

.cve-chip.unknown {
  background-color: #CBD5E0;
  color: #2D3748;
}

.cve-summary {
  margin-top: 0.5rem;
}

.severity-distribution {
  margin-bottom: 1rem;
}

.severity-bar {
  display: flex;
  height: 12px;
  width: 100%;
  border-radius: 6px;
  overflow: hidden;
  margin-bottom: 0.5rem;
}

.language-segment {
  height: 100%;
  transition: width 0.3s ease;
}

.language-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 0.5rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 3px;
}

.legend-color.critical {
  background-color: #F56565;
}

.legend-color.high {
  background-color: #ED8936;
}

.legend-color.medium {
  background-color: #ECC94B;
}

.legend-color.low {
  background-color: #48BB78;
}

.legend-color.unknown {
  background-color: #CBD5E0;
}

.pagination-controls {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 1.5rem;
  flex-wrap: wrap;
}

.page-button, .show-all-button {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background-color: white;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.9rem;
  color: var(--text-color);
  cursor: pointer;
  transition: all 0.2s ease;
}

.page-button:hover, .show-all-button:hover {
  background-color: var(--background-color);
  border-color: var(--accent-color);
}

.page-info {
  color: var(--light-text);
  font-size: 0.9rem;
}

.show-all-button {
  margin-left: auto;
  background-color: var(--accent-color);
  color: white;
  border-color: var(--accent-color);
}

.show-all-button:hover {
  background-color: var(--secondary-color);
  border-color: var(--secondary-color);
  color: white;
}

.language-breakdown {
  margin-top: 0.75rem;
}

.debug-info {
  background-color: #EBF8FF;
  border: 1px solid #BEE3F8;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  color: #2C5282;
}

@media (max-width: 768px) {
  .repository-header-main {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .repository-meta {
    margin-top: 0.5rem;
  }
  
  .pagination-controls {
    flex-direction: column;
    align-items: stretch;
  }
  
  .show-all-button {
    margin-left: 0;
  }
}
</style> 