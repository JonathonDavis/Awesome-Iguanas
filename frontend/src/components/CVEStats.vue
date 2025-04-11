<template>
  <div class="cve-explorer">
    <div class="explorer-header">
      <div class="search-container">
        <div class="search-input-wrapper">
          <i class="fas fa-search search-icon"></i>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search vulnerabilities..."
            class="search-input"
          />
        </div>
        <button 
          @click="expandAllCVEs" 
          class="action-button"
          :disabled="!cves.length"
        >
          <i :class="expandedCVEs.length === cves.length ? 'fas fa-compress-alt' : 'fas fa-expand-alt'"></i>
          {{ expandedCVEs.length === cves.length ? 'Collapse All' : 'Expand All' }}
        </button>
      </div>
    </div>
    
    <div v-if="loading" class="loading-state">
      <i class="fas fa-circle-notch fa-spin"></i>
      <p>Loading vulnerability data...</p>
    </div>
    
    <div v-else-if="!cves.length" class="empty-state">
      <i class="fas fa-shield-alt"></i>
      <p>No vulnerability data available</p>
    </div>
    
    <div v-else class="cve-list">
      <div 
        v-for="cve in filteredCVEs" 
        :key="cve.cveId"
        class="cve-item"
      >
        <div 
          class="cve-header"
          @click="toggleCVE(cve)"
        >
          <div class="cve-header-main">
            <div class="cve-title">
              <i :class="expandedCVEs.includes(cve.cveId) ? 'fas fa-chevron-down' : 'fas fa-chevron-right'" class="expand-icon"></i>
              <a 
                :href="`https://nvd.nist.gov/vuln/detail/${cve.cveId}`" 
                target="_blank" 
                rel="noopener noreferrer"
                class="cve-link"
                @click.stop
              >
                {{ cve.cveId }}
              </a>
            </div>
            <div class="severity-badge" :class="cve.severity.toLowerCase()">
              {{ cve.severity }}
            </div>
          </div>
          <div class="cve-meta">
            <span class="meta-item">
              <i class="fas fa-calendar-alt"></i> {{ formatDate(cve.publishedDate) }}
            </span>
            <span class="meta-item">
              <i class="fas fa-code-branch"></i> {{ cve.repositories.length }} repositories
            </span>
            <span class="status-badge" :class="cve.status.toLowerCase()">
              {{ cve.status }}
            </span>
          </div>
        </div>
        
        <div class="cve-details" v-if="expandedCVEs.includes(cve.cveId)">
          <div class="details-section">
            <h3 class="section-title"><i class="fas fa-info-circle"></i> Vulnerability Details</h3>
            <div class="details-grid">
              <div class="detail-item">
                <strong>Published:</strong> {{ formatDate(cve.publishedDate) }}
              </div>
              <div class="detail-item">
                <strong>Last Modified:</strong> {{ formatDate(cve.modifiedDate) }}
              </div>
              <div class="detail-item full-width" v-if="cve.details">
                <strong>Details:</strong>
                <p class="detail-text">{{ cve.details }}</p>
              </div>
              <div class="detail-item" v-if="cve.withdrawn">
                <strong>Withdrawn:</strong> {{ formatDate(cve.withdrawn) }}
              </div>
            </div>
          </div>
          
          <div class="details-section">
            <h3 class="section-title"><i class="fas fa-code-branch"></i> Affected Repositories</h3>
            <div class="repository-list">
              <a 
                v-for="repo in cve.repositories" 
                :key="repo"
                :href="repo" 
                target="_blank" 
                rel="noopener noreferrer"
                class="repo-link"
              >
                <i class="fas fa-external-link-alt"></i>
                {{ getRepoName(repo) }}
              </a>
            </div>
          </div>
        </div>
      </div>
      
      <div v-if="!showAll && cves.length > displayLimit" class="pagination-controls">
        <button @click="showLessCVEs" class="page-button" v-if="displayLimit > 10">
          <i class="fas fa-chevron-left"></i> Previous 10
        </button>
        <span class="page-info">Showing {{ Math.min(displayLimit, filteredCVEs.length) }} of {{ cves.length }}</span>
        <button @click="showMoreCVEs" class="page-button">
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
import { ref, computed, onMounted } from 'vue'
import neo4jService from '../services/neo4j/neo4jService'
import { useRoute } from 'vue-router'

const route = useRoute()
const cves = ref([])
const expandedCVEs = ref([])
const searchQuery = ref('')
const loading = ref(true)
const displayLimit = ref(10)
const showAll = ref(false)

const filteredCVEs = computed(() => {
  if (!searchQuery.value) {
    return showAll.value ? cves.value : cves.value.slice(0, displayLimit.value);
  }
  
  const query = searchQuery.value.toLowerCase();
  const filtered = cves.value.filter(cve => {
    const cveId = cve.cveId.toLowerCase();
    const repoMatches = cve.repositories.some(repo => 
      repo.toLowerCase().includes(query)
    );
    return cveId.includes(query) || repoMatches;
  });
  
  return showAll.value ? filtered : filtered.slice(0, displayLimit.value);
});

const getRepoName = (url) => {
  try {
    const urlObj = new URL(url)
    return urlObj.pathname.split('/').slice(-2).join('/')
  } catch {
    return url
  }
}

const formatDate = (dateString) => {
  if (!dateString) return 'Not available';
  return new Date(dateString).toLocaleDateString();
}

const toggleCVE = (cve) => {
  const index = expandedCVEs.value.indexOf(cve.cveId)
  if (index === -1) {
    expandedCVEs.value.push(cve.cveId)
  } else {
    expandedCVEs.value.splice(index, 1)
  }
}

const expandAllCVEs = () => {
  if (expandedCVEs.value.length === cves.value.length) {
    expandedCVEs.value = [];
  } else {
    expandedCVEs.value = cves.value.map(cve => cve.cveId);
  }
};

const toggleShowAll = () => {
  showAll.value = !showAll.value;
  if (!showAll.value) {
    expandedCVEs.value = [];
    displayLimit.value = 10; // Reset display limit when showing less
  }
}

const showMoreCVEs = () => {
  displayLimit.value += 10;
}

const showLessCVEs = () => {
  displayLimit.value = Math.max(10, displayLimit.value - 10);
}

onMounted(async () => {
  // Check for CVE search parameter and populate search field
  if (route.query.cveSearch) {
    searchQuery.value = route.query.cveSearch
  }
  
  await fetchCVEs()
})

async function fetchCVEs() {
  try {
    loading.value = true
    cves.value = await neo4jService.getCVERepositoryData()
    
    // If search parameter is present, expand matching CVEs
    if (route.query.cveSearch) {
      const matchingCVEs = cves.value.filter(cve => {
        return cve.cveId.toLowerCase().includes(route.query.cveSearch.toLowerCase())
      })
      
      if (matchingCVEs.length) {
        matchingCVEs.forEach(cve => {
          if (!expandedCVEs.value.includes(cve.cveId)) {
            expandedCVEs.value.push(cve.cveId)
          }
        })
      }
    }
  } catch (error) {
    console.error('Error fetching CVE data:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.cve-explorer {
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

.cve-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.cve-item {
  background-color: white;
  border-radius: 8px;
  border: 1px solid var(--border-color);
  overflow: hidden;
  transition: box-shadow 0.2s ease;
}

.cve-item:hover {
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}

.cve-header {
  padding: 1rem 1.25rem;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.cve-header:hover {
  background-color: rgba(0, 0, 0, 0.02);
}

.cve-header-main {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.cve-title {
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

.cve-link {
  color: var(--primary-color);
  text-decoration: none;
  font-size: 1.1rem;
  transition: color 0.2s ease;
}

.cve-link:hover {
  color: var(--accent-color);
  text-decoration: underline;
}

.cve-meta {
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

.severity-badge, .status-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.critical {
  background-color: #F56565;
  color: white;
}

.severity-badge.high {
  background-color: #ED8936;
  color: white;
}

.severity-badge.medium {
  background-color: #ECC94B;
  color: #744210;
}

.severity-badge.low {
  background-color: #48BB78;
  color: white;
}

.severity-badge.unknown {
  background-color: #CBD5E0;
  color: #2D3748;
}

.status-badge.published {
  background-color: #4299E1;
  color: white;
}

.status-badge.modified {
  background-color: #805AD5;
  color: white;
}

.status-badge.withdrawn {
  background-color: #A0AEC0;
  color: white;
}

.cve-details {
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

.repository-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 0.75rem;
}

.repo-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background-color: rgba(0, 0, 0, 0.02);
  border-radius: 4px;
  color: var(--text-color);
  text-decoration: none;
  font-size: 0.95rem;
  transition: all 0.2s ease;
  border: 1px solid var(--border-color);
}

.repo-link:hover {
  background-color: var(--accent-color);
  color: white;
  border-color: var(--accent-color);
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

@media (max-width: 768px) {
  .cve-header-main {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .cve-meta {
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
