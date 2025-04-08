<template>
  <div class="cve-explorer">
    <div class="explorer-container">
      <div class="search-container">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search CVEs..."
          class="search-input"
        />
        <button 
          @click="expandAllCVEs" 
          class="expand-all-button"
          :disabled="!cves.length"
        >
          {{ expandedCVEs.length === cves.length ? 'Collapse All' : 'Expand All' }}
        </button>
      </div>
      
      <div v-if="loading" class="loading-message">
        Loading CVE data...
      </div>
      
      <div v-else-if="!cves.length" class="no-data-message">
        No CVE data available
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
            <div class="cve-title">
              <a 
                :href="`https://nvd.nist.gov/vuln/detail/${cve.cveId}`" 
                target="_blank" 
                rel="noopener noreferrer"
                class="cve-link"
                @click.stop
              >
                {{ cve.cveId }}
              </a>
              <span class="cve-status" :class="cve.status.toLowerCase()">
                {{ cve.status }}
              </span>
            </div>
            <div class="cve-meta">
              <div class="repo-count">{{ cve.repositories.length }} repositories</div>
              <div class="severity" :class="cve.severity.toLowerCase()">{{ cve.severity }}</div>
            </div>
          </div>
          
          <div class="cve-details" v-if="expandedCVEs.includes(cve.cveId)">
            <div class="cve-info">
              <div class="info-item">
                <strong>Published:</strong> {{ formatDate(cve.publishedDate) }}
              </div>
              <div class="info-item">
                <strong>Last Modified:</strong> {{ formatDate(cve.modifiedDate) }}
              </div>
              <!-- <div class="info-item">
                <strong>Summary:</strong> {{ cve.summary }}
              </div> -->
              <div class="info-item" v-if="cve.details">
                <strong>Details:</strong> {{ cve.details }}
              </div>
              <div class="info-item" v-if="cve.withdrawn">
                <strong>Withdrawn:</strong> {{ formatDate(cve.withdrawn) }}
              </div>
            </div>
            
            <div class="repository-list">
              <div class="repo-list-header">Affected Repositories:</div>
              <div 
                v-for="repo in cve.repositories" 
                :key="repo"
                class="repo-item"
              >
                <a 
                  :href="repo" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  class="repo-link"
                >
                  {{ getRepoName(repo) }}
                </a>
              </div>
            </div>
          </div>
        </div>
        
        <div v-if="!showAll && cves.length > displayLimit" class="show-more-container">
          <button @click="toggleShowAll" class="show-more-button">
            Show More ({{ cves.length - displayLimit }} more)
          </button>
        </div>
        
        <div v-if="showAll" class="show-more-container">
          <button @click="toggleShowAll" class="show-more-button">
            Show Less
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import neo4jService from '../services/neo4jService'

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
  }
}

const fetchData = async () => {
  try {
    loading.value = true;
    const data = await neo4jService.getCVERepositoryData();
    console.log('Fetched CVE data:', data);
    cves.value = data;
  } catch (error) {
    console.error('Error fetching CVE data:', error);
  } finally {
    loading.value = false;
  }
}

const formatDate = (date) => {
  if (!date) return 'Not available';
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

fetchData()
</script>

<style scoped>
.cve-explorer {
  width: 100%;
  height: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.explorer-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  background-color: #066c43;
  border-radius: 4px;
  padding: 1rem;
  overflow: hidden;
  flex: 1;
}

.cve-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  overflow-y: auto;
  flex: 1;
  padding-right: 0.5rem;
  margin-right: -0.5rem;
  min-height: 0;
}

.cve-list::-webkit-scrollbar {
  width: 8px;
}

.cve-list::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
}

.cve-list::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

.cve-list::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

.cve-item {
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  overflow: hidden;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
}

.cve-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  cursor: pointer;
  transition: background-color 0.2s;
  background-color: #402C1B;
}

.cve-header:hover {
  background-color: rgba(184, 105, 8, 0.815);
}

.cve-link {
  color: white;
  text-decoration: none;
  font-weight: bold;
  font-size: 1.1rem;
  transition: color 0.2s;
}

.cve-link:hover {
  color: #61dafb;
  text-decoration: underline;
}

.repo-count {
  color: #efefee;
  font-size: 0.9rem;
}

.repository-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem;
  background-color: #402C1B;
  overflow-y: auto;
  margin-right: -0.5rem;
  padding-right: 0.5rem;
  max-height: 50vh;
}

.repository-list::-webkit-scrollbar {
  width: 8px;
}

.repository-list::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
}

.repository-list::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

.repository-list::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

.repo-item {
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
  padding: 0.75rem;
  transition: background-color 0.2s;
}

.repo-item:hover {
  background-color: rgba(210, 34, 34, 0.943);
}

.repo-link {
  color: white;
  text-decoration: none;
  display: block;
  width: 100%;
}

.repo-link:hover {
  color: #61dafb;
  text-decoration: underline;
}

.search-container {
  margin-bottom: 1rem;
  padding: 0.5rem;
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.search-input {
  flex: 1;
  padding: 0.75rem;
  border: none;
  border-radius: 4px;
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  font-size: 1rem;
  width: 100%;
  box-sizing: border-box;
}

.search-input::placeholder {
  color: rgba(255, 255, 255, 0.5);
}

.search-input:focus {
  outline: none;
  background-color: rgba(255, 255, 255, 0.15);
}

.expand-all-button {
  padding: 0.75rem 1rem;
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background-color 0.2s;
  white-space: nowrap;
}

.expand-all-button:hover {
  background-color: rgba(255, 255, 255, 0.2);
}

@media (max-width: 768px) {
  .explorer-container {
    padding: 0.5rem;
  }
  
  .cve-link {
    font-size: 1rem;
  }
}

.loading-message, .no-data-message {
  color: white;
  text-align: center;
  padding: 2rem;
  font-size: 1.1rem;
}

.loading-message {
  color: #61dafb;
}

.no-data-message {
  color: #ff6b6b;
}

.cve-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.cve-status {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: bold;
}

.cve-status.active {
  background-color: rgba(40, 167, 69, 0.2);
  color: #28a745;
}

.cve-status.withdrawn {
  background-color: rgba(220, 53, 69, 0.2);
  color: #dc3545;
}

.cve-meta {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.severity {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: bold;
}

.severity.critical {
  background-color: rgba(220, 53, 69, 0.2);
  color: #dc3545;
}

.severity.high {
  background-color: rgba(255, 193, 7, 0.2);
  color: #ffc107;
}

.severity.medium {
  background-color: rgba(23, 162, 184, 0.2);
  color: #17a2b8;
}

.severity.low {
  background-color: rgba(40, 167, 69, 0.2);
  color: #28a745;
}

.cve-details {
  padding: 1rem;
  background-color: rgba(0, 0, 0, 0.2);
  border-top: 1px solid rgba(255, 255, 255, 0.1);
}

.cve-info {
  margin-bottom: 1rem;
}

.info-item {
  margin-bottom: 0.5rem;
  color: white;
}

.info-item strong {
  color: #61dafb;
  margin-right: 0.5rem;
}

.repo-list-header {
  color: #61dafb;
  font-weight: bold;
  margin-bottom: 0.5rem;
}

.show-more-container {
  display: flex;
  justify-content: center;
  margin-top: 1rem;
  padding: 0.5rem;
}

.show-more-button {
  padding: 0.75rem 1.5rem;
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background-color 0.2s;
}

.show-more-button:hover {
  background-color: rgba(255, 255, 255, 0.2);
}
</style>
