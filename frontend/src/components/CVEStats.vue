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
        
        <!-- Severity Filter Dropdown -->
        <div class="filter-dropdown">
          <button class="filter-button" @click="toggleSeverityFilter">
            <i class="fas fa-filter"></i>
            <span>{{ selectedSeverity || 'Filter by Severity' }}</span>
            <i class="fas fa-chevron-down"></i>
          </button>
          <div class="dropdown-menu" v-if="showSeverityFilter">
            <div 
              v-for="severity in severityOptions" 
              :key="severity.value"
              class="dropdown-item"
              :class="{ active: selectedSeverity === severity.value }"
              @click="selectSeverity(severity.value)"
            >
              <span 
                class="severity-indicator"
                :class="severity.value ? severity.value.toLowerCase() : 'all'"
              ></span>
              {{ severity.label }}
            </div>
          </div>
        </div>
        
        <button 
          @click="expandAllCVEs" 
          class="action-button"
          :disabled="!cves.length"
        >
          <i :class="expandedCVEs.length === cves.length ? 'fas fa-compress-alt' : 'fas fa-expand-alt'"></i>
          {{ expandedCVEs.length === cves.length ? 'Collapse All' : 'Expand All' }}
        </button>
        <button 
          @click="updateSeverity" 
          class="action-button update-button"
          :disabled="!cves.length || updatingSeverity"
        >
          <i :class="updatingSeverity ? 'fas fa-circle-notch fa-spin' : 'fas fa-sync-alt'"></i>
          {{ updatingSeverity ? 'Updating...' : 'Update Severity' }}
        </button>
      </div>
      
      <!-- Filter tags/pills to show active filters -->
      <div class="active-filters" v-if="selectedSeverity">
        <div class="filter-tag">
          <span class="tag-label">Severity:</span>
          <span class="tag-value" :class="selectedSeverity.toLowerCase()">{{ selectedSeverity }}</span>
          <button class="tag-remove" @click="clearSeverityFilter">
            <i class="fas fa-times"></i>
          </button>
        </div>
      </div>
    </div>
    
    <!-- Notification component -->
    <div 
      v-if="notification.show" 
      class="notification"
      :class="notification.type"
    >
      <i :class="getNotificationIcon()"></i>
      <p>{{ notification.message }}</p>
      <button @click="closeNotification" class="notification-close">
        <i class="fas fa-times"></i>
      </button>
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
              <span v-if="updatingCVEs.includes(cve.cveId)" class="updating-indicator">
                <i class="fas fa-sync-alt fa-spin"></i>
              </span>
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
import { ref, computed, onMounted, onUnmounted } from 'vue'
import neo4jService from '../services/neo4j/neo4jService'
import { useRoute } from 'vue-router'

const route = useRoute()
const cves = ref([])
const expandedCVEs = ref([])
const searchQuery = ref('')
const loading = ref(true)
const displayLimit = ref(10)
const showAll = ref(false)
const updatingSeverity = ref(false)
const updatingCVEs = ref([])
const notification = ref({
  show: false,
  message: '',
  type: 'info',
  timeout: null
})

// Severity filter state
const showSeverityFilter = ref(false)
const selectedSeverity = ref('')
const severityOptions = [
  { value: '', label: 'All Severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
  { value: 'UNKNOWN', label: 'Unknown' }
]

// Toggle severity filter dropdown
const toggleSeverityFilter = () => {
  showSeverityFilter.value = !showSeverityFilter.value
}

// Select a severity level for filtering
const selectSeverity = (severity) => {
  selectedSeverity.value = severity
  showSeverityFilter.value = false
}

// Clear the severity filter
const clearSeverityFilter = () => {
  selectedSeverity.value = ''
}

// Click outside to close dropdown
const handleClickOutside = (event) => {
  const dropdown = document.querySelector('.filter-dropdown')
  if (dropdown && !dropdown.contains(event.target)) {
    showSeverityFilter.value = false
  }
}

// Add and remove click outside event listener
onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})

const filteredCVEs = computed(() => {
  // First apply severity filter if selected
  let filtered = selectedSeverity.value
    ? cves.value.filter(cve => cve.severity === selectedSeverity.value)
    : cves.value
  
  // Then apply search filter if query exists
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    filtered = filtered.filter(cve => {
      const cveId = cve.cveId.toLowerCase()
      const repoMatches = cve.repositories.some(repo => 
        repo.toLowerCase().includes(query)
      )
      return cveId.includes(query) || repoMatches
    })
  }
  
  // Apply pagination
  return showAll.value ? filtered : filtered.slice(0, displayLimit.value)
})

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

const closeNotification = () => {
  notification.value.show = false
  if (notification.value.timeout) {
    clearTimeout(notification.value.timeout)
    notification.value.timeout = null
  }
}

const showNotification = (message, type = 'info', duration = 5000) => {
  // Clear existing notification if any
  if (notification.value.timeout) {
    clearTimeout(notification.value.timeout)
  }
  
  // Set new notification
  notification.value = {
    show: true,
    message,
    type,
    timeout: setTimeout(() => {
      notification.value.show = false
    }, duration)
  }
}

const getNotificationIcon = () => {
  switch (notification.value.type) {
    case 'success':
      return 'fas fa-check-circle'
    case 'error':
      return 'fas fa-exclamation-circle'
    case 'warning':
      return 'fas fa-exclamation-triangle'
    default:
      return 'fas fa-info-circle'
  }
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

async function updateSeverity() {
  try {
    updatingSeverity.value = true
    
    // Get all CVE IDs from the current list
    const cveIds = cves.value.map(cve => cve.cveId)
    updatingCVEs.value = [...cveIds] // Mark all CVEs as updating
    
    // Call service to update severity with progress callback
    const result = await neo4jService.updateCVESeverities(cveIds, (processedCveId) => {
      // Remove the processed CVE from the updating list
      updatingCVEs.value = updatingCVEs.value.filter(id => id !== processedCveId)
    })
    
    // Check if the update was successful
    if (result.success) {
      // Show success notification with any warnings
      const warningText = result.failedCount > 0 
        ? ` ${result.failedCount} CVEs could not be updated.` 
        : '';
        
      showNotification(
        `Successfully updated ${result.updatedCount} CVE severities from NVD API.${warningText}`,
        result.failedCount > 0 ? 'warning' : 'success'
      )
    } else {
      // Show warning notification with error message
      showNotification(
        result.message || 'Failed to update CVE severities',
        'warning'
      )
    }
    
    // Refresh the CVE data after update
    await fetchCVEs()
  } catch (error) {
    console.error('Error updating CVE severities:', error)
    showNotification(
      `Error updating CVE severities: ${error.message || 'Unknown error'}`,
      'error'
    )
  } finally {
    updatingSeverity.value = false
    updatingCVEs.value = [] // Clear updating status for any remaining CVEs
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

.update-button {
  background-color: var(--secondary-color);
  color: white;
  border-color: var(--secondary-color);
}

.update-button:hover:not(:disabled) {
  background-color: var(--accent-color);
  border-color: var(--accent-color);
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

.notification {
  display: flex;
  align-items: center;
  padding: 1rem;
  margin-bottom: 1.5rem;
  border-radius: 6px;
  border-left: 4px solid;
  position: relative;
  animation: slideIn 0.3s ease;
}

@keyframes slideIn {
  from {
    transform: translateY(-20px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

.notification.info {
  background-color: #EBF8FF;
  border-left-color: #4299E1;
  color: #2A4365;
}

.notification.success {
  background-color: #F0FFF4;
  border-left-color: #48BB78;
  color: #22543D;
}

.notification.warning {
  background-color: #FFFAF0;
  border-left-color: #ED8936;
  color: #7B341E;
}

.notification.error {
  background-color: #FFF5F5;
  border-left-color: #F56565;
  color: #822727;
}

.notification i {
  font-size: 1.25rem;
  margin-right: 0.75rem;
}

.notification p {
  flex: 1;
}

.notification-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.25rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: inherit;
  opacity: 0.6;
  transition: opacity 0.2s;
}

.notification-close:hover {
  opacity: 1;
}

.updating-indicator {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 0.5rem;
  color: var(--accent-color);
  font-size: 0.9rem;
}

.filter-dropdown {
  position: relative;
  display: inline-block;
}

.filter-button {
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
  min-width: 180px;
}

.filter-button i:last-child {
  margin-left: auto;
  font-size: 0.8rem;
  opacity: 0.7;
}

.filter-button:hover {
  background-color: var(--background-color);
  border-color: var(--accent-color);
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  left: 0;
  z-index: 10;
  width: 100%;
  min-width: 180px;
  background-color: white;
  border-radius: 6px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1), 0 1px 3px rgba(0, 0, 0, 0.08);
  margin-top: 0.5rem;
  overflow: hidden;
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

.dropdown-item {
  display: flex;
  align-items: center;
  padding: 0.75rem 1rem;
  cursor: pointer;
  transition: background-color 0.2s;
}

.dropdown-item:hover {
  background-color: rgba(0, 0, 0, 0.05);
}

.dropdown-item.active {
  background-color: var(--background-color);
  font-weight: 500;
}

.severity-indicator {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  margin-right: 0.75rem;
}

.severity-indicator.critical {
  background-color: #F56565;
}

.severity-indicator.high {
  background-color: #ED8936;
}

.severity-indicator.medium {
  background-color: #ECC94B;
}

.severity-indicator.low {
  background-color: #48BB78;
}

.severity-indicator.unknown {
  background-color: #CBD5E0;
}

.severity-indicator.all {
  background: linear-gradient(to right, #F56565, #ED8936, #ECC94B, #48BB78);
}

.active-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.filter-tag {
  display: flex;
  align-items: center;
  padding: 0.25rem 0.5rem;
  background-color: white;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.9rem;
}

.tag-label {
  color: var(--light-text);
  margin-right: 0.5rem;
}

.tag-value {
  font-weight: 500;
  padding: 0.15rem 0.4rem;
  border-radius: 3px;
  margin-right: 0.5rem;
}

.tag-value.critical {
  background-color: #F56565;
  color: white;
}

.tag-value.high {
  background-color: #ED8936;
  color: white;
}

.tag-value.medium {
  background-color: #ECC94B;
  color: #744210;
}

.tag-value.low {
  background-color: #48BB78;
  color: white;
}

.tag-value.unknown {
  background-color: #CBD5E0;
  color: #2D3748;
}

.tag-remove {
  background: none;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--light-text);
  padding: 0.15rem;
  border-radius: 50%;
  transition: all 0.2s;
}

.tag-remove:hover {
  background-color: rgba(0, 0, 0, 0.05);
  color: var(--text-color);
}
</style>
