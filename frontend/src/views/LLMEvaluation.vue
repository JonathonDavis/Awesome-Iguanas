<template>
  <div class="vulnerability-dashboard">
    <!-- Dashboard Header -->
    <div class="dashboard-header">
      <div class="logo-area">
        <div class="logo-shield">
          <i class="fas fa-shield-alt"></i>
        </div>
        <div class="logo-text">
          <h1>VulnRadar</h1>
          <span class="tagline">AI-Powered Vulnerability Detection</span>
        </div>
      </div>
      <div class="header-actions">
        <button class="action-button refresh-btn" @click="refreshData">
          <i class="fas fa-sync-alt"></i>
          <span>Refresh Data</span>
        </button>
      </div>
    </div>
    
    <!-- Main Dashboard Grid -->
    <div class="dashboard-grid">
      <!-- Stats Panel -->
      <div class="dashboard-panel stats-panel">
        <div class="panel-header">
          <h2><i class="fas fa-chart-pie"></i> Vulnerability Metrics</h2>
        </div>
        <div class="stats-grid">
          <div class="stat-card total">
            <div class="stat-icon">
              <i class="fas fa-shield-virus"></i>
            </div>
            <div class="stat-data">
              <span class="stat-value">{{ totalFindings }}</span>
              <span class="stat-label">Total Findings</span>
            </div>
          </div>
          <div class="stat-card critical">
            <div class="stat-icon">
              <i class="fas fa-radiation"></i>
            </div>
            <div class="stat-data">
              <span class="stat-value">{{ veryPromisingCount }}</span>
              <span class="stat-label">Very Promising</span>
            </div>
          </div>
          <div class="stat-card warning">
            <div class="stat-icon">
              <i class="fas fa-exclamation-triangle"></i>
            </div>
            <div class="stat-data">
              <span class="stat-value">{{ slightlyPromisingCount }}</span>
              <span class="stat-label">Slightly Promising</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Filters -->
      <div class="dashboard-panel filters-panel">
        <div class="panel-header">
          <h2><i class="fas fa-filter"></i> Quick Filters</h2>
        </div>
        <div class="filters-content">
          <div class="filter-group">
            <div class="filter-label">Classification:</div>
            <div class="filter-options">
              <button 
                @click="setFilter('all')" 
                :class="['filter-chip', { active: activeFilter === 'all' }]"
              >
                <i class="fas fa-globe"></i> All
              </button>
              <button 
                @click="setFilter('Very Promising')" 
                :class="['filter-chip critical', { active: activeFilter === 'Very Promising' }]"
              >
                <i class="fas fa-radiation"></i> Very Promising
              </button>
              <button 
                @click="setFilter('Slightly Promising')" 
                :class="['filter-chip warning', { active: activeFilter === 'Slightly Promising' }]"
              >
                <i class="fas fa-exclamation-triangle"></i> Slightly Promising
              </button>
            </div>
          </div>
          <div class="search-bar">
            <i class="fas fa-search"></i>
            <input 
              type="text" 
              v-model="searchQuery" 
              placeholder="Search vulnerabilities..." 
            />
            <button v-if="searchQuery" @click="searchQuery = ''" class="clear-search">
              <i class="fas fa-times"></i>
            </button>
          </div>
        </div>
      </div>

      <!-- Main Data Table -->
      <div class="dashboard-panel data-panel">
        <div class="panel-header with-actions">
          <h2><i class="fas fa-table"></i> Vulnerability Findings</h2>
          <div class="panel-actions">
            <button class="action-button small" @click="exportData">
              <i class="fas fa-file-export"></i>
              <span>Export</span>
            </button>
          </div>
        </div>
        <div class="data-content">
          <table class="data-table" v-if="filteredFindings.length">
            <thead>
              <tr>
                <th @click="sortBy('CWE_CVE')" class="sortable-header">
                  CWE/CVE
                  <i v-if="sortColumn === 'CWE_CVE'" :class="['fas', sortDirection === 'asc' ? 'fa-sort-up' : 'fa-sort-down']"></i>
                </th>
                <th @click="sortBy('Vulnerability')" class="sortable-header">
                  Vulnerability
                  <i v-if="sortColumn === 'Vulnerability'" :class="['fas', sortDirection === 'asc' ? 'fa-sort-up' : 'fa-sort-down']"></i>
                </th>
                <th @click="sortBy('Classification')" class="sortable-header">
                  Classification
                  <i v-if="sortColumn === 'Classification'" :class="['fas', sortDirection === 'asc' ? 'fa-sort-up' : 'fa-sort-down']"></i>
                </th>
                <th @click="sortBy('OccurrenceCount')" class="sortable-header">
                  Occurrences
                  <i v-if="sortColumn === 'OccurrenceCount'" :class="['fas', sortDirection === 'asc' ? 'fa-sort-up' : 'fa-sort-down']"></i>
                </th>
                <th>Summary</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(item, index) in paginatedFindings" :key="index" :class="item.Classification.toLowerCase().replace(' ', '-')">
                <td class="cve-cell">{{ item.CWE_CVE || 'N/A' }}</td>
                <td class="vuln-cell">{{ item.Vulnerability }}</td>
                <td>
                  <span :class="['classification-tag', item.Classification.toLowerCase().replace(' ', '-')]">
                    {{ item.Classification }}
                  </span>
                </td>
                <td class="count-cell">
                  <span class="count-badge">{{ item.OccurrenceCount }}</span>
                </td>
                <td class="summary-cell">
                  {{ truncateSummary(item.Summary) }}
                </td>
                <td class="actions-cell">
                  <button class="icon-button" @click="viewDetails(item)" title="View Details">
                    <i class="fas fa-eye"></i>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
          
          <div v-else class="empty-state">
            <i class="fas fa-search"></i>
            <p>No vulnerability findings match your criteria</p>
            <button @click="resetFilters" class="action-button">Reset Filters</button>
          </div>

          <!-- Pagination Controls -->
          <div class="pagination-controls" v-if="filteredFindings.length">
            <div class="pagination-info">
              Showing {{ (currentPage - 1) * itemsPerPage + 1 }} - 
              {{ Math.min(currentPage * itemsPerPage, filteredFindings.length) }} 
              of {{ filteredFindings.length }}
            </div>
            <div class="pagination-buttons">
              <button @click="goToPage(1)" :disabled="currentPage === 1" class="page-button">
                <i class="fas fa-angle-double-left"></i>
              </button>
              <button @click="prevPage" :disabled="currentPage === 1" class="page-button">
                <i class="fas fa-angle-left"></i>
              </button>
              <div class="page-indicator">
                <span class="current-page">{{ currentPage }}</span>
                <span class="page-divider">/</span>
                <span class="total-pages">{{ totalPages }}</span>
              </div>
              <button @click="nextPage" :disabled="currentPage >= totalPages" class="page-button">
                <i class="fas fa-angle-right"></i>
              </button>
              <button @click="goToPage(totalPages)" :disabled="currentPage >= totalPages" class="page-button">
                <i class="fas fa-angle-double-right"></i>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Detail Modal -->
    <div v-if="selectedItem" class="modal-overlay" @click="selectedItem = null">
      <div class="modal-container" @click.stop>
        <div class="modal-header">
          <h3>Vulnerability Details</h3>
          <button class="close-button" @click="selectedItem = null">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body">
          <div class="detail-section">
            <div class="detail-header">
              <span :class="['classification-tag large', selectedItem.Classification.toLowerCase().replace(' ', '-')]">
                {{ selectedItem.Classification }}
              </span>
              <span class="detail-id">Found in {{ selectedItem.OccurrenceCount }} locations</span>
            </div>
            <h4 class="detail-title">{{ selectedItem.Vulnerability }}</h4>
          </div>

          <div class="detail-section">
            <h5><i class="fas fa-hashtag"></i> CWE/CVE Reference</h5>
            <p class="detail-content">{{ selectedItem.CWE_CVE || 'No specific CWE/CVE associated' }}</p>
          </div>

          <div class="detail-section">
            <h5><i class="fas fa-code-branch"></i> Affected Repositories</h5>
            <div class="repos-list">
              <div v-if="Array.isArray(selectedItem.AffectedRepositories) && selectedItem.AffectedRepositories.length > 0">
                <div v-for="(repo, index) in selectedItem.AffectedRepositories" :key="index" class="repo-item">
                  <i class="fas fa-archive"></i> {{ repo }}
                </div>
              </div>
              <p v-else class="detail-content">{{ selectedItem.Repository }}</p>
            </div>
          </div>

          <div class="detail-section">
            <h5><i class="fas fa-search"></i> Analysis</h5>
            <p class="detail-content">{{ selectedItem.Summary }}</p>
          </div>

          <div class="detail-actions">
            <button class="action-button" @click="selectedItem = null">
              <i class="fas fa-arrow-left"></i> Back to Results
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Loading State -->
    <div v-if="loading" class="loading-overlay">
      <div class="loader">
        <div class="loader-icon"></div>
        <div class="loader-text">Loading vulnerability data...</div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted, watch } from 'vue';
import neo4jService from '../services/neo4j/neo4jService';

export default {
  name: 'LLMEvaluation',
  setup() {
    // State
    const vulnerabilityData = ref([]);
    const loading = ref(true);
    const error = ref(null);
    const searchQuery = ref('');
    const activeFilter = ref('all');
    const selectedItem = ref(null);
    const currentPage = ref(1);
    const itemsPerPage = 10;
    const sortColumn = ref('Classification');
    const sortDirection = ref('desc');

    // Fetch vulnerability data from Neo4j
    const fetchData = async () => {
      loading.value = true;
      error.value = null;
      try {
        console.log("Starting to fetch vulnerability data...");
        
        const query = `
          MATCH (f:AIVulnerabilityFinding)-[:IDENTIFIED]->(v:Vulnerability)
          WHERE v.classification IN ['Slightly Promising', 'Very Promising']
          
          // Get repository name from ID
          WITH 
              CASE 
                  WHEN f.id CONTAINS 'github.com' 
                  THEN split(split(f.id, 'github.com/')[1], '@')[0]
                  ELSE f.id
              END AS Repository,
              v.headline AS Vulnerability,
              v.classification AS Classification,
              v.cve_cwe AS CWE_CVE,
              v.analysis AS Summary
          
          // Return individual results without grouping first
          RETURN
              CWE_CVE,
              Classification,
              Vulnerability,
              Summary,
              Repository
          ORDER BY Classification DESC, CWE_CVE
        `;
        
        console.log("Executing Neo4j query...");
        const results = await neo4jService.executeCustomQuery(query);
        console.log("Query results received:", results);
        
        // Process results
        if (!results || results.length === 0) {
          console.log("No results returned from query");
          vulnerabilityData.value = [];
        } else {
          console.log(`Got ${results.length} results`);
          
          // Group by CWE_CVE manually in JavaScript
          const groupedResults = {};
          results.forEach(item => {
            const key = `${item.CWE_CVE || 'unknown'}_${item.Classification}`;
            if (!groupedResults[key]) {
              groupedResults[key] = {
                CWE_CVE: item.CWE_CVE,
                Classification: item.Classification,
                Vulnerability: item.Vulnerability,
                Summary: item.Summary,
                AffectedRepositories: [],
                OccurrenceCount: 0
              };
            }
            
            if (item.Repository && !groupedResults[key].AffectedRepositories.includes(item.Repository)) {
              groupedResults[key].AffectedRepositories.push(item.Repository);
            }
            groupedResults[key].OccurrenceCount++;
          });
          
          vulnerabilityData.value = Object.values(groupedResults).map(item => ({
            ...item,
            Repository: Array.isArray(item.AffectedRepositories) ? 
              item.AffectedRepositories.join(', ') : 
              (item.AffectedRepositories || 'Unknown')
          }));
          
          console.log("Processed data:", vulnerabilityData.value);
        }
      } catch (err) {
        console.error('Error fetching vulnerability data:', err);
        error.value = `Failed to load vulnerability data: ${err.message || 'Unknown error'}`;
      } finally {
        loading.value = false;
        console.log("Finished loading data, loading state set to false");
      }
    };

    // Computed properties
    const filteredFindings = computed(() => {
      let filtered = vulnerabilityData.value;

      // Apply classification filter
      if (activeFilter.value !== 'all') {
        filtered = filtered.filter(v => v.Classification === activeFilter.value);
      }

      // Apply search filter
      if (searchQuery.value.trim()) {
        const query = searchQuery.value.toLowerCase();
        filtered = filtered.filter(v => 
          v.Repository?.toLowerCase().includes(query) ||
          v.Vulnerability?.toLowerCase().includes(query) ||
          (v.CWE_CVE && v.CWE_CVE.toLowerCase().includes(query)) ||
          v.Summary?.toLowerCase().includes(query)
        );
      }

      // Apply sorting
      return [...filtered].sort((a, b) => {
        const aValue = a[sortColumn.value] || '';
        const bValue = b[sortColumn.value] || '';
        
        if (aValue < bValue) return sortDirection.value === 'asc' ? -1 : 1;
        if (aValue > bValue) return sortDirection.value === 'asc' ? 1 : -1;
        return 0;
      });
    });

    const totalPages = computed(() => Math.ceil(filteredFindings.value.length / itemsPerPage));

    const paginatedFindings = computed(() => {
      const startIndex = (currentPage.value - 1) * itemsPerPage;
      const endIndex = startIndex + itemsPerPage;
      return filteredFindings.value.slice(startIndex, endIndex);
    });

    const totalFindings = computed(() => {
      const uniqueCount = vulnerabilityData.value.length;
      const totalInstances = vulnerabilityData.value.reduce((sum, item) => 
        sum + (item.OccurrenceCount || 0), 0);
      return `${uniqueCount} (${totalInstances} instances)`;
    });

    const veryPromisingCount = computed(() => {
      const veryPromisingItems = vulnerabilityData.value.filter(v => v.Classification === 'Very Promising');
      const uniqueCount = veryPromisingItems.length;
      const totalInstances = veryPromisingItems.reduce((sum, item) => 
        sum + (item.OccurrenceCount || 0), 0);
      return `${uniqueCount} (${totalInstances} instances)`;
    });

    const slightlyPromisingCount = computed(() => {
      const slightlyPromisingItems = vulnerabilityData.value.filter(v => v.Classification === 'Slightly Promising');
      const uniqueCount = slightlyPromisingItems.length;
      const totalInstances = slightlyPromisingItems.reduce((sum, item) => 
        sum + (item.OccurrenceCount || 0), 0);
      return `${uniqueCount} (${totalInstances} instances)`;
    });

    // Methods
    const setFilter = (filter) => {
      activeFilter.value = filter;
      currentPage.value = 1;
    };

    const resetFilters = () => {
      activeFilter.value = 'all';
      searchQuery.value = '';
      currentPage.value = 1;
    };

    const refreshData = () => {
      fetchData();
    };

    const sortBy = (column) => {
      if (sortColumn.value === column) {
        sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc';
      } else {
        sortColumn.value = column;
        sortDirection.value = 'asc';
      }
    };

    const nextPage = () => {
      if (currentPage.value < totalPages.value) {
        currentPage.value++;
      }
    };

    const prevPage = () => {
      if (currentPage.value > 1) {
        currentPage.value--;
      }
    };

    const goToPage = (page) => {
      currentPage.value = page;
    };

    const viewDetails = (item) => {
      selectedItem.value = item;
    };

    const truncateSummary = (text) => {
      if (!text) return '';
      return text.length > 100 ? text.substring(0, 100) + '...' : text;
    };

    const exportData = () => {
      // Placeholder for export functionality
      alert('Export functionality would be implemented here');
    };

    // Reset page when filters change
    watch([searchQuery, activeFilter], () => {
      currentPage.value = 1;
    });

    // Initialize
    onMounted(fetchData);

    return {
      vulnerabilityData,
      loading,
      error,
      searchQuery,
      activeFilter,
      selectedItem,
      currentPage,
      totalPages,
      sortColumn,
      sortDirection,
      filteredFindings,
      paginatedFindings,
      totalFindings,
      veryPromisingCount,
      slightlyPromisingCount,
      setFilter,
      resetFilters,
      refreshData,
      sortBy,
      nextPage,
      prevPage,
      goToPage,
      viewDetails,
      truncateSummary,
      exportData
    };
  }
};
</script>

<style scoped>
/* Main Dashboard Layout */
.vulnerability-dashboard {
  --primary-bg: var(--card-background, #ffffff);
  --secondary-bg: var(--background-color, #f3f8e6);
  --panel-bg: var(--card-background, #ffffff);
  --border-color: var(--border-color, #bade9e);
  --text-primary: var(--text-color, #223344);
  --text-secondary: var(--light-text, #5c7b6b);
  --accent-blue: var(--primary-color, #2d9f5d);
  --accent-purple: var(--secondary-light, #3db77f);
  --accent-green: var(--success-color, #43aa8b);
  --accent-red: var(--error-color, #e63946);
  --accent-yellow: var(--warning-color, #f9a03f);
  --hover-bg: rgba(45, 159, 93, 0.08);

  background-color: var(--secondary-bg);
  color: var(--text-primary);
  min-height: 100vh;
  padding: 1rem;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  width: 100%;
  max-width: 100%;
  overflow-x: hidden;
  box-sizing: border-box;
}

/* Dashboard Header */
.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border-color);
}

.logo-area {
  display: flex;
  align-items: center;
}

.logo-shield {
  font-size: 2rem;
  color: var(--primary-color, #2d9f5d);
  margin-right: 1rem;
  animation: pulse 3s infinite;
}

@keyframes pulse {
  0% { opacity: 0.8; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.05); }
  100% { opacity: 0.8; transform: scale(1); }
}

.logo-text h1 {
  margin: 0;
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: 0.5px;
  color: var(--text-primary);
}

.tagline {
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.action-button {
  background-color: var(--accent-color, #ff5a3d);
  color: white;
  border: none;
  border-radius: 4px;
  padding: 0.5rem 1rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 2px 4px var(--shadow-color, rgba(6, 85, 53, 0.15));
}

.action-button:hover {
  background-color: var(--accent-dark, #d14124);
  box-shadow: 0 4px 8px var(--shadow-color, rgba(6, 85, 53, 0.15));
}

.action-button.small {
  padding: 0.35rem 0.75rem;
  font-size: 0.8rem;
}

.icon-button {
  background-color: var(--secondary-bg);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s ease;
}

.icon-button:hover {
  background-color: var(--hover-bg);
  color: var(--primary-color, #2d9f5d);
  border-color: var(--primary-color, #2d9f5d);
}

/* Dashboard Grid Layout */
.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1.5rem;
}

.dashboard-panel {
  background-color: var(--panel-bg);
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  border: 1px solid var(--border-color);
}

.panel-header {
  padding: 1rem;
  background-color: var(--secondary-bg);
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: center;
}

.panel-header.with-actions {
  justify-content: space-between;
}

.panel-header h2 {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-primary);
}

.panel-header h2 i {
  color: var(--primary-color, #2d9f5d);
}

/* Stats Panel */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  padding: 1rem;
}

.stat-card {
  display: flex;
  align-items: center;
  padding: 1rem;
  border-radius: 8px;
  background-color: rgba(45, 159, 93, 0.05);
  border: 1px solid rgba(45, 159, 93, 0.1);
}

.stat-card.critical {
  background-color: rgba(230, 57, 70, 0.05);
  border-color: rgba(230, 57, 70, 0.1);
}

.stat-card.warning {
  background-color: rgba(249, 160, 63, 0.05);
  border-color: rgba(249, 160, 63, 0.1);
}

.stat-icon {
  font-size: 1.75rem;
  margin-right: 1rem;
  color: var(--primary-color, #2d9f5d);
}

.stat-card.critical .stat-icon {
  color: var(--error-color, #e63946);
}

.stat-card.warning .stat-icon {
  color: var(--warning-color, #f9a03f);
}

.stat-data {
  display: flex;
  flex-direction: column;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  line-height: 1.2;
  color: var(--text-primary);
}

.stat-label {
  font-size: 0.85rem;
  color: var(--text-secondary);
}

/* Filters Panel */
.filters-content {
  padding: 1rem;
}

.filter-group {
  margin-bottom: 1rem;
}

.filter-label {
  font-size: 0.9rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: var(--text-primary);
}

.filter-options {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.filter-chip {
  background-color: var(--secondary-bg);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  border-radius: 20px;
  padding: 0.4rem 0.75rem;
  font-size: 0.85rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition: all 0.2s ease;
}

.filter-chip:hover {
  border-color: var(--primary-color, #2d9f5d);
  color: var(--primary-color, #2d9f5d);
}

.filter-chip.active {
  background-color: var(--primary-color, #2d9f5d);
  color: white;
  border-color: var(--primary-color, #2d9f5d);
}

.filter-chip.critical.active {
  background-color: var(--error-color, #e63946);
  border-color: var(--error-color, #e63946);
}

.filter-chip.warning.active {
  background-color: var(--warning-color, #f9a03f);
  border-color: var(--warning-color, #f9a03f);
}

.search-bar {
  position: relative;
  display: flex;
  align-items: center;
}

.search-bar i {
  position: absolute;
  left: 1rem;
  color: var(--text-secondary);
}

.search-bar input {
  background-color: var(--secondary-bg);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 0.6rem 2.5rem 0.6rem 2.5rem;
  font-size: 0.95rem;
  width: 100%;
  transition: all 0.2s ease;
}

.search-bar input:focus {
  outline: none;
  border-color: var(--primary-color, #2d9f5d);
  box-shadow: 0 0 0 2px rgba(45, 159, 93, 0.2);
}

.clear-search {
  position: absolute;
  right: 1rem;
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
}

.clear-search:hover {
  color: var(--text-primary);
}

/* Data Table Panel */
.data-content {
  padding: 0;
  width: 100%;
  overflow-x: auto;
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  table-layout: fixed;
}

.data-table th {
  padding: 1rem;
  font-weight: 600;
  font-size: 0.9rem;
  color: var(--text-primary);
  background-color: var(--secondary-bg);
  border-bottom: 1px solid var(--border-color);
}

.sortable-header {
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.sortable-header:hover {
  color: var(--primary-color, #2d9f5d);
}

.data-table td {
  padding: 1rem;
  border-bottom: 1px solid var(--border-color);
  font-size: 0.95rem;
  color: var(--text-primary);
}

.data-table tr:hover td {
  background-color: rgba(45, 159, 93, 0.05);
}

.data-table tr:last-child td {
  border-bottom: none;
}

.data-table tr.very-promising td:first-child {
  border-left: 3px solid var(--error-color, #e63946);
}

.data-table tr.slightly-promising td:first-child {
  border-left: 3px solid var(--warning-color, #f9a03f);
}

.repo-cell, .vuln-cell {
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cve-cell {
  white-space: nowrap;
  max-width: 100px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.summary-cell {
  max-width: 250px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.actions-cell {
  width: 50px;
  text-align: center;
}

.classification-tag {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.25rem 0.6rem;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 500;
  background-color: rgba(45, 159, 93, 0.1);
  color: var(--primary-color, #2d9f5d);
  white-space: nowrap;
}

.classification-tag.very-promising {
  background-color: rgba(230, 57, 70, 0.1);
  color: var(--error-color, #e63946);
}

.classification-tag.slightly-promising {
  background-color: rgba(249, 160, 63, 0.1);
  color: var(--warning-color, #f9a03f);
}

.classification-tag.large {
  padding: 0.5rem 1rem;
  font-size: 1rem;
}

/* Empty State */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 1rem;
  text-align: center;
}

.empty-state i {
  font-size: 3rem;
  color: var(--border-color);
  margin-bottom: 1.5rem;
}

.empty-state p {
  font-size: 1.1rem;
  color: var(--text-secondary);
  margin-bottom: 1.5rem;
}

/* Pagination Controls */
.pagination-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  border-top: 1px solid var(--border-color);
  background-color: var(--secondary-bg);
}

.pagination-info {
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.pagination-buttons {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.page-button {
  width: 36px;
  height: 36px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: white;
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  cursor: pointer;
  transition: all 0.2s ease;
}

.page-button:hover:not(:disabled) {
  border-color: var(--primary-color, #2d9f5d);
  color: var(--primary-color, #2d9f5d);
}

.page-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-indicator {
  display: flex;
  align-items: center;
  padding: 0 0.75rem;
  height: 36px;
  background-color: white;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.9rem;
}

.current-page {
  color: var(--text-primary);
  font-weight: 600;
}

.page-divider {
  margin: 0 0.3rem;
  color: var(--text-secondary);
}

.total-pages {
  color: var(--text-secondary);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 1rem;
}

.modal-container {
  background-color: white;
  border-radius: 10px;
  width: 90%;
  max-width: 750px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

.modal-header {
  padding: 1.25rem;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
  background-color: var(--secondary-bg);
}

.modal-header h3 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-primary);
}

.close-button {
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 1.25rem;
  cursor: pointer;
  transition: color 0.2s ease;
}

.close-button:hover {
  color: var(--text-primary);
}

.modal-body {
  padding: 1.5rem;
}

.detail-section {
  margin-bottom: 2rem;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.detail-id {
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.detail-title {
  font-size: 1.5rem;
  margin: 0 0 1.5rem 0;
  line-height: 1.3;
  color: var(--text-primary);
}

.detail-section h5 {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 0.75rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-primary);
}

.detail-section h5 i {
  color: var(--primary-color, #2d9f5d);
}

.detail-content {
  font-size: 1rem;
  line-height: 1.6;
  margin: 0;
  color: var(--text-secondary);
}

.detail-actions {
  margin-top: 2rem;
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
}

/* Loading Overlay */
.loading-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.loader {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.loader-icon {
  width: 60px;
  height: 60px;
  border: 4px solid rgba(45, 159, 93, 0.2);
  border-radius: 50%;
  border-top-color: var(--primary-color, #2d9f5d);
  animation: spin 1s linear infinite;
  margin-bottom: 1.5rem;
}

.loader-text {
  font-size: 1.1rem;
  color: var(--text-primary);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Responsive Design */
@media (min-width: 768px) {
  .dashboard-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .stats-panel {
    grid-column: 1 / -1;
  }
  
  .data-panel {
    grid-column: 1 / -1;
  }
}

@media (min-width: 1200px) {
  .vulnerability-dashboard {
    padding: 2rem;
  }
  
  .logo-text h1 {
    font-size: 2rem;
  }
  
  .dashboard-grid {
    grid-template-columns: repeat(12, 1fr);
  }
  
  .stats-panel {
    grid-column: span 12;
  }
  
  .filters-panel {
    grid-column: span 4;
  }
  
  .data-panel {
    grid-column: span 8;
  }
}

@media (max-width: 768px) {
  .vulnerability-dashboard {
    padding: 0.5rem;
  }
  
  .dashboard-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 1rem;
  }
  
  .header-actions {
    width: 100%;
    display: flex;
    justify-content: flex-end;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
  
  .filter-options {
    flex-direction: column;
    width: 100%;
  }
  
  .filter-chip {
    width: 100%;
    justify-content: center;
  }
  
  .pagination-controls {
    flex-direction: column;
    gap: 1rem;
  }
  
  .detail-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
  
  .data-table th, 
  .data-table td {
    padding: 0.75rem 0.5rem;
    font-size: 0.85rem;
  }
  
  .summary-cell,
  .repo-cell,
  .vuln-cell {
    max-width: 100px;
  }
}

@media (max-width: 480px) {
  .data-table th:nth-child(5), 
  .data-table td:nth-child(5) {
    display: none;
  }
  
  .page-indicator {
    display: none;
  }
}

.count-cell {
  text-align: center;
}

.count-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background-color: var(--secondary-bg);
  color: var(--text-primary);
  font-weight: 600;
  min-width: 24px;
  height: 24px;
  padding: 0 0.5rem;
  border-radius: 12px;
  font-size: 0.85rem;
}

.repos-list {
  max-height: 200px;
  overflow-y: auto;
  margin-top: 0.5rem;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background-color: var(--secondary-bg);
}

.repo-item {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.repo-item:last-child {
  border-bottom: none;
}

.repo-item i {
  color: var(--primary-color);
  font-size: 0.9rem;
}
</style>
