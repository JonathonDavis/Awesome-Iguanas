<template>
  <div class="repository-explorer">
    <div class="explorer-container">
      <div class="search-container">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search repositories..."
          class="search-input"
        />
        <button 
          @click="expandAllRepositories" 
          class="expand-all-button"
        >
          {{ expandedRepos.length === repositories.length ? 'Collapse All' : 'Expand All' }}
        </button>
      </div>
      
      <div class="repository-list">
        <div 
          v-for="repo in filteredRepositories" 
          :key="repo.repository"
          class="repository-item"
        >
          <div 
            class="repo-header"
            @click="toggleRepository(repo)"
          >
            <a 
              :href="repo.repository" 
              target="_blank" 
              rel="noopener noreferrer"
              class="repo-link"
              @click.stop
            >
              {{ getRepoName(repo.repository) }}
            </a>
            <div class="version-count">{{ repo.versions.length }} versions</div>
          </div>
          
          <div class="version-list" v-if="expandedRepos.includes(repo.repository)">
            <div 
              v-for="version in repo.versions" 
              :key="version.version"
              class="version-item"
              :class="{ 'selected': selectedVersion === version }"
              @click="selectVersion(version)"
            >
              <div class="version-header">
                <div class="version-name">{{ version.version }}</div>
                <div class="version-size">Size: {{ formatSize(version.size) }}</div>
              </div>
              
              <div class="version-details" v-if="expandedVersions.includes(version)">
                <div class="detail-item">
                  <strong>Primary Language:</strong>
                  <div class="primary-language">{{ version.primaryLanguage || 'Not specified' }}</div>
                </div>
                <div class="detail-item">
                  <strong>Language Breakdown:</strong>
                  <div class="language-chart">
                    <div 
                      v-for="(percentage, lang) in version.languages" 
                      :key="lang"
                      class="language-bar"
                      :style="{ width: percentage + '%', backgroundColor: getLanguageColor(lang) }"
                      :title="`${lang}: ${percentage}%`"
                    ></div>
                  </div>
                  <div class="language-legend">
                    <div 
                      v-for="(percentage, lang) in version.languages" 
                      :key="lang"
                      class="legend-item"
                    >
                      <span class="legend-color" :style="{ backgroundColor: getLanguageColor(lang) }"></span>
                      <span class="legend-text">{{ lang }} ({{ percentage.toFixed(2) }}%)</span>
                    </div>
                  </div>
                </div>
                <div class="detail-item" v-if="version.languageCount">
                  <strong>Total Languages:</strong>
                  <div class="language-count">{{ version.languageCount }}</div>
                </div>
                <div class="cve-list" v-if="version.cves && version.cves.length > 0">
                  <div class="cve-header">Affected by CVEs:</div>
                  <div class="cve-items">
                    <a 
                      v-for="cve in version.cves" 
                      :key="cve"
                      :href="`https://nvd.nist.gov/vuln/detail/${cve}`"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="cve-link"
                    >
                      {{ cve }}
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div v-if="!showAll && repositories.length > displayLimit" class="show-more-container">
          <button @click="showLessRepositories" class="show-less-button" v-if="displayLimit > 10">
            Show 10 Less
          </button>
          <button @click="showMoreRepositories" class="show-more-button">
            Show Next 10
          </button>
          <button @click="toggleShowAll" class="show-all-button">
            Show All ({{ repositories.length - displayLimit }} more)
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
import neo4jService from '../services/neo4j/neo4jService'

const repositories = ref([])
const expandedRepos = ref([])
const expandedVersions = ref([])
const selectedVersion = ref(null)
const searchQuery = ref('')
const displayLimit = ref(10)
const showAll = ref(false)

// Add computed property for filtered repositories
const filteredRepositories = computed(() => {
  if (!searchQuery.value) {
    return showAll.value ? repositories.value : repositories.value.slice(0, displayLimit.value);
  }
  
  const query = searchQuery.value.toLowerCase();
  const filtered = repositories.value.filter(repo => {
    const repoName = getRepoName(repo.repository).toLowerCase();
    const versionMatches = repo.versions.some(version => 
      version.version.toLowerCase().includes(query)
    );
    return repoName.includes(query) || versionMatches;
  });
  
  return showAll.value ? filtered : filtered.slice(0, displayLimit.value);
});

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
  'Scala': '#c22d40',
  'HTML': '#e34c26',
  'CSS': '#563d7c',
  'Shell': '#89e051',
  'Dockerfile': '#384d54',
  'Makefile': '#427819',
  'Vue': '#41b883',
  'React': '#61dafb',
  'Angular': '#dd0031',
  'Svelte': '#ff3e00',
  'Elixir': '#6e4a7e',
  'Clojure': '#db5855',
  'Haskell': '#5e5086',
  'OCaml': '#3be133',
  'R': '#198ce7',
  'MATLAB': '#e16737',
  'Perl': '#0298c3',
  'Lua': '#000080',
  'Dart': '#00B4AB',
  'Julia': '#a270ba',
  'Racket': '#3c5caa',
  'Erlang': '#B83998',
  'F#': '#b845fc',
  'Groovy': '#e69f56',
  'Objective-C': '#438eff',
  'Assembly': '#6E4C13',
  'PowerShell': '#012456',
  'Batchfile': '#C1F12E',
  'TeX': '#3D6117',
  'Markdown': '#083fa1',
  'YAML': '#cb171e',
  'JSON': '#292929',
  'XML': '#0060ac',
  'SQL': '#e38c00',
  'GraphQL': '#e10098',
  'PLSQL': '#dad8d8',
  'TSQL': '#e38c00',
  'PLpgSQL': '#336791',
  'PL/SQL': '#dad8d8',
  'Tcl': '#e4cc98',
  'CoffeeScript': '#244776',
  'D': '#ba595e',
  'F*': '#572e30',
  'Forth': '#341708',
  'Fortran': '#4d41b1',
  'Haxe': '#df7900',
  'Idris': '#b30000',
  'J': '#9EEDFF',
  'Jupyter Notebook': '#DA5B0B',
  'Lean': '#3D3C3E',
  'Nim': '#37775b',
  'Nix': '#7e7eff',
  'Pascal': '#E3F171',
  'Prolog': '#74283c',
  'PureScript': '#1D222D',
  'QML': '#44a51c',
  'Raku': '#0000fb',
  'Reason': '#ff5847',
  'Red': '#f50000',
  'RenPy': '#ff7f7f',
  'Ring': '#2D54CB',
  'Sass': '#a53b70',
  'Solidity': '#AA6746',
  'Stylus': '#ff6347',
  'Terraform': '#623ce4',
  'Vala': '#fbe5cd',
  'Vim script': '#199f4b',
  'Visual Basic': '#945db7',
  'WebAssembly': '#04133b',
  'Zig': '#ec915c'
}

const getLanguageColor = (lang) => {
  return languageColors[lang] || '#cccccc'
}

const getRepoName = (url) => {
  try {
    const urlObj = new URL(url)
    return urlObj.pathname.split('/').slice(-2).join('/')
  } catch {
    return url
  }
}

const formatSize = (sizeValue) => {
  // Debug log
  console.log('Formatting size:', {
    rawSize: sizeValue,
    type: typeof sizeValue
  });

  if (!sizeValue) return '0 MB';
  
  // Convert to string if it's a number
  const sizeStr = typeof sizeValue === 'number' ? sizeValue.toString() : sizeValue;
  
  // Remove the 'M' suffix and format the number
  const number = parseFloat(sizeStr.replace('M', ''));
  
  if (isNaN(number)) return '0 MB';
  
  // Format the number to show decimals only if they exist
  const formattedSize = number % 1 === 0 ? number.toString() : number.toFixed(2).replace(/\.?0+$/, '');
  
  console.log('Formatted size:', formattedSize + ' MB');
  return `${formattedSize} MB`;
}

const toggleRepository = (repo) => {
  const index = expandedRepos.value.indexOf(repo.repository)
  if (index === -1) {
    expandedRepos.value.push(repo.repository)
  } else {
    expandedRepos.value.splice(index, 1)
  }
}

const selectVersion = (version) => {
  if (selectedVersion.value === version) {
    selectedVersion.value = null;
    // Remove from expanded versions when deselecting
    const index = expandedVersions.value.indexOf(version);
    if (index !== -1) {
      expandedVersions.value.splice(index, 1);
    }
  } else {
    selectedVersion.value = version;
    // Add to expanded versions when selecting
    if (!expandedVersions.value.includes(version)) {
      expandedVersions.value.push(version);
    }
  }
}

const expandAllRepositories = () => {
  if (expandedRepos.value.length === repositories.value.length) {
    // If all are expanded, collapse all
    expandedRepos.value = [];
    expandedVersions.value = [];
    selectedVersion.value = null;
  } else {
    // Expand all repositories and their versions
    expandedRepos.value = repositories.value.map(repo => repo.repository);
    expandedVersions.value = repositories.value.flatMap(repo => 
      repo.versions.map(version => version)
    );
    // Select the first version of the first repository if available
    if (repositories.value.length > 0 && repositories.value[0].versions.length > 0) {
      selectedVersion.value = repositories.value[0].versions[0];
    }
  }
};

const toggleShowAll = () => {
  showAll.value = !showAll.value;
  if (!showAll.value) {
    // Reset expanded repos when collapsing
    expandedRepos.value = [];
    expandedVersions.value = [];
    selectedVersion.value = null;
    displayLimit.value = 10; // Reset display limit when showing less
  }
}

const showMoreRepositories = () => {
  displayLimit.value += 10;
}

const showLessRepositories = () => {
  displayLimit.value = Math.max(10, displayLimit.value - 10);
}

const fetchData = async () => {
  try {
    const data = await neo4jService.getRepositoryStatistics();
    console.log('Fetched data:', data);
    repositories.value = data;
  } catch (error) {
    console.error('Error fetching repository statistics:', error);
  }
}

fetchData()
</script>

<style scoped>
.repository-explorer {
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

.repository-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  overflow-y: auto;
  flex: 1;
  padding-right: 0.5rem;
  margin-right: -0.5rem;
  min-height: 0; /* Important for flex child scrolling */
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

.repository-item {
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  overflow: hidden;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
}

.repo-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  cursor: pointer;
  transition: background-color 0.2s;
  background-color: #402C1B  ;
}

.repo-header:hover {
  background-color: rgba(184, 105, 8, 0.815);
}

.repo-link {
  color: white;
  text-decoration: none;
  font-weight: bold;
  font-size: 1.1rem;
  transition: color 0.2s;
}

.repo-link:hover {
  color: #61dafb;
  text-decoration: underline;
}

.version-count {
  color: #efefee;
  font-size: 0.9rem;
}

.version-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem;
  background-color: #402C1B;
  overflow-y: auto;
  margin: 0;
  padding-right: 0.5rem;
  /* max-height: 80vh; */
}

.version-list::-webkit-scrollbar {
  width: 8px;
}

.version-list::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
}

.version-list::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

.version-list::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

.version-item {
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
  overflow: hidden;
  transition: all 0.3s ease;
  display: flex;
  flex-direction: column;
  margin: 0;
}

.version-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  cursor: pointer;
  transition: background-color 0.2s;
  background-color: rgba(255, 255, 255, 0.05);
  margin: 0;
}

.version-header:hover {
  background-color: rgba(210, 34, 34, 0.943);
}

.version-name {
  color: white;
  font-weight: bold;
}

.version-size {
  color: white;
  font-size: 0.9rem;
}

.version-details {
  padding: 0.75rem;
  background-color: rgba(68, 56, 45, 0.973);
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  overflow-y: auto;
  margin: 0;
  padding-right: 0.75rem;
}

.version-details::-webkit-scrollbar {
  width: 8px;
}

.version-details::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
}

.version-details::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 4px;
}

.version-details::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}

.detail-item {
  margin-bottom: 0.75rem;
}

.detail-item strong {
  color: white;
  display: block;
  margin-bottom: 0.25rem;
}

.primary-language {
  color: white;
  font-size: 1rem;
  margin-top: 0.25rem;
}

.language-chart {
  height: 12px;
  border-radius: 6px;
  overflow: hidden;
  margin: 0.75rem 0;
  display: flex;
  background: rgba(255, 255, 255, 0.1);
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
}

.language-bar {
  height: 100%;
  position: relative;
}

.language-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 0.75rem;
  padding: 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.25rem 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
}

.legend-color {
  width: 14px;
  height: 14px;
  border-radius: 3px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
}

.legend-text {
  color: white;
  font-size: 0.9rem;
  font-weight: 500;
}

.language-count {
  color: white;
  font-size: 1rem;
  margin-top: 0.25rem;
}

.version-item.selected {
  background-color: rgba(255, 255, 255, 0.15);
}

@media (max-width: 768px) {
  .explorer-container {
    padding: 0.5rem;
    
  }
  
  .repo-name {
    font-size: 1rem;
  }
  
  .version-name {
    font-size: 0.9rem;
  }
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

.cve-list {
  margin-top: 0.5rem;
  padding: 0.5rem;
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
}

.cve-header {
  color: #ff6b6b;
  font-weight: bold;
  margin-bottom: 0.5rem;
}

.cve-items {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.cve-link {
  color: #61dafb;
  text-decoration: none;
  padding: 0.25rem 0.5rem;
  background-color: rgba(97, 218, 251, 0.1);
  border-radius: 4px;
  transition: all 0.2s;
}

.cve-link:hover {
  background-color: rgba(97, 218, 251, 0.2);
  text-decoration: underline;
}

.show-more-container {
  display: flex;
  justify-content: center;
  margin-top: 1rem;
  padding: 0.5rem;
  gap: 0.5rem;
}

.show-more-button,
.show-all-button,
.show-less-button {
  padding: 0.75rem 1.5rem;
  background-color: rgba(255, 255, 255, 0.1);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  transition: background-color 0.2s;
}

.show-more-button:hover,
.show-all-button:hover,
.show-less-button:hover {
  background-color: rgba(255, 255, 255, 0.2);
}
</style> 