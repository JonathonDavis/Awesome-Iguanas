<template>
  <div class="repository-explorer">
    <div class="explorer-container">
      <div class="repository-list">
        <div 
          v-for="repo in repositories" 
          :key="repo.repository"
          class="repository-item"
        >
          <div 
            class="repo-header"
            @click="toggleRepository(repo)"
          >
            <div class="repo-name">{{ getRepoName(repo.repository) }}</div>
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
                <div class="version-name">v{{ version.version }}</div>
                <div class="version-size">{{ formatSize(version.size) }}</div>
              </div>
              
              <div class="version-details" v-if="selectedVersion === version">
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
                      <span class="legend-text">{{ lang }} ({{ percentage }}%)</span>
                    </div>
                  </div>
                </div>
                <div class="detail-item" v-if="version.languageCount">
                  <strong>Total Languages:</strong>
                  <div class="language-count">{{ version.languageCount }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import neo4jService from '../services/neo4jService'

const repositories = ref([])
const expandedRepos = ref([])
const selectedVersion = ref(null)

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

const formatSize = (bytes) => {
  // Debug log
  console.log('Formatting size:', {
    rawBytes: bytes,
    type: typeof bytes,
    isNumber: typeof bytes === 'number',
    isNaN: isNaN(bytes)
  });

  if (!bytes && bytes !== 0) return '0 M';
  if (isNaN(bytes)) return '0 M';
  
  const units = ['M'];
  let size = Number(bytes);
  let unitIndex = 0;
  
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  
  // Format the number to show decimals only if they exist
  const formattedSize = size % 1 === 0 ? size.toString() : size.toFixed(2).replace(/\.?0+$/, '');
  console.log('Formatted size:', formattedSize + ' ' + units[unitIndex]);
  return `${formattedSize} ${units[unitIndex]}`;
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
  selectedVersion.value = selectedVersion.value === version ? null : version
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
}

.explorer-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  background-color: #066c43;
  border-radius: 4px;
  padding: 1rem;
  overflow: hidden;
}

.repository-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  overflow-y: auto;
  max-height: 70vh;
  padding-right: 0.5rem;
  margin-right: -0.5rem;
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
  background-color: rgba(255, 255, 255, 0.15);
}

.repo-name {
  color: white;
  font-weight: bold;
  font-size: 1.1rem;
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
  background-color: #402C1B ;
  max-height: 40vh;
  overflow-y: auto;
  margin-right: -0.5rem;
  padding-right: 0.5rem;
}

.version-list::-webkit-scrollbar {
  width: 6px;
}

.version-list::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.05);
  border-radius: 3px;
}

.version-list::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 3px;
}

.version-list::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.15);
}

.version-item {
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
  overflow: hidden;
  transition: all 0.3s ease;
}

.version-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  cursor: pointer;
  transition: background-color 0.2s;
  background-color: rgba(255, 255, 255, 0.05);
}

.version-header:hover {
  background-color: rgba(255, 255, 255, 0.1);
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
  background-color: rgba(0, 0, 0, 0.2);
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  max-height: 30vh;
  overflow-y: auto;
  margin-right: -0.5rem;
  padding-right: 0.5rem;
}

.version-details::-webkit-scrollbar {
  width: 4px;
}

.version-details::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.05);
  border-radius: 2px;
}

.version-details::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 2px;
}

.version-details::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.15);
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
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  margin: 0.5rem 0;
  display: flex;
}

.language-bar {
  height: 100%;
  transition: width 0.3s ease;
}

.language-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 2px;
}

.legend-text {
  color: white;
  font-size: 0.9rem;
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
</style> 